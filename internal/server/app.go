// File purpose: Wires the controller database, transport, API, scheduler, TLS, and shutdown lifecycle.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package server implements the NeoDSE control-server application.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/dashboard"
	"github.com/RealisLux/NeoDSE/internal/netlimit"
	"github.com/RealisLux/NeoDSE/internal/swagger"
)

type serverRunOptions struct {
	configPath string
	verbose    bool
	debug      bool
}

const (
	// Management clients must not occupy the local proxy's authorization budget.
	maxLocalAPIConnections   = 2048
	maxManagementConnections = 512
	maxManagementPerSource   = 256
)

// Run loads the controller configuration and serves requests until ctx is cancelled.
func Run(ctx context.Context, args []string, buildVersion string) error {
	if len(args) > 0 && isProvisionCommand(args[0]) {
		return runProvisionCommand(ctx, args)
	}
	options, err := parseServerRunOptions(args)
	if err != nil {
		return err
	}
	loaded, err := config.LoadServer(options.configPath)
	if err != nil {
		return fmt.Errorf("load server configuration: %w", err)
	}
	if err := config.VerifyPlaintextLink(loaded.Server.TransportURL, loaded.Server.WireGuardInterface, false); err != nil {
		return err
	}
	controller := newConfiguredServer(loaded, buildVersion, options)
	if err := controller.waitForUnlock(ctx, unlockSocketPath, 0); err != nil {
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return nil
		}
		return err
	}
	defer controller.store.Close()
	runContext, cancel := context.WithCancel(ctx)
	controller.startBackgroundServices(runContext)
	err = controller.serveHTTPS(runContext, options.configPath)
	cancel()
	controller.workers.Wait()
	return err
}

// parseServerRunOptions parses controller flags without opening external resources.
func parseServerRunOptions(args []string) (serverRunOptions, error) {
	options := serverRunOptions{configPath: config.DefaultServerPath}
	flags := flag.NewFlagSet("neodse-server", flag.ContinueOnError)
	flags.StringVar(&options.configPath, "config", config.DefaultServerPath, "path to the server YAML configuration")
	flags.BoolVar(&options.verbose, "verbose", false, "log one summary for each server operation")
	flags.BoolVar(&options.debug, "debug", false, "log server operation summaries (same as --verbose)")
	flags.Usage = func() { writeServerUsage(flags) }
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	// The argument is not echoed: it may be a secret pasted in the wrong place.
	if flags.NArg() != 0 {
		return options, errors.New("neodse-server does not accept positional arguments; run neodse-server --help for the commands")
	}
	return options, nil
}

// writeServerUsage describes the service flags and the root maintenance commands.
func writeServerUsage(flags *flag.FlagSet) {
	output := flags.Output()
	fmt.Fprintln(output, "Usage: neodse-server [--config PATH] [--verbose | --debug]")
	fmt.Fprintln(output, "       neodse-server COMMAND [OPTIONS]")
	fmt.Fprintln(output, "\nService options:")
	flags.PrintDefaults()
	fmt.Fprintln(output, "\nCommands, run as root:")
	for _, command := range maintenanceCommands {
		fmt.Fprintf(output, "  %-18s %s\n", command.name, command.summary)
	}
	fmt.Fprintln(output, "\nRun neodse-server COMMAND --help for the options of a command.")
}

// newConfiguredServer applies run options to a controller whose database is still locked.
func newConfiguredServer(loaded Config, buildVersion string, options serverRunOptions) *Server {
	version := buildVersion
	if version == "" {
		version = "dev"
	}
	controller := newServer(loaded, version)
	controller.verbose = controller.verbose || options.verbose
	controller.debug = controller.debug || options.debug
	return controller
}

// startBackgroundServices starts transport, schedule, and retention loops owned by ctx.
func (s *Server) startBackgroundServices(ctx context.Context) {
	s.link = newControllerLink(s, s.config.Server.TransportURL, s.config.Server.TransportPSK)
	s.workers.Go(func() { s.link.Run(ctx) })
	s.workers.Go(func() { s.runScheduler(ctx) })
	s.workers.Go(func() { s.runRetention(ctx) })
}

// controllerHandler builds the complete public and private HTTP routing stack.
func (s *Server) controllerHandler() http.Handler {
	mux := http.NewServeMux()
	dashboard.RegisterRoutes(mux)
	mux.HandleFunc("/healthz", s.healthz)
	swagger.RegisterRoutes(mux)
	mux.HandleFunc("/internal/v1/proxy/authorize", s.proxyAuthorizeHandler)
	s.registerAPIRoutes(mux)
	return requestIDMiddleware(securityHeaders(mux))
}

// serveHTTPS owns the TLS listener and bounded graceful-shutdown lifecycle.
func (s *Server) serveHTTPS(ctx context.Context, configPath string) error {
	requestContext, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	certificate, err := prepareServerCertificate(s.config.Server.TLSCert, s.config.Server.TLSKey, configPath)
	if err != nil {
		return fmt.Errorf("API TLS setup: %w", err)
	}
	notAfter := certificate.Leaf.NotAfter
	s.workers.Go(func() { reportCertificateExpiry(requestContext, notAfter, time.Now, log.Printf) })
	listenAddresses, err := serverListenAddresses(s.config.Server.Listen)
	if err != nil {
		return fmt.Errorf("API listener setup: %w", err)
	}
	server := &http.Server{
		Addr: s.config.Server.Listen, Handler: s.ownHTTP(s.controllerHandler()), ErrorLog: newHTTPServerErrorLogger(),
		BaseContext: func(net.Listener) context.Context { return requestContext },
		ReadTimeout: 15 * time.Second, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	listeners := make([]net.Listener, 0, len(listenAddresses))
	for _, address := range listenAddresses {
		listener, listenErr := net.Listen("tcp4", address)
		if listenErr != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("API listen on %s: %w", address, listenErr)
		}
		limit := maxManagementConnections
		if listener.Addr().(*net.TCPAddr).IP.IsLoopback() {
			limit = maxLocalAPIConnections
		}
		admission, admissionErr := netlimit.New(limit, maxManagementPerSource)
		if admissionErr != nil {
			_ = listener.Close()
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("API connection limits: %w", admissionErr)
		}
		// Each listener owns its pool, so management traffic cannot exhaust
		// loopback capacity. Wrapping below TLS also bounds stalled handshakes.
		listeners = append(listeners, admission.Wrap(listener))
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS13}
	serveErrors := make(chan error, len(listeners))
	for _, listener := range listeners {
		tlsListener := tls.NewListener(listener, tlsConfig)
		go func() { serveErrors <- server.Serve(tlsListener) }()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case serveErr := <-serveErrors:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			runErr = fmt.Errorf("API stopped: %w", serveErr)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s.stopHTTPAdmission()
	cancelRequests()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		if runErr == nil {
			runErr = fmt.Errorf("API shutdown: %w", err)
		}
	}
	s.httpWorkers.Wait()
	return runErr
}

// serverListenAddresses keeps the controller reachable at 127.0.0.1 for its local proxy.
func serverListenAddresses(configured string) ([]string, error) {
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return nil, err
	}
	loopback := net.JoinHostPort("127.0.0.1", port)
	if host == "127.0.0.1" {
		return []string{configured}, nil
	}
	return []string{configured, loopback}, nil
}
