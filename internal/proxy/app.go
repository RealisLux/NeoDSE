// File purpose: Wires and serves the authenticated explicit proxy application.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package proxy implements the NeoDSE explicit-proxy application.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/netlimit"
	"github.com/RealisLux/NeoDSE/internal/proxyauth"
)

// Config is the strict explicit-proxy configuration contract.
type Config = config.Proxy

type proxyRunOptions struct {
	configPath string
	verbose    bool
	debug      bool
}

// Run loads proxy configuration and serves requests until ctx is cancelled.
func Run(ctx context.Context, args []string, buildVersion string) error {
	version := buildVersion
	if version == "" {
		version = "dev"
	}
	options, err := parseProxyRunOptions(args)
	if err != nil {
		return err
	}
	loaded, err := config.LoadProxy(options.configPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if err := config.VerifyPlaintextLink(loaded.Proxy.Listen, loaded.Proxy.WireGuardInterface, true); err != nil {
		return err
	}
	proxy, err := newConfiguredProxy(loaded, options)
	if err != nil {
		return err
	}
	return proxy.serve(ctx, version)
}

// parseProxyRunOptions parses process flags without loading or mutating runtime state.
func parseProxyRunOptions(args []string) (proxyRunOptions, error) {
	options := proxyRunOptions{configPath: config.DefaultProxyPath}
	flags := flag.NewFlagSet("neodse-proxy", flag.ContinueOnError)
	flags.StringVar(&options.configPath, "config", config.DefaultProxyPath, "path to the proxy YAML configuration")
	flags.BoolVar(&options.verbose, "verbose", false, "log one summary for each proxy request")
	flags.BoolVar(&options.debug, "debug", false, "log detailed proxy request processing")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, errors.New("neodse-proxy does not accept positional arguments")
	}
	return options, nil
}

// newConfiguredProxy derives credentials, trust roots, network policy, and bounded HTTP clients.
func newConfiguredProxy(loaded Config, options proxyRunOptions) (*Proxy, error) {
	internalToken, err := proxyauth.InternalToken(loaded.Proxy.InternalPSK)
	if err != nil {
		return nil, fmt.Errorf("internal proxy credential: %w", err)
	}
	rootCAs, err := proxyRootCAs(loaded.Proxy.TLSCA)
	if err != nil {
		return nil, err
	}
	authorizedNetworks := make([]netip.Prefix, 0, len(loaded.Proxy.AuthorizedNetworks))
	for _, value := range loaded.Proxy.AuthorizedNetworks {
		prefix, _ := netip.ParsePrefix(value)
		authorizedNetworks = append(authorizedNetworks, prefix)
	}
	maxConnections, maxAgentConnections := loaded.Proxy.MaxConnections, loaded.Proxy.MaxAgentConnections
	if maxConnections <= 0 {
		maxConnections = config.DefaultProxyConnections
	}
	if maxAgentConnections <= 0 {
		maxAgentConnections = config.DefaultProxyAgentConnections
	}
	proxy := &Proxy{
		config: loaded, internalToken: internalToken, authorizedNetworks: authorizedNetworks,
		connections: make(chan struct{}, maxConnections), agentLimit: maxAgentConnections,
		agentConnections: make(map[string]int), verbose: options.verbose || loaded.Proxy.LogLevel == "verbose",
		debug: options.debug || loaded.Proxy.LogLevel == "debug",
	}
	proxy.backendClient = newBackendClient(rootCAs)
	proxy.proxyClient = newForwardingClient(proxy)
	return proxy, nil
}

// proxyRootCAs loads an optional private controller CA into the system trust pool.
func proxyRootCAs(path string) (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	if path == "" {
		return rootCAs, nil
	}
	certificate, err := readTrustAnchor(path)
	if err != nil {
		return nil, fmt.Errorf("read proxy backend CA: %w", err)
	}
	if !rootCAs.AppendCertsFromPEM(certificate) {
		return nil, errors.New("proxy backend CA contains no valid certificates")
	}
	return rootCAs, nil
}

// readTrustAnchor loads one bounded, trusted regular file without following its final path element.
func readTrustAnchor(path string) ([]byte, error) {
	// Reject FIFOs without waiting for a writer before inspecting the file type.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("trust anchor is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("trust anchor is group or world writable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("trust anchor has unexpected owner uid %d", stat.Uid)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > 1<<20 {
		return nil, errors.New("trust anchor exceeds 1 MiB")
	}
	return contents, nil
}

// newBackendClient creates the short-deadline client used only for authorization decisions.
func newBackendClient(rootCAs *x509.CertPool) *http.Client {
	// Authorization is meaningful only at the configured authority. Redirects
	// can disclose our internal credential and accept a different host's decision.
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: returnRedirectResponse, Transport: &http.Transport{
		Proxy: nil, DialContext: dialIPv4Context, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS13},
	}}
}

// dialIPv4Context enforces IPv4-only backend connectivity.
func dialIPv4Context(ctx context.Context, _, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, "tcp4", address)
}

// newForwardingClient creates the SSRF-filtered client used for authorized HTTP content.
func newForwardingClient(proxy *Proxy) *http.Client {
	return &http.Client{CheckRedirect: returnRedirectResponse, Transport: &http.Transport{
		Proxy: nil, DialContext: proxy.safeDialContext, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second, MaxResponseHeaderBytes: 1 << 20,
		MaxIdleConns: 128, MaxIdleConnsPerHost: 16,
	}}
}

// serve owns the listener and HTTP shutdown lifecycle for one configured proxy.
func (p *Proxy) serve(ctx context.Context, version string) error {
	log.Printf("| NeoDSE explicit proxy starting version=%s listen=%s backend=%s log_level=%s internal_credential_configured=%t", version, p.config.Proxy.Listen, p.config.Proxy.BackendURL, effectiveLogLevel(p), p.internalToken != "")
	connections, perSource := cap(p.connections), p.agentLimit
	if connections == 0 {
		connections = config.DefaultProxyConnections
	}
	if perSource <= 0 {
		perSource = config.DefaultProxyAgentConnections
	}
	// Count sockets before HTTP parsing, with bounded headroom for idle and
	// reconnecting clients. A claimed agent ID cannot select this source quota.
	admission, err := netlimit.New(connections+min(connections, 128), perSource+min(perSource, 8))
	if err != nil {
		return fmt.Errorf("proxy connection limits: %w", err)
	}
	server := &http.Server{
		Addr: p.config.Proxy.Listen, Handler: http.HandlerFunc(p.handleProxy), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 32 << 10, ErrorLog: log.Default(),
	}
	listenerConfig := net.ListenConfig{Control: config.PlaintextSocketControl(p.config.Proxy.WireGuardInterface)}
	listener, err := listenerConfig.Listen(ctx, "tcp4", p.config.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	defer listener.Close()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(admission.Wrap(listener)) }()
	watchContext, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	linkErrors := make(chan error, 1)
	go func() {
		linkErrors <- config.WatchPlaintextListener(watchContext, listener, p.config.Proxy.WireGuardInterface)
	}()
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("proxy server stopped: %w", err)
		}
	case runErr = <-linkErrors:
	}
	p.stopLeases()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		if runErr == nil {
			runErr = fmt.Errorf("proxy shutdown: %w", err)
		}
	}
	if p.backendClient != nil {
		p.backendClient.CloseIdleConnections()
	}
	if p.proxyClient != nil {
		p.proxyClient.CloseIdleConnections()
	}
	return runErr
}

// returnRedirectResponse prevents the proxy client from following a newly unauthorized target.
func returnRedirectResponse(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// effectiveLogLevel returns the most detailed enabled proxy diagnostic level.
func effectiveLogLevel(proxy *Proxy) string {
	if proxy.debug {
		return "debug"
	}
	if proxy.verbose {
		return "verbose"
	}
	return "info"
}
