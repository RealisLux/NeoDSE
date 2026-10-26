// File purpose: Wires the stateless display agent lifecycle and authenticated transport session.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package agent implements the NeoDSE display agent. It authenticates one
// controller session at a time, applies desired state and transient commands
// through the local renderer, HDMI-CEC and serial peripherals, and relays web
// content and the read-only display view.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/wire"
	"github.com/gorilla/websocket"
)

const (
	commandReplayWindow    = 5 * time.Minute
	transportRetryMax      = 15 * time.Second
	transportDialTimeout   = 10 * time.Second
	transportPingInterval  = 10 * time.Second
	transportPongTimeout   = 45 * time.Second
	transportWriteTimeout  = 15 * time.Second
	stableTransportSession = time.Minute
	transportInboundFrames = 128
	transportInboundBytes  = 8 << 20
)

// Run loads agent configuration and maintains transport sessions until cancellation.
func Run(ctx context.Context, args []string, buildVersion string) error {
	if len(args) > 0 && isProvisionCommand(args[0]) {
		return runProvisionCommand(ctx, args)
	}
	if buildVersion == "" {
		buildVersion = "dev"
	}
	path := config.DefaultAgentPath
	var verbose, debug bool
	flags := flag.NewFlagSet("neodse-agent", flag.ContinueOnError)
	flags.StringVar(&path, "config", path, "path to agent YAML configuration")
	flags.BoolVar(&verbose, "verbose", false, "verbose logging")
	flags.BoolVar(&debug, "debug", false, "debug logging")
	flags.Usage = func() { writeAgentUsage(flags) }
	if err := flags.Parse(args); err != nil {
		return err
	}
	// The argument is not echoed: it may be a secret pasted in the wrong place.
	if flags.NArg() != 0 {
		return errors.New("neodse-agent does not accept positional arguments; run neodse-agent --help for the commands")
	}
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return fmt.Errorf("load agent configuration: %w", err)
	}
	for _, endpoint := range []string{cfg.Transport.URL, cfg.Proxy.URL} {
		if err := config.VerifyPlaintextLink(endpoint, cfg.Agent.WireGuardInterface, false); err != nil {
			return err
		}
	}
	psk, err := keyderivation.ParsePSK(cfg.Agent.PSK)
	if err != nil {
		return fmt.Errorf("parse agent PSK: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &Agent{ctx: ctx, config: cfg, psk: psk, commandKeys: replay.New(commandReplayWindow, 4096), started: time.Now(), version: buildVersion, verbose: verbose || cfg.Agent.LogLevel == "verbose", debug: debug || cfg.Agent.LogLevel == "debug"}
	defer func() {
		cancel()
		a.cancelReconnectReload()
		a.workers.Wait()
		a.closeCEC()
	}()
	a.initializeCEC()
	a.startVNCAuthSupervisor(ctx)
	if err := a.startProxyRelay(ctx); err != nil {
		return err
	}
	a.workers.Go(func() { a.initializeUI(ctx) })
	a.workers.Go(func() { a.heartbeat(ctx) })
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		progress := a.sessionProgress.Load()
		if err := a.runSession(ctx); err != nil && ctx.Err() == nil {
			a.infof("! Transport disconnected: %v", err)
		}
		backoff = resetTransportBackoff(backoff, time.Since(started), a.sessionProgress.Load() != progress)
		a.transportConnected.Store(false)
		a.updateControlConnectionStatus()
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < transportRetryMax {
			backoff *= 2
			if backoff > transportRetryMax {
				backoff = transportRetryMax
			}
		}
	}
	return nil
}

// writeAgentUsage describes the service flags and the root provisioning commands.
func writeAgentUsage(flags *flag.FlagSet) {
	output := flags.Output()
	fmt.Fprintln(output, "Usage: neodse-agent [--config PATH] [--verbose | --debug]")
	fmt.Fprintln(output, "       neodse-agent COMMAND [OPTIONS]")
	fmt.Fprintln(output, "\nService options:")
	flags.PrintDefaults()
	fmt.Fprintln(output, "\nCommands, run as root:")
	for _, command := range provisionCommands {
		fmt.Fprintf(output, "  %-14s %s\n", command.name, command.summary)
	}
	fmt.Fprintln(output, "\nRun neodse-agent COMMAND --help for the options of a command.")
}

// resetTransportBackoff restores prompt retries after authenticated application
// traffic or a stable session; unsuccessful attempts retain bounded backoff.
func resetTransportBackoff(current, sessionDuration time.Duration, progressed bool) time.Duration {
	if progressed || sessionDuration >= stableTransportSession {
		return time.Second
	}
	return current
}

// runSession authenticates one transport connection and processes typed frames until disconnect.
func (a *Agent) runSession(ctx context.Context) error {
	connection, cleanup, err := a.openTransportConnection(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	handshakeTimer := time.AfterFunc(transportDialTimeout, func() { _ = connection.ws.Close() })
	defer handshakeTimer.Stop()
	hello, handshakeKey, err := a.sendHello()
	if err != nil {
		return err
	}
	frames := make(chan inboundFrame, transportInboundFrames)
	readErrors := make(chan error, 1)
	readerDone := make(chan struct{})
	var queuedBytes atomic.Int64
	go func() {
		defer close(readerDone)
		defer connection.ws.Close()
		readErrors <- readTransportFrames(connection.ws, frames, &queuedBytes)
	}()
	defer func() {
		_ = connection.ws.Close()
		<-readerDone
	}()
	for {
		var incoming inboundFrame
		select {
		case err := <-readErrors:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case incoming = <-frames:
		}
		queuedBytes.Add(-incoming.bytes)
		// Discard pending work after a read failure rather than executing commands
		// from a connection whose authority is about to be cleared.
		select {
		case err := <-readErrors:
			return err
		default:
		}
		frame := incoming.frame
		if frame.Type == "welcome" {
			// The bounded welcome handler either authenticates or ends this session.
			// Its later UI status update must not consume the handshake timeout.
			handshakeTimer.Stop()
		}
		if err := a.handleTransportFrame(frame, hello, handshakeKey); err != nil {
			return err
		}
		if frame.Type != "welcome" {
			a.sessionProgress.Add(1)
		}
	}
}

// inboundFrame accounts for the encoded bytes retained by one ordered request.
type inboundFrame struct {
	frame protocol.Frame
	bytes int64
}

// readTransportFrames keeps processing WebSocket control traffic while ordered
// command execution waits on hardware or the UI. Saturation ends the connection.
func readTransportFrames(ws *websocket.Conn, frames chan<- inboundFrame, queuedBytes *atomic.Int64) error {
	for {
		var raw []byte
		if err := ws.ReadJSON(&raw); err != nil {
			return err
		}
		var frame protocol.Frame
		if err := protocol.Decode(raw, &frame); err != nil {
			return fmt.Errorf("decode transport frame: %w", err)
		}
		size := int64(len(raw))
		if queuedBytes.Add(size) > transportInboundBytes {
			queuedBytes.Add(-size)
			return errors.New("agent inbound byte capacity reached")
		}
		select {
		case frames <- inboundFrame{frame: frame, bytes: size}:
		default:
			queuedBytes.Add(-size)
			return errors.New("agent inbound frame capacity reached")
		}
	}
}

// newTransportDialer constructs the IPv4-only, proxy-independent control-channel dialer.
func newTransportDialer(device string) websocket.Dialer {
	return websocket.Dialer{
		Proxy:            nil,
		HandshakeTimeout: transportDialTimeout,
		NetDialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: transportDialTimeout, KeepAlive: 30 * time.Second, Control: config.PlaintextSocketControl(device)}).DialContext(ctx, "tcp4", address)
		},
	}
}

// openTransportConnection dials the configured endpoint and returns cleanup that erases session state.
func (a *Agent) openTransportConnection(ctx context.Context) (*agentConnection, func(), error) {
	u, err := url.Parse(a.config.Transport.URL)
	if err != nil {
		return nil, nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/agents/" + url.PathEscape(a.config.Agent.ID)
	dialer := newTransportDialer(a.config.Agent.WireGuardInterface)
	ws, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	ws.SetReadLimit(wire.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(transportPongTimeout))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(transportPongTimeout))
	})
	c := &agentConnection{ws: ws}
	sessionDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = ws.Close()
		case <-sessionDone:
		}
	}()
	a.connectionMu.Lock()
	a.connection = c
	a.connectionMu.Unlock()
	cleanup := func() {
		close(sessionDone)
		_ = ws.Close()
		<-watcherDone
		a.clearSession()
		a.connectionMu.Lock()
		if a.connection == c {
			a.connection = nil
		}
		a.connectionMu.Unlock()
	}
	return c, cleanup, nil
}

// sendHello creates and sends a fresh signed handshake initiation message.
func (a *Agent) sendHello() (protocol.Hello, []byte, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return protocol.Hello{}, nil, err
	}
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: a.config.Agent.ID, Version: a.version, ClientNonce: hex.EncodeToString(nonceBytes), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	handshakeKey, err := a.purposeKey(keyderivation.TransportHandshake)
	if err != nil {
		return protocol.Hello{}, nil, err
	}
	hello.Signature, err = protocol.SignHello(hello, handshakeKey)
	if err != nil {
		return protocol.Hello{}, nil, err
	}
	if err := a.send("hello", hello); err != nil {
		return protocol.Hello{}, nil, err
	}
	return hello, handshakeKey, nil
}

// handleTransportFrame dispatches one decoded frame and rejects protocol errors by ending the session.
func (a *Agent) handleTransportFrame(frame protocol.Frame, hello protocol.Hello, handshakeKey []byte) error {
	switch frame.Type {
	case "welcome":
		return a.acceptWelcome(frame.Payload, hello, handshakeKey)
	case "desired_state":
		var state protocol.DesiredState
		if err := protocol.Decode(frame.Payload, &state); err != nil {
			return fmt.Errorf("decode desired state: %w", err)
		}
		return a.handleDesiredState(state)
	case "command":
		var command protocol.Command
		if err := protocol.Decode(frame.Payload, &command); err != nil {
			return fmt.Errorf("decode command: %w", err)
		}
		return a.handleCommand(command)
	case "display":
		var display protocol.Display
		if err := protocol.Decode(frame.Payload, &display); err != nil {
			return fmt.Errorf("decode display relay: %w", err)
		}
		return a.handleDisplay(display)
	default:
		return errors.New("unsupported transport frame type")
	}
}

// acceptWelcome verifies freshness and authentication before installing session authority.
func (a *Agent) acceptWelcome(payload []byte, hello protocol.Hello, handshakeKey []byte) error {
	a.sessionMu.Lock()
	installed := a.sessionID != ""
	a.sessionMu.Unlock()
	if installed {
		return errors.New("welcome cannot replace an active session")
	}
	var welcome protocol.Welcome
	if protocol.Decode(payload, &welcome) != nil || welcome.Protocol != protocol.Version || welcome.AgentID != a.config.Agent.ID || welcome.ClientNonce != hello.ClientNonce || len(welcome.SessionID) != 32 {
		return errors.New("invalid welcome message")
	}
	expected, err := protocol.SignWelcome(welcome, handshakeKey)
	if err != nil || !protocol.Verify(welcome.Signature, expected) {
		return errors.New("welcome authentication failed")
	}
	welcomeTime, err := time.Parse(time.RFC3339Nano, welcome.Timestamp)
	if err != nil || !replay.Fresh(welcomeTime, time.Now().UTC(), commandReplayWindow) {
		return errors.New("welcome timestamp is outside the accepted window")
	}
	if err := a.installSession(welcome.SessionID, welcome.ClientNonce, welcome.ServerNonce); err != nil {
		return fmt.Errorf("install transport session: %w", err)
	}
	// Install the new proxy credential even when reconciliation retains the playlist.
	// A missing renderer is retried through normal desired-state reconciliation.
	if err := a.sendProxyAuthToUI(); err != nil {
		a.debugf("! Could not install proxy session in UI: %v", err)
		a.retryRenderer()
	}
	a.transportConnected.Store(true)
	a.transportConnectedOnce.Store(true)
	a.infof("| Transport connected")
	a.updateControlConnectionStatus()
	return nil
}

// initializeUI prepares the renderer when its socket appears without delaying
// the agent's control connection on a headless host.
// Offline startup needs only the local relay; acceptWelcome installs credentials
// once authenticated. An already connected session restores them here as well.
func (a *Agent) initializeUI(ctx context.Context) {
	for ctx.Err() == nil {
		if _, err := os.Stat(a.config.Agent.UISocket); err == nil &&
			a.sendUIStatus("initializing", "info", "Starting display service") == nil &&
			a.sendProxyConfigToUI() == nil &&
			(!a.transportConnected.Load() || a.sendProxyAuthToUI() == nil) {
			a.updateControlConnectionStatus()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
