// File purpose: Relays UI proxy connections through a volatile loopback endpoint to the configured peer.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
)

const (
	proxyRelayConnections        = 64
	proxyRelayDialTimeout        = 10 * time.Second
	proxyRelayIdleTimeout        = 5 * time.Minute
	proxyRelayFailureLogInterval = 30 * time.Second
)

// startProxyRelay creates the only TCP endpoint available to WebKit. The relay
// forwards bytes to the configured explicit proxy; authorization and destination
// policy remain enforced by the server-side proxy.
func (a *Agent) startProxyRelay(ctx context.Context) error {
	proxyURL, err := url.Parse(a.config.Proxy.URL)
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Host == "" {
		return errors.New("configured proxy is not a plain HTTP endpoint")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start local proxy relay: %w", err)
	}
	a.proxyRelayURL = "http://" + listener.Addr().String()
	a.proxyRelayStatus = make(chan bool, 1)
	a.workers.Go(func() {
		<-ctx.Done()
		_ = listener.Close()
	})
	a.workers.Go(func() { a.publishProxyRelayStatus(ctx) })
	a.workers.Go(func() { a.serveProxyRelay(ctx, listener, proxyURL.Host) })
	return nil
}

// serveProxyRelay accepts bounded loopback connections until cancellation.
func (a *Agent) serveProxyRelay(ctx context.Context, listener net.Listener, upstreamAddress string) {
	capacity := make(chan struct{}, proxyRelayConnections)
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				a.infof("! Local proxy relay stopped: %v", err)
			}
			return
		}
		select {
		case capacity <- struct{}{}:
			a.workers.Go(func() {
				defer func() { <-capacity }()
				a.relayProxyConnection(ctx, client, upstreamAddress)
			})
		default:
			a.logProxyRelayFailure("capacity", errors.New("connection limit reached"))
			_ = client.Close()
		}
	}
}

// relayProxyConnection copies one bounded connection to the configured remote proxy.
func (a *Agent) relayProxyConnection(ctx context.Context, client net.Conn, upstreamAddress string) {
	defer client.Close()
	dialer := &net.Dialer{Timeout: proxyRelayDialTimeout, KeepAlive: 30 * time.Second, Control: config.PlaintextSocketControl(a.config.Agent.WireGuardInterface)}
	upstream, err := dialer.DialContext(ctx, "tcp4", upstreamAddress)
	if err != nil {
		if ctx.Err() == nil {
			a.logProxyRelayFailure("upstream_dial", err)
			a.setProxyRelayAvailability(false)
		}
		return
	}
	a.setProxyRelayAvailability(true)
	defer upstream.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = client.Close(); _ = upstream.Close() })
	defer stopClose()

	firstErr := relayProxyBytes(client, upstream, proxyRelayIdleTimeout)
	if ctx.Err() == nil && !expectedProxyRelayClosure(firstErr) {
		a.logProxyRelayFailure("transfer", firstErr)
		a.setProxyRelayAvailability(false)
	}
}

// relayProxyBytes copies both directions until either side closes or neither
// direction transfers data for the idle period, then closes both connections
// and returns the first result. Data in one direction keeps a one-way stream
// open while the other is silent; offsets use the monotonic clock.
func relayProxyBytes(client, upstream net.Conn, idle time.Duration) error {
	opened := time.Now()
	var lastTransfer atomic.Int64
	idleDeadline := func() time.Time {
		return opened.Add(time.Duration(lastTransfer.Load()) + idle)
	}
	done := make(chan error, 2)
	copyDirection := func(destination, source net.Conn) {
		buffer := make([]byte, 32*1024)
		for {
			_ = source.SetReadDeadline(idleDeadline())
			count, readErr := source.Read(buffer)
			if count > 0 {
				lastTransfer.Store(int64(time.Since(opened)))
				_ = destination.SetWriteDeadline(time.Now().Add(idle))
				if writeErr := writeAll(destination, buffer[:count]); writeErr != nil {
					done <- writeErr
					return
				}
			}
			if readErr != nil {
				// The other direction may have transferred data while this read waited.
				if errors.Is(readErr, os.ErrDeadlineExceeded) && time.Now().Before(idleDeadline()) {
					continue
				}
				done <- readErr
				return
			}
		}
	}
	go copyDirection(upstream, client)
	go copyDirection(client, upstream)
	firstErr := <-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
	return firstErr
}

// setProxyRelayAvailability coalesces relay state transitions for the UI publisher.
func (a *Agent) setProxyRelayAvailability(available bool) {
	failed := !available
	a.proxyRelayStateMu.Lock()
	defer a.proxyRelayStateMu.Unlock()
	if a.proxyRelayFailed == failed {
		return
	}
	a.proxyRelayFailed = failed
	if a.proxyRelayStatus == nil {
		return
	}
	select {
	case <-a.proxyRelayStatus:
	default:
	}
	select {
	case a.proxyRelayStatus <- failed:
	default:
	}
}

// publishProxyRelayStatus serializes immediate relay failure and recovery updates.
func (a *Agent) publishProxyRelayStatus(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case failed := <-a.proxyRelayStatus:
			stage, severity, message := proxyRelayUIStatus(failed)
			if err := a.sendUIStatus(stage, severity, message); err != nil {
				a.verbosef("! Could not update UI proxy relay status: %v", err)
			}
		}
	}
}

// proxyRelayUIStatus maps one relay transition to bounded renderer status fields.
func proxyRelayUIStatus(failed bool) (stage, severity, message string) {
	if failed {
		return "proxy_connection_lost", "critical", "Connection to the proxy lost — reconnecting automatically"
	}
	return "proxy_connection_restored", "success", "Connection to the proxy restored"
}

// expectedProxyRelayClosure identifies clean shutdown and idle-timeout outcomes.
func expectedProxyRelayClosure(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

// logProxyRelayFailure reports the first relay failure in each interval and
// counts suppressed repeats to prevent a local connection flood from filling logs.
func (a *Agent) logProxyRelayFailure(operation string, err error) {
	now := time.Now()
	a.proxyRelayLogMu.Lock()
	if !a.proxyRelayLastLog.IsZero() && now.Sub(a.proxyRelayLastLog) < proxyRelayFailureLogInterval {
		a.proxyRelaySuppressed++
		a.proxyRelayLogMu.Unlock()
		return
	}
	suppressed := a.proxyRelaySuppressed
	a.proxyRelayLastLog = now
	a.proxyRelaySuppressed = 0
	a.proxyRelayLogMu.Unlock()
	a.infof("! Proxy relay connection failed operation=%s error=%v suppressed=%d", operation, err, suppressed)
}

// writeAll rejects stalled short writes while transferring a complete buffer.
func writeAll(destination net.Conn, value []byte) error {
	for len(value) > 0 {
		count, err := destination.Write(value)
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("proxy relay write made no progress")
		}
		value = value[count:]
	}
	return nil
}
