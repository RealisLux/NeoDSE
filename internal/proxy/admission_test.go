// File purpose: Verifies accepted-socket admission through the production proxy listener.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestProxyListenerBoundsIncompleteHeaders reproduces the pre-authentication
// socket exhaustion path without reaching the HTTP request limiter.
func TestProxyListenerBoundsIncompleteHeaders(t *testing.T) {
	p := &Proxy{connections: make(chan struct{}, 1)}
	address := serveAdmissionProxy(t, p)
	first := openPartialProxyRequest(t, address)
	openPartialProxyRequest(t, address)
	assertProxyAdmissionClosed(t, dialAdmissionProxy(t, address))
	if requests := p.requestID.Load(); requests != 0 || len(p.connections) != 0 {
		t.Fatalf("incomplete headers reached handler: requests=%d occupied_request_slots=%d", requests, len(p.connections))
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	assertProxyAdmissionRecovered(t, address)
}

// TestProxyListenerCountsConnectLifetime keeps a hijacked socket in the raw
// connection budget until the tunnel closes, then checks that its slot returns.
func TestProxyListenerCountsConnectLifetime(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authenticated":true,"allowed":true}`)
	}))
	t.Cleanup(backend.Close)
	upstreamClient, upstreamServer := net.Pipe()
	t.Cleanup(func() { _ = upstreamClient.Close(); _ = upstreamServer.Close() })
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		defer upstreamServer.Close()
		_, _ = io.Copy(upstreamServer, upstreamServer)
	}()
	p := &Proxy{connections: make(chan struct{}, 1), backendClient: backend.Client(), internalToken: "test"}
	p.config.Proxy.BackendURL = backend.URL
	p.dialOverride = func(context.Context, string, string) (net.Conn, error) { return upstreamClient, nil }
	address := serveAdmissionProxy(t, p)
	tunnel := dialAdmissionProxy(t, address)
	if err := tunnel.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("display:" + strings.Repeat("ab", 32)))
	if _, err := fmt.Fprintf(tunnel, "CONNECT content.example:443 HTTP/1.1\r\nHost: content.example:443\r\nProxy-Authorization: Basic %s\r\n\r\n", credentials); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(tunnel)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", response.StatusCode)
	}
	openPartialProxyRequest(t, address)
	assertProxyAdmissionClosed(t, dialAdmissionProxy(t, address))
	if len(p.connections) != 1 {
		t.Fatal("CONNECT released its request slot before the tunnel closed")
	}
	if _, err := io.WriteString(tunnel, "alive"); err != nil {
		t.Fatal(err)
	}
	var echoed [5]byte
	if _, err := io.ReadFull(reader, echoed[:]); err != nil || string(echoed[:]) != "alive" {
		t.Fatalf("admission rejection disturbed the existing tunnel: data=%q error=%v", echoed, err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing the raw socket releases listener admission before the CONNECT
	// handler joins both copy workers and returns its separate request slot.
	// No new complete request is sent until that handler has finished.
	handlerDone := make(chan struct{})
	go func() { p.requestWorkers.Wait(); close(handlerDone) }()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closed CONNECT left its request handler running")
	}
	assertProxyAdmissionRecovered(t, address)
	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closed CONNECT left an upstream worker running")
	}
}

// TestRejectedCredentialsDoNotSelectAgentQuota keeps an unauthenticated claim
// from reserving or probing another display's active connection quota.
func TestRejectedCredentialsDoNotSelectAgentQuota(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authenticated":false,"allowed":false}`)
	}))
	defer backend.Close()
	p := &Proxy{
		backendClient: backend.Client(), internalToken: "test", agentLimit: 1,
		agentConnections: map[string]int{"display": 1},
	}
	p.config.Proxy.BackendURL = backend.URL
	request := httptest.NewRequest(http.MethodGet, "http://content.example/", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("display:" + strings.Repeat("ab", 32)))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	response := httptest.NewRecorder()
	p.handleProxy(response, request)
	if response.Code != http.StatusProxyAuthRequired || calls.Load() != 1 {
		t.Fatalf("invalid credentials selected a display quota: status=%d authority_calls=%d", response.Code, calls.Load())
	}
	if p.agentConnections["display"] != 1 {
		t.Fatal("invalid credentials changed an authenticated display's quota")
	}
}

// serveAdmissionProxy starts the production listener on a reserved loopback port.
func serveAdmissionProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	p.config.Proxy.Listen = address
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() { defer close(done); runErr = p.serve(ctx, "admission-test") }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if runErr != nil {
				t.Errorf("proxy serving failed: %v", runErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy did not stop after client cleanup")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("proxy stopped before readiness: %v", runErr)
		default:
		}
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			// Read a complete response so readiness does not leave an accepted
			// socket waiting in front of the deliberately tiny admission budget.
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(connection, "GET http://content.example/ HTTP/1.1\r\nHost: content.example\r\nConnection: close\r\n\r\n")
			_, _ = io.ReadAll(connection)
			_ = connection.Close()
			p.requestID.Store(0)
			return address
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("proxy listener did not start")
	return ""
}

// dialAdmissionProxy owns one test connection and closes it before proxy shutdown.
func dialAdmissionProxy(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// openPartialProxyRequest waits for previously closed sockets to relinquish
// admission, then proves that this socket stays open before headers finish.
func openPartialProxyRequest(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		connection := dialAdmissionProxy(t, address)
		_, lastErr = io.WriteString(connection, "GET http://content.example/ HTTP/1.1\r\nHost: content.example\r\n")
		if lastErr == nil {
			if err := connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			if _, lastErr = connection.Read(data[:]); lastErr == nil {
				t.Fatal("incomplete headers unexpectedly produced a response")
			} else if timeout, ok := lastErr.(net.Error); ok && timeout.Timeout() {
				if err := connection.SetReadDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				return connection
			}
		}
		_ = connection.Close()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("socket below admission limit remained closed: %v", lastErr)
	return nil
}

// assertProxyAdmissionClosed distinguishes immediate admission from header timeouts.
func assertProxyAdmissionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := connection.Read(data[:]); err == nil {
		t.Fatal("over-limit socket unexpectedly produced data")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("over-limit socket remained open before HTTP parsing")
	}
}

// assertProxyAdmissionRecovered retries while the server observes the closed peer.
func assertProxyAdmissionRecovered(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection := dialAdmissionProxy(t, address)
		_ = connection.SetDeadline(deadline)
		_, writeErr := io.WriteString(connection, "GET http://content.example/ HTTP/1.1\r\nHost: content.example\r\nConnection: close\r\n\r\n")
		response, readErr := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
		if readErr == nil {
			_ = response.Body.Close()
		}
		_ = connection.Close()
		if writeErr == nil && readErr == nil {
			if response.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("recovered request status=%d, want407", response.StatusCode)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("closing a retained socket did not restore listener admission")
}
