// File purpose: Verifies bounded bidirectional behavior of the agent loopback proxy relay.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestProxyRelayForwardsOnlyToConfiguredProxy verifies proxy relay forwards only to configured proxy.
func TestProxyRelayForwardsOnlyToConfiguredProxy(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan error, 1)
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			upstreamDone <- acceptErr
			return
		}
		defer connection.Close()
		buffer := make([]byte, 4)
		if _, readErr := io.ReadFull(connection, buffer); readErr != nil {
			upstreamDone <- readErr
			return
		}
		_, writeErr := connection.Write(buffer)
		upstreamDone <- writeErr
	}()

	ctx := t.Context()
	agent := &Agent{}
	agent.config.Proxy.URL = "http://" + upstream.Addr().String()
	if err := agent.startProxyRelay(ctx); err != nil {
		t.Fatal(err)
	}
	relayURL, err := url.Parse(agent.proxyRelayURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", relayURL.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("relay response = %q", response)
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

// TestProxyRelayRejectsEncryptedOrMissingEndpoint verifies proxy relay rejects encrypted or missing endpoint.
func TestProxyRelayRejectsEncryptedOrMissingEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "https://127.0.0.1:3128", "not-a-url"} {
		agent := &Agent{}
		agent.config.Proxy.URL = endpoint
		if err := agent.startProxyRelay(context.Background()); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
}

// TestProxyRelayFailureLoggingIsRateLimited verifies proxy relay failure logging is rate limited.
func TestProxyRelayFailureLoggingIsRateLimited(t *testing.T) {
	var output bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(originalOutput)
		log.SetFlags(originalFlags)
	})

	agent := &Agent{}
	agent.logProxyRelayFailure("upstream_dial", errors.New("connection refused"))
	agent.logProxyRelayFailure("upstream_dial", errors.New("connection refused"))
	if strings.Count(output.String(), "Proxy relay connection failed") != 1 || agent.proxyRelaySuppressed != 1 {
		t.Fatalf("first interval output=%q suppressed=%d", output.String(), agent.proxyRelaySuppressed)
	}

	agent.proxyRelayLastLog = time.Now().Add(-proxyRelayFailureLogInterval)
	agent.logProxyRelayFailure("upstream_dial", errors.New("connection refused"))
	if !strings.Contains(output.String(), "suppressed=1") || agent.proxyRelaySuppressed != 0 {
		t.Fatalf("second interval output=%q suppressed=%d", output.String(), agent.proxyRelaySuppressed)
	}
}

// TestProxyRelayKeepsOneWayStreamsOpen verifies that data in either direction
// keeps a relay connection open, as for long downloads or server-sent events,
// and that the connection closes once neither direction is active.
func TestProxyRelayKeepsOneWayStreamsOpen(t *testing.T) {
	const idle = 500 * time.Millisecond
	clientApplication, clientSide := net.Pipe()
	upstreamSide, upstreamApplication := net.Pipe()
	defer clientApplication.Close()
	defer upstreamApplication.Close()
	result := make(chan error, 1)
	go func() { result <- relayProxyBytes(clientSide, upstreamSide, idle) }()
	received := make(chan int64, 1)
	go func() {
		count, _ := io.Copy(io.Discard, clientApplication)
		received <- count
	}()
	var sent int64
	for started := time.Now(); time.Since(started) < 3*idle; sent++ {
		if _, err := upstreamApplication.Write([]byte{'x'}); err != nil {
			t.Fatalf("one-way stream closed after %d bytes while data was flowing: %v", sent, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) || !expectedProxyRelayClosure(err) {
			t.Fatalf("idle relay ended with %v, want an expected idle timeout", err)
		}
	case <-time.After(idle + 5*time.Second):
		t.Fatal("relay stayed open after both directions were idle")
	}
	if count := <-received; count != sent {
		t.Fatalf("client received %d of %d streamed bytes", count, sent)
	}
}

// TestExpectedProxyRelayClosureClassification verifies expected proxy relay closure classification.
func TestExpectedProxyRelayClosureClassification(t *testing.T) {
	if !expectedProxyRelayClosure(io.EOF) || !expectedProxyRelayClosure(net.ErrClosed) {
		t.Fatal("clean relay closure was classified as a failure")
	}
	if expectedProxyRelayClosure(errors.New("connection reset")) {
		t.Fatal("unexpected relay failure was classified as a clean closure")
	}
}

// TestProxyRelayAvailabilityCoalescesTransitions verifies only the latest state is queued.
func TestProxyRelayAvailabilityCoalescesTransitions(t *testing.T) {
	agent := &Agent{proxyRelayStatus: make(chan bool, 1)}
	agent.setProxyRelayAvailability(false)
	agent.setProxyRelayAvailability(false)
	agent.setProxyRelayAvailability(true)

	select {
	case failed := <-agent.proxyRelayStatus:
		if failed {
			t.Fatal("stale proxy failure was not replaced by recovery")
		}
	default:
		t.Fatal("proxy recovery transition was not queued")
	}
	if agent.proxyRelayFailed {
		t.Fatal("proxy relay remained failed after recovery")
	}
}

// TestProxyRelayUIStatus verifies failure and recovery renderer messages.
func TestProxyRelayUIStatus(t *testing.T) {
	stage, severity, message := proxyRelayUIStatus(true)
	if stage != "proxy_connection_lost" || severity != "critical" {
		t.Fatalf("failure status = %q %q", stage, severity)
	}
	if message != "Connection to the proxy lost — reconnecting automatically" {
		t.Fatalf("failure message = %q", message)
	}
	stage, severity, message = proxyRelayUIStatus(false)
	if stage != "proxy_connection_restored" || severity != "success" {
		t.Fatalf("recovery status = %q %q", stage, severity)
	}
	if message != "Connection to the proxy restored" {
		t.Fatalf("recovery message = %q", message)
	}
}
