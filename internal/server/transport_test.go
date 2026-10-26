// File purpose: Verifies controller transport bounds and reconnect recovery behavior.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestControllerDialerFailsClosedWhenWireGuardDisappears exercises the production dialer.
func TestControllerDialerFailsClosedWhenWireGuardDisappears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialer := newControllerDialer("neodse-missing")
	conn, err := dialer.NetDialContext(ctx, "tcp4", "192.0.2.1:80")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatalf("missing WireGuard must prevent network dialing: %v", err)
	}
}

// TestControllerTransportRejectsInvalidPSK prevents malformed keys from signing
// a network request with an empty or partially decoded HMAC key.
func TestControllerTransportRejectsInvalidPSK(t *testing.T) {
	requests := make(chan struct{}, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer peer.Close()
	valid := strings.Repeat("ab", 32)
	for _, psk := range []string{"", "invalid", " " + valid, valid + " ", "ab" + strings.Repeat("zz", 31)} {
		link := newControllerLink(newServer(Config{}, "test"), "ws"+strings.TrimPrefix(peer.URL, "http"), psk)
		if err := link.session(context.Background()); err == nil || !strings.Contains(err.Error(), "transport credential") {
			t.Fatalf("malformed PSK error = %v, want credential failure before dialing", err)
		}
		select {
		case <-requests:
			t.Fatal("invalid key reached the network")
		default:
		}
	}
}

// TestControllerTransportSignsWithConfiguredKey checks the actual dial header
// against an independently constructed HMAC, including uppercase hexadecimal.
func TestControllerTransportSignsWithConfiguredKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	verified := make(chan bool, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimPrefix(r.Header.Get("Authorization"), "NeoDSE ")
		separator := strings.LastIndexByte(value, ':')
		if separator < 0 {
			verified <- false
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		timestamp, signature := value[:separator], value[separator+1:]
		mac := hmac.New(sha256.New, key)
		_, _ = io.WriteString(mac, "neodse/transport/v1\x00"+timestamp+"\x00"+r.Header.Get("X-NeoDSE-Nonce"))
		verified <- signature == hex.EncodeToString(mac.Sum(nil))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer peer.Close()
	link := newControllerLink(newServer(Config{}, "test"), "ws"+strings.TrimPrefix(peer.URL, "http"), strings.Repeat("AB", 32))
	if err := link.session(context.Background()); !errors.Is(err, websocket.ErrBadHandshake) {
		t.Fatalf("controller did not reach the credential verifier: %v", err)
	}
	if !<-verified {
		t.Fatal("controller signed with a key different from its validated configuration")
	}
}

// TestControllerTransportReadLimit verifies an oversized routed frame terminates the session.
func TestControllerTransportReadLimit(t *testing.T) {
	upgrader := websocket.Upgrader{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.WriteJSON(routedFrame{Type: "connected", Reason: strings.Repeat("x", controllerMaxMessageBytes)})
	}))
	defer peer.Close()

	link := newControllerLink(newServer(Config{}, "test"), "ws"+strings.TrimPrefix(peer.URL, "http"), strings.Repeat("ab", 32))
	err := link.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized frame error = %v, want read limit failure", err)
	}
}

// TestControllerDialerIgnoresEnvironmentProxies keeps plaintext control traffic on WireGuard.
func TestControllerDialerIgnoresEnvironmentProxies(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://attacker.invalid:8080")
	}
	dialer := newControllerDialer("")
	if dialer.Proxy != nil {
		t.Fatal("controller WebSocket dialer inherited an environment proxy")
	}
	if dialer.HandshakeTimeout != controllerDialTimeout || dialer.NetDialContext == nil {
		t.Fatal("controller WebSocket dialer is missing explicit network timeouts")
	}
}

// TestStableControllerSessionResetsBackoff verifies a recovered connection restores prompt retries.
func TestStableControllerSessionResetsBackoff(t *testing.T) {
	if got := resetControllerBackoff(controllerRetryMax, time.Second, true); got != time.Second {
		t.Fatalf("successful short session backoff = %s, want 1s", got)
	}
	if got := resetControllerBackoff(controllerRetryMax, stableTransportSession, false); got != time.Second {
		t.Fatalf("stable session backoff = %s, want 1s", got)
	}
	if got := resetControllerBackoff(controllerRetryMax, stableTransportSession-time.Nanosecond, false); got != controllerRetryMax {
		t.Fatalf("short session backoff = %s, want %s", got, controllerRetryMax)
	}
}
