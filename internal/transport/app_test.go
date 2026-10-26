// File purpose: Verifies transport authentication, routing, origin checks, and connection limits.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/gorilla/websocket"
)

// TestTransportRejectsPositionalArguments prevents misplaced flags from being
// ignored before the transport selects its credential-bearing configuration.
func TestTransportRejectsPositionalArguments(t *testing.T) {
	for _, args := range [][]string{
		{"transport.yaml"},
		{"--config", "missing.yaml", "extra"},
		{"extra", "--config", "missing.yaml"},
	} {
		if err := Run(context.Background(), args, "test"); err == nil || !strings.Contains(err.Error(), "positional arguments") {
			t.Fatalf("Run(%q) = %v, want positional argument rejection", args, err)
		}
	}
}

// TestControllerAuthorizationRejectsInvalidAuthority rejects even correctly
// forged signatures when authority is absent, truncated, or oversized.
func TestControllerAuthorizationRejectsInvalidAuthority(t *testing.T) {
	now := time.Now().UTC()
	for _, key := range [][]byte{nil, []byte("short"), make([]byte, keyderivation.PSKBytes-1), make([]byte, keyderivation.PSKBytes+1)} {
		s := &service{psk: key, authNonces: replay.New(2*time.Minute, 8192)}
		request := signedControllerRequest(key, now.Format(time.RFC3339), strings.Repeat("ab", 32))
		if s.authorizedAt(request, now) {
			t.Fatalf("controller accepted a forged signature with a %d-byte authority key", len(key))
		}
	}
}

// TestAgentIdentityValidation verifies agent identity validation.
func TestAgentIdentityValidation(t *testing.T) {
	for _, id := range []string{"display-01", "A", strings.Repeat("a", 32)} {
		if !identity.ValidAgentID(id) {
			t.Fatalf("valid agent id %q rejected", id)
		}
	}
	for _, id := range []string{"", "-display", "display/01", strings.Repeat("a", 33)} {
		if identity.ValidAgentID(id) {
			t.Fatalf("invalid agent id %q accepted", id)
		}
	}
}

// TestReserveAgentDoesNotDisplaceLiveIdentity verifies reserve agent does not displace live identity.
func TestReserveAgentDoesNotDisplaceLiveIdentity(t *testing.T) {
	controller := &peer{}
	first := &peer{}
	s := &service{controller: controller, agents: make(map[string]*peer)}
	gotController, ok := s.reserveAgent("display-01", first)
	if !ok || gotController != controller {
		t.Fatal("first live identity was not admitted")
	}
	if _, ok := s.reserveAgent("display-01", &peer{}); ok {
		t.Fatal("duplicate live identity was admitted")
	}
	if s.agents["display-01"] != first {
		t.Fatal("duplicate reservation displaced established identity")
	}
}

// TestControllerAuthorization verifies controller authorization.
func TestControllerAuthorization(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &service{psk: key, authNonces: replay.New(2*time.Minute, 8192)}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := strings.Repeat("ab", 32)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("neodse/transport/v1\x00" + ts + "\x00" + nonce))
	r := httptest.NewRequest("GET", "http://transport/v1/controller", nil)
	r.Header.Set("Authorization", "NeoDSE "+ts+":"+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-NeoDSE-Nonce", nonce)
	if !s.authorized(r) {
		t.Fatal("valid controller authorization rejected")
	}
	r.Header.Set("X-NeoDSE-Nonce", strings.Repeat("cd", 32))
	r.Header.Set("Authorization", "NeoDSE "+ts+":"+strings.Repeat("00", 32))
	if s.authorized(r) {
		t.Fatal("invalid controller authorization accepted")
	}
}

// signedControllerRequest builds a deterministic authenticated controller fixture.
func signedControllerRequest(key []byte, timestamp, nonce string) *http.Request {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("neodse/transport/v1\x00" + timestamp + "\x00" + nonce))
	r := httptest.NewRequest(http.MethodGet, "http://transport/v1/controller", nil)
	r.Header.Set("Authorization", "NeoDSE "+timestamp+":"+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-NeoDSE-Nonce", nonce)
	return r
}

// TestControllerReplayWindowRetainsFutureNonces covers replay after arrival-based expiry.
func TestControllerReplayWindowRetainsFutureNonces(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1800000000, 0)
	s := &service{psk: key, authNonces: replay.New(2*time.Minute, 1)}
	request := signedControllerRequest(key, now.Add(2*time.Minute).Format(time.RFC3339), strings.Repeat("ab", 32))
	if !s.authorizedAt(request, now) {
		t.Fatal("valid future-dated authorization rejected")
	}
	for _, elapsed := range []time.Duration{2*time.Minute + time.Second, 4 * time.Minute} {
		if s.authorizedAt(request, now.Add(elapsed)) {
			t.Fatalf("replay accepted after %s", elapsed)
		}
	}
	fresh := signedControllerRequest(key, now.Add(3*time.Minute).Format(time.RFC3339), strings.Repeat("cd", 32))
	if s.authorizedAt(fresh, now.Add(3*time.Minute)) {
		t.Fatal("full cache admitted a new nonce")
	}
	if !s.authorizedAt(fresh, now.Add(4*time.Minute+time.Second)) {
		t.Fatal("expired nonce did not release capacity")
	}
}

// TestControllerAuthorizationRejectsReplayAndMalformedInputs verifies controller authorization rejects replay and malformed inputs.
func TestControllerAuthorizationRejectsReplayAndMalformedInputs(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now().UTC()
	service := &service{psk: key, authNonces: replay.New(2*time.Minute, 8192)}
	nonce := strings.Repeat("ab", 32)
	request := signedControllerRequest(key, now.Format(time.RFC3339), nonce)
	if !service.authorized(request) {
		t.Fatal("valid authorization rejected")
	}
	if service.authorized(request) {
		t.Fatal("authorization nonce replay accepted")
	}

	tests := []struct {
		name      string
		timestamp string
		nonce     string
		mutate    func(*http.Request)
	}{
		{name: "expired", timestamp: now.Add(-3 * time.Minute).Format(time.RFC3339), nonce: strings.Repeat("01", 32)},
		{name: "future", timestamp: now.Add(3 * time.Minute).Format(time.RFC3339), nonce: strings.Repeat("02", 32)},
		{name: "timestamp", timestamp: "invalid", nonce: strings.Repeat("03", 32)},
		{name: "nonce length", timestamp: now.Format(time.RFC3339), nonce: "abcd"},
		{name: "nonce encoding", timestamp: now.Format(time.RFC3339), nonce: strings.Repeat("gg", 32)},
		{name: "authorization scheme", timestamp: now.Format(time.RFC3339), nonce: strings.Repeat("04", 32), mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") }},
		{name: "missing scheme", timestamp: now.Format(time.RFC3339), nonce: strings.Repeat("06", 32), mutate: func(r *http.Request) {
			r.Header.Set("Authorization", strings.TrimPrefix(r.Header.Get("Authorization"), "NeoDSE "))
		}},
		{name: "signature", timestamp: now.Format(time.RFC3339), nonce: strings.Repeat("05", 32), mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "NeoDSE "+now.Format(time.RFC3339)+":"+strings.Repeat("00", 32))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := signedControllerRequest(key, test.timestamp, test.nonce)
			if test.mutate != nil {
				test.mutate(request)
			}
			if service.authorized(request) {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
}

// TestReserveAgentEnforcesCapacity verifies reserve agent enforces capacity.
func TestReserveAgentEnforcesCapacity(t *testing.T) {
	t.Parallel()
	agents := make(map[string]*peer, 4096)
	for index := range 4096 {
		agents[fmt.Sprintf("agent-%04d", index)] = &peer{}
	}
	service := &service{agents: agents}
	if _, admitted := service.reserveAgent("display-over-capacity", &peer{}); admitted {
		t.Fatal("agent admitted beyond capacity")
	}
}

// TestTransportRoutesOpaqueFramesAndDisconnects verifies transport routes opaque frames and disconnects.
func TestTransportRoutesOpaqueFramesAndDisconnects(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	service := &service{
		psk:        key,
		agents:     make(map[string]*peer),
		authNonces: replay.New(2*time.Minute, 8192),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: time.Second,
			CheckOrigin:      func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/controller", service.handleController)
	mux.HandleFunc("GET /v1/agents/{agentId}", service.handleAgent)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	websocketBase := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := strings.Repeat("ab", 32)
	signed := signedControllerRequest(key, timestamp, nonce)
	controller, response, err := websocket.DefaultDialer.Dial(websocketBase+"/v1/controller", signed.Header)
	if err != nil {
		if response != nil {
			t.Fatalf("controller dial: %v status=%d", err, response.StatusCode)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	waitForControllerRegistration(t, service)

	agent, response, err := websocket.DefaultDialer.Dial(websocketBase+"/v1/agents/display-01", nil)
	if err != nil {
		if response != nil {
			t.Fatalf("agent dial: %v status=%d", err, response.StatusCode)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Second))
	var connected routedFrame
	if err := controller.ReadJSON(&connected); err != nil {
		t.Fatal(err)
	}
	if connected.Type != "connected" || connected.AgentID != "display-01" {
		t.Fatalf("connected frame = %+v", connected)
	}

	agentPayload := []byte(`{"type":"hello"}`)
	if err := agent.WriteJSON(agentPayload); err != nil {
		t.Fatal(err)
	}
	var fromAgent routedFrame
	if err := controller.ReadJSON(&fromAgent); err != nil {
		t.Fatal(err)
	}
	if fromAgent.Type != "from_agent" || fromAgent.AgentID != "display-01" || string(fromAgent.Payload) != string(agentPayload) {
		t.Fatalf("from-agent frame = %+v", fromAgent)
	}
	if len(connected.ConnectionID) != 32 || fromAgent.ConnectionID != connected.ConnectionID {
		t.Fatal("routing frames did not identify their connection")
	}

	controllerPayload := []byte(`{"type":"welcome"}`)
	if err := controller.WriteJSON(routedFrame{Type: "to_agent", AgentID: "display-01", ConnectionID: connected.ConnectionID, Payload: controllerPayload}); err != nil {
		t.Fatal(err)
	}
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	var delivered []byte
	if err := agent.ReadJSON(&delivered); err != nil {
		t.Fatal(err)
	}
	if string(delivered) != string(controllerPayload) {
		t.Fatalf("agent payload = %q, want %q", delivered, controllerPayload)
	}

	if err := controller.WriteJSON(routedFrame{Type: "disconnect", AgentID: "display-01", ConnectionID: connected.ConnectionID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := agent.ReadMessage(); err == nil {
		t.Fatal("agent connection remained open after controller disconnect")
	} else if closeError, ok := err.(*websocket.CloseError); !ok || closeError.Code != websocket.ClosePolicyViolation || closeError.Text != "controller rejected agent session" {
		t.Fatalf("agent close = %v, want policy rejection with reason", err)
	}
	var disconnected routedFrame
	if err := controller.ReadJSON(&disconnected); err != nil {
		t.Fatal(err)
	}
	if disconnected.Type != "disconnected" || disconnected.ConnectionID != connected.ConnectionID {
		t.Fatal("disconnect notice lost connection identity")
	}
	replacement, _, err := websocket.DefaultDialer.Dial(websocketBase+"/v1/agents/display-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	var reconnected routedFrame
	if err := controller.ReadJSON(&reconnected); err != nil {
		t.Fatal(err)
	}
	if reconnected.Type != "connected" || reconnected.ConnectionID == "" || reconnected.ConnectionID == connected.ConnectionID {
		t.Fatal("reconnection reused routing identity")
	}
	// The final marker proves that stale frames were consumed without either
	// reaching or closing the replacement. No timing-based absence check is needed.
	for _, oldID := range []string{connected.ConnectionID, ""} {
		for _, kind := range []string{"to_agent", "disconnect"} {
			if err := controller.WriteJSON(routedFrame{Type: kind, AgentID: "display-01", ConnectionID: oldID, Payload: []byte("stale")}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := controller.WriteJSON(routedFrame{Type: "to_agent", AgentID: "display-01", ConnectionID: reconnected.ConnectionID, Payload: []byte("current")}); err != nil {
		t.Fatal(err)
	}
	_ = replacement.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := replacement.ReadJSON(&delivered); err != nil || string(delivered) != "current" {
		t.Fatalf("stale routing affected replacement: payload=%q error=%v", delivered, err)
	}
}

func TestReplacedControllerCannotRouteQueuedFrames(t *testing.T) {
	current := &peer{}
	agent := &peer{connectionID: strings.Repeat("ab", 16)}
	s := &service{controller: current, agents: map[string]*peer{"display": agent}}
	for _, kind := range []string{"to_agent", "disconnect"} {
		if s.routeControllerFrame(&peer{}, routedFrame{Type: kind, AgentID: "display", ConnectionID: agent.connectionID, Payload: []byte("stale")}) {
			t.Fatal("replaced controller retained routing authority")
		}
	}
}

// waitForControllerRegistration waits for application readiness after the HTTP upgrade.
// A completed client handshake can precede the server publishing its controller.
func waitForControllerRegistration(t *testing.T, s *service) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.RLock()
		ready := s.controller != nil
		s.mu.RUnlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("controller was not registered after WebSocket upgrade")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestControllerDisconnectResetsAgents ensures an idle agent cannot retain a stale controller session.
func TestControllerDisconnectResetsAgents(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	service := &service{
		psk:        key,
		agents:     make(map[string]*peer),
		authNonces: replay.New(2*time.Minute, 8192),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: time.Second,
			CheckOrigin:      func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/controller", service.handleController)
	mux.HandleFunc("GET /v1/agents/{agentId}", service.handleAgent)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	websocketBase := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	controllerRequest := signedControllerRequest(key, time.Now().UTC().Format(time.RFC3339), strings.Repeat("cd", 32))
	controller, _, err := websocket.DefaultDialer.Dial(websocketBase+"/v1/controller", controllerRequest.Header)
	if err != nil {
		t.Fatalf("dial controller: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	waitForControllerRegistration(t, service)
	agent, _, err := websocket.DefaultDialer.Dial(websocketBase+"/v1/agents/display-01", nil)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Second))
	var connected routedFrame
	if err := controller.ReadJSON(&connected); err != nil {
		t.Fatalf("read agent connection notification: %v", err)
	}
	if connected.Type != "connected" || connected.AgentID != "display-01" || connected.ConnectionID == "" {
		t.Fatalf("unexpected agent connection notification: %+v", connected)
	}
	if err := controller.Close(); err != nil {
		t.Fatalf("close controller: %v", err)
	}
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := agent.ReadMessage(); err == nil {
		t.Fatal("agent connection remained open after controller disconnect")
	} else if _, ok := err.(*websocket.CloseError); !ok {
		t.Fatalf("agent read failed without a WebSocket close: %v", err)
	}
}

// TestTransportRejectsUnauthorizedControllerAndInvalidAgent verifies transport rejects unauthorized controller and invalid agent.
func TestTransportRejectsUnauthorizedControllerAndInvalidAgent(t *testing.T) {
	t.Parallel()
	service := &service{psk: []byte("0123456789abcdef0123456789abcdef"), agents: make(map[string]*peer), authNonces: replay.New(2*time.Minute, 8192), upgrader: websocket.Upgrader{}}
	recorder := httptest.NewRecorder()
	service.handleController(recorder, httptest.NewRequest(http.MethodGet, "/v1/controller", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("controller status = %d, want 401", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	service.handleAgent(recorder, httptest.NewRequest(http.MethodGet, "/v1/agents/../invalid", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("agent status = %d, want 404", recorder.Code)
	}
}
