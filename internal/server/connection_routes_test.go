// File purpose: Verifies lifecycle notices revoke queued work without affecting replacement connections.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestRoutingLifecycleSkipsStaleWork(t *testing.T) {
	const id = "display"
	s := testServerWithAgents(t, Config{}, map[string]string{id: ""})
	l := &controllerLink{s: s, conn: &websocket.Conn{}, routes: make(map[string]string)}
	s.link = l
	oldID, newID := strings.Repeat("ab", 16), strings.Repeat("cd", 16)
	accept := func(kind, connectionID string) bool {
		t.Helper()
		ok, err := l.acceptRoute(routedFrame{Type: kind, AgentID: id, ConnectionID: connectionID})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	accept("connected", oldID)
	// Fill the application queue, then deliver lifecycle notices through the
	// reader path. Revocation must not wait for free queue space or a worker.
	queue := make(chan routedFrame, 32)
	var budget atomic.Int64
	for range cap(queue) {
		payload := []byte("invalid old application frame")
		queue <- routedFrame{Type: "from_agent", AgentID: id, ConnectionID: oldID, Payload: payload}
		budget.Add(int64(len(payload)))
	}
	accept("disconnected", oldID)
	if accept("from_agent", oldID) {
		t.Fatal("disconnected connection retained queue admission")
	}
	accept("connected", newID)
	current := &agentSession{id: "new", connectionID: newID}
	s.sessions[id] = current
	accept("disconnected", oldID)
	if !accept("from_agent", newID) || s.sessions[id] != current {
		t.Fatal("old disconnect revoked replacement")
	}
	if accept("from_agent", oldID) {
		t.Fatal("old application frame admitted after reconnect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.processAgentFrames(ctx, queue, &budget); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for budget.Load() != 0 {
		select {
		case <-deadline.C:
			t.Fatal("stale queue did not drain")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	s.mu.RLock()
	retained := s.sessions[id] == current
	s.mu.RUnlock()
	if !retained {
		t.Fatal("stale queued frame revoked replacement")
	}
	l.forgetRoute(id, newID)
	if accept("from_agent", newID) || s.sessions[id] != nil {
		t.Fatal("queue rejection retained route or session authority")
	}
}

func TestHandshakeCannotReplaceNewerConnectionSession(t *testing.T) {
	const id = "display"
	s := testServerWithAgents(t, Config{}, map[string]string{id: ""})
	s.agentConnected(id)
	oldID, newID := strings.Repeat("ab", 16), strings.Repeat("cd", 16)
	l := &controllerLink{s: s, conn: &websocket.Conn{}, routes: map[string]string{id: oldID}}
	s.link = l
	psk, _ := keyderivation.ParsePSK(strings.Repeat("ab", 32))
	key, _ := keyderivation.Derive(psk, id, keyderivation.TransportHandshake)
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: id, Version: "test", ClientNonce: strings.Repeat("12", 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, _ = protocol.SignHello(hello, key)
	current := &agentSession{id: "replacement", connectionID: newID}
	s.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type != "welcome" {
			t.Fatal("old handshake published state after connection replacement")
		}
		l.forgetRoute(id, oldID)
		if _, err := l.acceptRoute(routedFrame{Type: "connected", AgentID: id, ConnectionID: newID}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.sessions[id] = current
		s.mu.Unlock()
		return nil
	}
	if err := s.handleHello(id, oldID, mustJSON(t, hello), psk, key); err == nil {
		t.Fatal("handshake survived replacement during welcome")
	}
	if s.sessions[id] != current {
		t.Fatal("old handshake overwrote replacement session")
	}
	if err := l.send(id, oldID, protocol.Frame{Type: "command"}); err == nil {
		t.Fatal("old route remained writable")
	}
}

func TestRoutingRejectsInvalidContracts(t *testing.T) {
	l := &controllerLink{}
	for _, frame := range []routedFrame{
		{Type: "connected", AgentID: "display"},
		{Type: "connected", AgentID: "display", ConnectionID: strings.Repeat("gg", 16)},
		{Type: "connected", AgentID: "../display", ConnectionID: strings.Repeat("ab", 16)},
		{Type: "unknown", AgentID: "display", ConnectionID: strings.Repeat("ab", 16)},
	} {
		if ok, err := l.acceptRoute(frame); ok || err == nil {
			t.Fatal("invalid routing frame accepted")
		}
	}
}

// TestConnectionSourceMustMatchEnrollment closes another WireGuard peer's or an
// unknown identity's connection before it can hold that identity, while the
// enrolled address still completes the authenticated handshake.
func TestConnectionSourceMustMatchEnrollment(t *testing.T) {
	controller := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	for _, test := range []struct{ agentID, source, want string }{
		{"display", "10.99.0.2", ""},
		{"display", "127.0.0.1", ""},
		{"display", "10.99.0.9", "connection source does not match the enrolled tunnel address"},
		{"display", "", "connection source does not match the enrolled tunnel address"},
		{"unknown", "10.99.0.2", "agent is not provisioned in the authority database"},
	} {
		if got := controller.connectionSourceRejection(test.agentID, test.source); got != test.want {
			t.Errorf("%s from %q rejection=%q, want %q", test.agentID, test.source, got, test.want)
		}
	}
	responses := make(chan routedFrame, 16)
	upgrader := websocket.Upgrader{}
	transport := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		foreign, enrolled := strings.Repeat("ab", 16), strings.Repeat("cd", 16)
		for _, frame := range []routedFrame{
			{Type: "connected", AgentID: "display", ConnectionID: foreign, RemoteAddress: "10.99.0.9"},
			controllerWorkerFrame(t, foreign),
		} {
			if err := connection.WriteJSON(frame); err != nil {
				return
			}
		}
		var response routedFrame
		if err := connection.ReadJSON(&response); err != nil {
			return
		}
		responses <- response
		for _, frame := range []routedFrame{
			{Type: "disconnected", AgentID: "display", ConnectionID: foreign},
			{Type: "connected", AgentID: "display", ConnectionID: enrolled, RemoteAddress: "10.99.0.2"},
			controllerWorkerFrame(t, enrolled),
		} {
			if err := connection.WriteJSON(frame); err != nil {
				return
			}
		}
		if err := connection.ReadJSON(&response); err == nil {
			responses <- response
		}
	}))
	t.Cleanup(transport.Close)
	controller.sendOverride = nil
	controller.link = newControllerLink(controller, "ws"+strings.TrimPrefix(transport.URL, "http"), strings.Repeat("ab", 32))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = controller.link.session(ctx) }()
	for index, want := range []routedFrame{
		{Type: "disconnect", ConnectionID: strings.Repeat("ab", 16)},
		{Type: "to_agent", ConnectionID: strings.Repeat("cd", 16)},
	} {
		select {
		case response := <-responses:
			if response.Type != want.Type || response.ConnectionID != want.ConnectionID {
				t.Fatalf("response %d = %+v, want %s for %s", index, response, want.Type, want.ConnectionID)
			}
		case <-ctx.Done():
			t.Fatalf("response %d was not received", index)
		}
	}
}

// TestConnectionSourceFailsClosedWithoutAuthority prevents a transient lookup
// failure from admitting a source that a later PSK-only hello would not check.
func TestConnectionSourceFailsClosedWithoutAuthority(t *testing.T) {
	controller := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	if err := controller.store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"10.99.0.2", "10.99.0.9", "127.0.0.1"} {
		if got := controller.connectionSourceRejection("display", source); got != "agent enrollment authority unavailable" {
			t.Fatalf("unavailable enrollment from %s: rejection=%q", source, got)
		}
	}
	controller.store = nil
	if got := controller.connectionSourceRejection("display", "10.99.0.2"); got != "agent enrollment authority unavailable" {
		t.Fatalf("absent enrollment authority: rejection=%q", got)
	}
}
