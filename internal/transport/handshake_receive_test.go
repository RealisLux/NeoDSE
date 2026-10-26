// File purpose: Verifies first-frame limits and controller approval isolate active transport traffic.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package transport

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/gorilla/websocket"
)

type handshakeFixture struct {
	service    *service
	controller *websocket.Conn
	frames     chan routedFrame
	url        string
}

// newHandshakeFixture owns real transport sockets with a manually approving controller.
func newHandshakeFixture(t *testing.T) *handshakeFixture {
	t.Helper()
	return newHandshakeFixtureFrom(t, "")
}

// newHandshakeFixtureFrom optionally presents agent connections as arriving
// from one WireGuard source address instead of the loopback test client.
func newHandshakeFixtureFrom(t *testing.T, source string) *handshakeFixture {
	t.Helper()
	key := bytes.Repeat([]byte{0xab}, 32)
	s := &service{psk: key, agents: make(map[string]*peer), authNonces: replay.New(2*time.Minute, 8192)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/controller", s.handleController)
	mux.HandleFunc("GET /v1/agents/{agentId}", func(w http.ResponseWriter, r *http.Request) {
		if source != "" {
			r.RemoteAddr = net.JoinHostPort(source, "40000")
		}
		s.handleAgent(w, r)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(s.stopPeers)
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	request := signedControllerRequest(key, time.Now().UTC().Format(time.RFC3339), strings.Repeat("ab", 32))
	controller, _, err := websocket.DefaultDialer.Dial(base+"/v1/controller", request.Header)
	if err != nil {
		t.Fatal(err)
	}
	waitForControllerRegistration(t, s)
	fixture := &handshakeFixture{service: s, controller: controller, frames: make(chan routedFrame, 64), url: base}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			var frame routedFrame
			if controller.ReadJSON(&frame) != nil {
				return
			}
			select {
			case fixture.frames <- frame:
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); _ = controller.Close(); <-done })
	return fixture
}

// dial opens a small-buffer client so partial fragments reach the transport immediately.
func (fixture *handshakeFixture) dial(t *testing.T, id string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{WriteBufferSize: 128}
	connection, _, err := dialer.Dial(fixture.url+"/v1/agents/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// nextPayload waits for a routed application message while ignoring lifecycle notices.
func (fixture *handshakeFixture) nextPayload(t *testing.T, id string) routedFrame {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case frame := <-fixture.frames:
			if frame.Type == "from_agent" && frame.AgentID == id {
				return frame
			}
		case <-timer.C:
			t.Fatalf("agent %s did not reach the controller", id)
		}
	}
}

// approve completes the same first-reply barrier used by the authenticated controller.
func (fixture *handshakeFixture) approve(t *testing.T, id string, connection *websocket.Conn) {
	t.Helper()
	frame := fixture.nextPayload(t, id)
	if err := fixture.controller.WriteJSON(routedFrame{Type: "to_agent", AgentID: id, ConnectionID: frame.ConnectionID, Payload: []byte("approved")}); err != nil {
		t.Fatal(err)
	}
	var reply []byte
	if err := connection.ReadJSON(&reply); err != nil || string(reply) != "approved" {
		t.Fatalf("controller approval failed: %q %v", reply, err)
	}
}

// TestUnapprovedFramesCannotStarveActiveAgents reproduces decoder starvation
// with unauthenticated partial frames and preserves an approved peer's status traffic.
func TestUnapprovedFramesCannotStarveActiveAgents(t *testing.T) {
	fixture := newHandshakeFixture(t)
	healthy := fixture.dial(t, "healthy")
	if err := healthy.WriteJSON([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	fixture.approve(t, "healthy", healthy)
	clients := make([]*websocket.Conn, maxConcurrentHandshakes)
	for index := range clients {
		clients[index] = fixture.dial(t, fmt.Sprintf("partial-%02d", index))
		writer, err := clients[index].NextWriter(websocket.TextMessage)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(append([]byte{'"'}, bytes.Repeat([]byte{'a'}, 1024)...)); err != nil {
			t.Fatal(err)
		}
		waitForHandshakeFrameCount(t, fixture.service, int64(index+1))
	}
	overCapacity := fixture.dial(t, "over-capacity")
	writer, err := overCapacity.NextWriter(websocket.TextMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(append([]byte{'"'}, bytes.Repeat([]byte{'a'}, 1024)...)); err != nil {
		t.Fatal(err)
	}
	_ = overCapacity.SetReadDeadline(time.Now().Add(agentFrameAdmissionWait + time.Second))
	if _, _, err := overCapacity.ReadMessage(); err == nil {
		t.Fatal("over-capacity handshake remained connected")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("over-capacity handshake did not release its connection promptly")
	}
	if got := fixture.service.helloFrames.Load(); got != maxConcurrentHandshakes {
		t.Fatalf("handshake decoders exceeded their bound: %d", got)
	}
	if got := fixture.service.agentFrames.Load(); got != 0 {
		t.Fatalf("unapproved partial frames consumed %d active slots", got)
	}
	if err := healthy.WriteJSON([]byte("healthy-status")); err != nil {
		t.Fatal(err)
	}
	if got := fixture.nextPayload(t, "healthy"); string(got.Payload) != "healthy-status" {
		t.Fatalf("healthy status changed: %q", got.Payload)
	}
	// The controller can receive the queued status before its routing caller's
	// deferred reservation release runs. Wait for that healthy frame to finish.
	waitForAgentFrameCount(t, fixture.service, 0)
	_ = clients[0].Close()
	waitForHandshakeFrameCount(t, fixture.service, maxConcurrentHandshakes-1)
	recovered := fixture.dial(t, "recovered")
	if err := recovered.WriteJSON([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	fixture.approve(t, "recovered", recovered)
	fixture.service.stopPeers()
	if fixture.service.helloFrames.Load() != 0 || fixture.service.agentFrames.Load() != 0 || fixture.service.queueBudget.Load() != 0 {
		t.Fatal("shutdown leaked handshake, active, or queue reservations")
	}
}

// TestHandshakeRejectsOversizedAndTrailingFrames checks the complete first
// message remains bounded even when valid JSON precedes excessive trailing bytes.
func TestHandshakeRejectsOversizedAndTrailingFrames(t *testing.T) {
	for _, scenario := range []struct{ name, frame string }{
		{"oversized", `"` + strings.Repeat("a", maxHandshakeMessageBytes) + `"`},
		{"trailing bytes", `"aGVsbG8="` + strings.Repeat(" ", maxHandshakeMessageBytes)},
		{"multiple values", `"aGVsbG8=" "c2Vjb25k"`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := newHandshakeFixture(t)
			connection := fixture.dial(t, "oversized")
			_ = connection.WriteMessage(websocket.TextMessage, []byte(scenario.frame))
			_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := connection.ReadMessage(); err == nil {
				t.Fatal("invalid first frame remained connected")
			} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				t.Fatal("invalid first frame was not rejected promptly")
			}
			for {
				select {
				case frame := <-fixture.frames:
					if frame.Type == "from_agent" {
						t.Fatal("invalid first frame reached the controller")
					}
				default:
					return
				}
			}
		})
	}
}

// TestPipelinedFrameWaitsForControllerApproval prevents read-ahead from
// reserving active capacity before a controller accepts the first message.
func TestPipelinedFrameWaitsForControllerApproval(t *testing.T) {
	fixture := newHandshakeFixture(t)
	connection := fixture.dial(t, "pipeline")
	if err := connection.WriteJSON([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := connection.WriteJSON(bytes.Repeat([]byte{'x'}, maxHandshakeMessageBytes)); err != nil {
		t.Fatal(err)
	}
	first := fixture.nextPayload(t, "pipeline")
	if string(first.Payload) != "hello" {
		t.Fatalf("unexpected first message: %q", first.Payload)
	}
	select {
	case frame := <-fixture.frames:
		if frame.Type == "from_agent" {
			t.Fatal("pipelined frame reached the controller before approval")
		}
	case <-time.After(100 * time.Millisecond):
	}
	if fixture.service.agentFrames.Load() != 0 {
		t.Fatal("pipelined message reserved active capacity before approval")
	}
	if err := fixture.controller.WriteJSON(routedFrame{Type: "to_agent", AgentID: first.AgentID, ConnectionID: first.ConnectionID, Payload: []byte("approved")}); err != nil {
		t.Fatal(err)
	}
	if got := fixture.nextPayload(t, "pipeline"); len(got.Payload) != maxHandshakeMessageBytes {
		t.Fatalf("approval did not admit the full-size pipelined frame: %d", len(got.Payload))
	}
}

// TestUnapprovedPeerRetainsHandshakeDeadline checks a complete first message
// cannot disable the deadline without the controller's first reply.
func TestUnapprovedPeerRetainsHandshakeDeadline(t *testing.T) {
	fixture := newHandshakeFixture(t)
	connection := fixture.dial(t, "unapproved")
	if err := connection.WriteJSON([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	fixture.nextPayload(t, "unapproved")
	fixture.service.mu.RLock()
	peer := fixture.service.agents["unapproved"]
	fixture.service.mu.RUnlock()
	// Reset the actual production timer after the peer is fully registered.
	// Waiting eleven seconds adds no evidence beyond exercising its callback.
	peer.handshake.Reset(25 * time.Millisecond)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("unapproved peer survived its handshake deadline")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("unapproved peer was not closed by its handshake timer")
	}
}

// TestControllerChangeReleasesUnapprovedPeer checks that approval waiters
// relinquish their identity immediately when their owning controller disappears.
func TestControllerChangeReleasesUnapprovedPeer(t *testing.T) {
	for _, change := range []string{"disconnect", "replacement"} {
		t.Run(change, func(t *testing.T) {
			fixture := newHandshakeFixture(t)
			connection := fixture.dial(t, "unapproved")
			if err := connection.WriteJSON([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			fixture.nextPayload(t, "unapproved")
			fixture.service.mu.RLock()
			peer := fixture.service.agents["unapproved"]
			fixture.service.mu.RUnlock()
			if change == "disconnect" {
				_ = fixture.controller.Close()
			} else {
				request := signedControllerRequest(bytes.Repeat([]byte{0xab}, 32), time.Now().UTC().Format(time.RFC3339), strings.Repeat("cd", 32))
				replacement, _, err := websocket.DefaultDialer.Dial(fixture.url+"/v1/controller", request.Header)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = replacement.Close() })
			}
			select {
			case <-peer.done:
			case <-time.After(time.Second):
				t.Fatal("controller change did not release the approval waiter")
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				fixture.service.mu.RLock()
				reserved := fixture.service.agents["unapproved"] != nil
				fixture.service.mu.RUnlock()
				if !reserved {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("unapproved identity remained reserved after controller change")
		})
	}
}

// TestPendingConnectionsAreBoundedPerSource keeps one WireGuard peer from
// holding other displays' identities or every handshake decoder, and reports
// the authenticated source address to the controller.
func TestPendingConnectionsAreBoundedPerSource(t *testing.T) {
	fixture := newHandshakeFixtureFrom(t, "10.99.0.7")
	first := fixture.dial(t, "display-a")
	fixture.dial(t, "display-b")
	if connection, response, err := (&websocket.Dialer{}).Dial(fixture.url+"/v1/agents/display-c", nil); err == nil {
		_ = connection.Close()
		t.Fatal("a third pending connection from one source was admitted")
	} else if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-limit source response=%v error=%v", response, err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for connected := false; !connected; {
		select {
		case frame := <-fixture.frames:
			if frame.Type == "connected" && frame.AgentID == "display-a" {
				if frame.RemoteAddress != "10.99.0.7" {
					t.Fatalf("connection source = %q", frame.RemoteAddress)
				}
				connected = true
			}
		case <-timer.C:
			t.Fatal("controller was not told about the new connection")
		}
	}
	if err := first.WriteJSON([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	fixture.approve(t, "display-a", first)
	source := netip.MustParseAddr("10.99.0.7")
	deadline := time.Now().Add(2 * time.Second)
	for {
		fixture.service.mu.RLock()
		pending := fixture.service.pending[source]
		fixture.service.mu.RUnlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("approval left %d pending connections", pending)
		}
		time.Sleep(time.Millisecond)
	}
	fixture.dial(t, "display-c")
	loopback := netip.MustParseAddr("127.0.0.1")
	for range maxPendingConnectionsPerSource + 1 {
		if !fixture.service.admitPendingSource(loopback) {
			t.Fatal("controller-host connections were limited")
		}
	}
}

// waitForHandshakeFrameCount synchronizes incomplete first-message fixtures.
func waitForHandshakeFrameCount(t *testing.T, s *service, wanted int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.helloFrames.Load() == wanted {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active handshake frames = %d, want %d", s.helloFrames.Load(), wanted)
}
