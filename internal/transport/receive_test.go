// File purpose: Verifies bounded transport reads isolate unauthenticated peers and tolerate bursts.
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/gorilla/websocket"
)

// TestPartialAgentFramesHaveGlobalReceiveBound holds incomplete JSON strings
// open, checks controller responsiveness, and proves closing a peer restores capacity.
func TestPartialAgentFramesHaveGlobalReceiveBound(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	s := &service{psk: key, agents: make(map[string]*peer), authNonces: replay.New(2*time.Minute, 8192)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/controller", s.handleController)
	mux.HandleFunc("GET /v1/agents/{agentId}", s.handleAgent)
	server := httptest.NewServer(mux)
	defer server.Close()
	defer s.stopPeers()
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	request := signedControllerRequest(key, time.Now().UTC().Format(time.RFC3339), strings.Repeat("ab", 32))
	controller, _, err := websocket.DefaultDialer.Dial(base+"/v1/controller", request.Header)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	waitForControllerRegistration(t, s)
	frames := make(chan routedFrame, 64)
	pong := make(chan struct{}, 1)
	controller.SetPongHandler(func(string) error {
		select {
		case pong <- struct{}{}:
		default:
		}
		return nil
	})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			var frame routedFrame
			if controller.ReadJSON(&frame) != nil {
				return
			}
			if frame.Type == "from_agent" && string(frame.Payload) == "hello" {
				if controller.WriteJSON(routedFrame{Type: "to_agent", AgentID: frame.AgentID, ConnectionID: frame.ConnectionID, Payload: []byte("approved")}) != nil {
					return
				}
			} else {
				frames <- frame
			}
		}
	}()
	defer func() { _ = controller.Close(); <-readerDone }()

	dialAgent := func(id string) *websocket.Conn {
		t.Helper()
		connection, _, err := websocket.DefaultDialer.Dial(base+"/v1/agents/"+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.WriteJSON([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		var reply []byte
		if err := connection.ReadJSON(&reply); err != nil || string(reply) != "approved" {
			t.Fatalf("controller approval failed: %q %v", reply, err)
		}
		return connection
	}
	startPartialFrame := func(connection *websocket.Conn) error {
		t.Helper()
		writer, err := connection.NextWriter(websocket.TextMessage)
		if err != nil {
			return err
		}
		// Exceed the WebSocket write buffer so an unfinished message reaches the
		// server. Keeping the JSON string open also keeps its decoder blocked.
		_, err = writer.Write(append([]byte{'"'}, bytes.Repeat([]byte{'a'}, 64<<10)...))
		return err
	}
	clients := make([]*websocket.Conn, maxConcurrentAgentFrames)
	for index := range clients {
		clients[index] = dialAgent(fmt.Sprintf("partial-%02d", index))
		if err := startPartialFrame(clients[index]); err != nil {
			t.Fatal(err)
		}
		waitForAgentFrameCount(t, s, int64(index+1))
	}
	limited := dialAgent("over-capacity")
	_ = startPartialFrame(limited)
	_ = limited.SetReadDeadline(time.Now().Add(agentFrameAdmissionWait + time.Second))
	if _, _, err := limited.ReadMessage(); err == nil {
		t.Fatal("over-capacity partial frame remained connected")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("over-capacity partial frame was not rejected promptly")
	}
	if got := s.agentFrames.Load(); got != maxConcurrentAgentFrames {
		t.Fatalf("active receive frames = %d, want %d", got, maxConcurrentAgentFrames)
	}
	if err := controller.WriteControl(websocket.PingMessage, []byte("receive-capacity"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pong:
	case <-time.After(time.Second):
		t.Fatal("agent receive saturation blocked the authenticated controller")
	}
	_ = clients[0].Close()
	waitForAgentFrameCount(t, s, maxConcurrentAgentFrames-1)
	recovered := dialAgent("recovered")
	if err := recovered.WriteJSON([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case frame := <-frames:
			if frame.Type == "from_agent" && frame.AgentID == "recovered" && string(frame.Payload) == "probe" {
				s.stopPeers()
				if s.agentFrames.Load() != 0 || s.queueBudget.Load() != 0 {
					t.Fatal("shutdown leaked receive or queued-frame reservations")
				}
				return
			}
		case <-deadline:
			t.Fatal("closing an incomplete frame did not restore receive capacity")
		}
	}
}

// TestAgentFrameBurstSurvivesAdmissionDelay keeps the receive bound while a
// complete-frame burst waits through a short period of busy routing workers.
func TestAgentFrameBurstSurvivesAdmissionDelay(t *testing.T) {
	const pendingFrames = 99
	s := &service{}
	held := make(chan struct{}, maxConcurrentAgentFrames)
	started := make(chan struct{}, pendingFrames)
	completed := make(chan bool, pendingFrames)
	forwarded := make(chan []byte, pendingFrames)
	release := make(chan struct{})
	pendingStart := make(chan struct{})
	var releaseOnce sync.Once
	var pendingStartOnce sync.Once
	releaseHolders := func() { releaseOnce.Do(func() { close(release) }) }
	startPending := func() { pendingStartOnce.Do(func() { close(pendingStart) }) }
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetReadLimit(maxMessageBytes)
		if r.URL.Path == "/pending" {
			started <- struct{}{}
			<-pendingStart
		}
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		accepted := s.readAgentFrame(connection, func(payload []byte) bool {
			if r.URL.Path == "/holder" {
				held <- struct{}{}
				<-release
			} else {
				forwarded <- payload
			}
			return true
		})
		if r.URL.Path == "/pending" {
			completed <- accepted
		}
	}))
	defer server.Close()
	defer releaseHolders()
	defer startPending()
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	dialFrame := func(path string) {
		t.Helper()
		connection, _, err := websocket.DefaultDialer.Dial(base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.WriteJSON([]byte("probe")); err != nil {
			t.Fatal(err)
		}
	}
	for range maxConcurrentAgentFrames {
		dialFrame("/holder")
		select {
		case <-held:
		case <-time.After(2 * time.Second):
			t.Fatal("frame did not enter its blocked routing callback")
		}
	}
	for range pendingFrames {
		dialFrame("/pending")
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("pending frame reader did not start")
		}
	}
	// Start admission only after every reader has started and every complete
	// frame has been written, excluding connection setup from the wait budget.
	// The former 100 ms admission policy disconnected healthy queued frames
	// during this bounded routing delay.
	startPending()
	select {
	case <-completed:
		t.Fatal("queued frame ended before routing capacity was released")
	case <-time.After(250 * time.Millisecond):
	}
	if got := s.agentFrames.Load(); got != maxConcurrentAgentFrames {
		t.Fatalf("waiting frames changed the receive bound: %d", got)
	}
	releaseHolders()
	deadline := time.After(3 * time.Second)
	for range pendingFrames {
		select {
		case accepted := <-completed:
			if !accepted {
				t.Fatal("healthy frame rejected after routing capacity became available")
			}
		case <-deadline:
			t.Fatal("queued frame did not complete after routing capacity was released")
		}
		select {
		case payload := <-forwarded:
			if string(payload) != "probe" {
				t.Fatalf("forwarded payload=%q", payload)
			}
		default:
			t.Fatal("accepted frame was not forwarded")
		}
	}
	waitForAgentFrameCount(t, s, 0)
}

// TestAgentFrameBurstWaitsForReceiveCapacity keeps the decoder allocation bound
// while allowing a complete frame to use capacity released by a short burst.
func TestAgentFrameBurstWaitsForReceiveCapacity(t *testing.T) {
	s := &service{}
	frames := make(chan []byte, 1)
	pendingDone := make(chan bool, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetReadLimit(maxMessageBytes)
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		accepted := s.readAgentFrame(connection, func(payload []byte) bool {
			frames <- payload
			return true
		})
		if r.URL.Path == "/pending" {
			pendingDone <- accepted
		}
	}))
	defer server.Close()
	base := "ws" + strings.TrimPrefix(server.URL, "http")
	clients := make([]*websocket.Conn, maxConcurrentAgentFrames)
	for index := range clients {
		connection, _, err := websocket.DefaultDialer.Dial(base, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		clients[index] = connection
		writer, err := connection.NextWriter(websocket.TextMessage)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(append([]byte{'"'}, bytes.Repeat([]byte{'a'}, 64<<10)...)); err != nil {
			t.Fatal(err)
		}
		waitForAgentFrameCount(t, s, int64(index+1))
	}
	pending, _, err := websocket.DefaultDialer.Dial(base+"/pending", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	if err := pending.WriteJSON([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pendingDone:
		t.Fatal("a short receive burst disconnected the waiting frame")
	case <-time.After(25 * time.Millisecond):
	}
	if got := s.agentFrames.Load(); got != maxConcurrentAgentFrames {
		t.Fatalf("waiting frame exceeded the decoder bound: %d", got)
	}
	_ = clients[0].Close()
	select {
	case payload := <-frames:
		if string(payload) != "probe" {
			t.Fatalf("forwarded payload=%q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting frame did not use released receive capacity")
	}
	if !<-pendingDone {
		t.Fatal("waiting frame was rejected after capacity became available")
	}
}

// TestFrameCapacityAtExpiry models a reader resuming after its admission timer
// fired while another reader released capacity. Available slots must win over
// expiry, while a full decoder pool still rejects without another wait.
func TestFrameCapacityAtExpiry(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "available"
		if full {
			name = "full"
		}
		t.Run(name, func(t *testing.T) {
			for attempt := range 64 {
				slots := make(chan struct{}, maxConcurrentAgentFrames)
				occupied := maxConcurrentAgentFrames - 1
				if full {
					occupied++
				}
				for range occupied {
					slots <- struct{}{}
				}
				expired := make(chan time.Time, 1)
				expired <- time.Time{}
				if accepted := waitForFrameCapacity(slots, expired); accepted == full {
					t.Fatalf("attempt=%d accepted=%t full=%t", attempt, accepted, full)
				}
				if len(slots) != maxConcurrentAgentFrames {
					t.Fatalf("reserved slots=%d, want %d", len(slots), maxConcurrentAgentFrames)
				}
			}
		})
	}
}

// waitForAgentFrameCount synchronizes partial-frame fixtures without allocation-heavy payloads.
func waitForAgentFrameCount(t *testing.T, s *service, wanted int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.agentFrames.Load() == wanted {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active receive frames = %d, want %d", s.agentFrames.Load(), wanted)
}
