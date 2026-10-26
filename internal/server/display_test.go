// File purpose: Verifies authenticated display stream framing, cancellation, and revocation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestDisplayFrameRejectionReasons checks actionable logs without exposing authenticated message contents.
func TestDisplayFrameRejectionReasons(t *testing.T) {
	var logged bytes.Buffer
	previousLog := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previousLog)
	for _, scenario := range []struct {
		name   string
		change func(*protocol.Display)
		raw    []byte
		want   string
	}{
		{name: "malformed", raw: []byte(`{"private-invalid-field":true}`), want: "malformed display message"},
		{name: "identity", change: func(m *protocol.Display) { m.AgentID = "private-other-agent" }, want: "invalid display identity or field bounds"},
		{name: "action", change: func(m *protocol.Display) { m.Action = "private-action" }, want: "unsupported display action"},
		{name: "payload", change: func(m *protocol.Display) { m.Data = []byte("private-frame-contents") }, want: "invalid display payload fields"},
		{name: "session", change: func(m *protocol.Display) { m.SessionID = "private-old-session" }, want: "display session changed"},
		{name: "sequence", change: func(m *protocol.Display) { m.Sequence = 2 }, want: "nonconsecutive display sequence: received=2 expected=1"},
		{name: "signature", change: func(m *protocol.Display) { m.Signature = "private-invalid-signature" }, want: "display authentication failed"},
		{name: "timestamp", change: func(m *protocol.Display) { m.Timestamp = "private-invalid-time" }, want: "invalid display timestamp"},
		{name: "stale", change: func(m *protocol.Display) {
			m.Timestamp = time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano)
		}, want: "stale display timestamp"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
			session := server.sessions["display"]
			message := protocol.Display{Protocol: protocol.Version, AgentID: "display", SessionID: session.id,
				Sequence: 1, StreamID: strings.Repeat("a", 32), Action: "ready", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
			if scenario.change != nil {
				scenario.change(&message)
			}
			if message.Signature == "" {
				var err error
				message.Signature, err = protocol.SignDisplay(message, session.keys[keyderivation.TransportDisplay])
				if err != nil {
					t.Fatal(err)
				}
			}
			payload := scenario.raw
			if payload == nil {
				payload = mustJSON(t, message)
			}
			if err := server.handleDisplayFrame("display", payload); err == nil || err.Error() != scenario.want {
				t.Fatalf("rejection=%v, want %q", err, scenario.want)
			}
			if session.lastReceived != 0 {
				t.Fatal("rejected frame advanced the receive sequence")
			}
			logged.Reset()
			server.handleAgentFrame("display", session.connectionID, mustJSON(t, protocol.Frame{Type: "display", Payload: payload}))
			if !strings.Contains(logged.String(), "invalid authenticated display relay frame: "+scenario.want) {
				t.Fatalf("missing rejection detail: %q", logged.String())
			}
			for _, secret := range []string{"private-", session.id, message.StreamID, message.Signature, fmt.Sprintf("%x", session.keys[keyderivation.TransportDisplay])} {
				if strings.Contains(logged.String(), secret) {
					t.Fatal("display rejection log exposed authenticated message contents")
				}
			}
			if server.sessionFor("display") != nil {
				t.Fatal("rejected frame retained session authority")
			}
		})
	}
}

// displayTestReplies simulates capture startup while exposing the request-owned relay.
func displayTestReplies(t *testing.T, server *Server, action string) <-chan *displayRelay {
	t.Helper()
	opened := make(chan *displayRelay, 1)
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		var message protocol.Display
		if err := protocol.Decode(frame.Payload, &message); err != nil {
			return err
		}
		server.displayMu.Lock()
		relay := server.displayRelays[message.StreamID]
		server.displayMu.Unlock()
		if relay == nil {
			return nil
		}
		switch message.Action {
		case "prepare":
			relay.control <- protocol.Display{Action: "ready"}
		case "open":
			relay.control <- protocol.Display{Action: action}
			opened <- relay
		}
		return nil
	}
	return opened
}

// TestDisplayStreamCancellationReleasesRelay verifies startup and active requests release capture.
func TestDisplayStreamCancellationReleasesRelay(t *testing.T) {
	for _, startup := range []bool{false, true} {
		t.Run(fmt.Sprint(startup), func(t *testing.T) {
			server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
			handler, token := testAPI(t, server)
			opened := displayTestReplies(t, server, "open")
			prepared := make(chan struct{}, 1)
			if startup {
				server.sendOverride = func(_ string, frame protocol.Frame) error {
					var message protocol.Display
					if err := protocol.Decode(frame.Payload, &message); err != nil {
						return err
					}
					if message.Action == "prepare" {
						prepared <- struct{}{}
					}
					return nil
				}
			}
			done := make(chan struct{})
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				handler.ServeHTTP(w, r)
			}))
			defer host.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, host.URL+"/api/v1/agents/agent/display/stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			result := make(chan error, 1)
			go func() {
				response, err := host.Client().Do(request)
				if err == nil {
					defer response.Body.Close()
					if response.StatusCode != http.StatusOK {
						err = fmt.Errorf("status=%d", response.StatusCode)
					} else {
						var header [4]byte
						_, err = io.ReadFull(response.Body, header[:])
						if err == nil && binary.BigEndian.Uint32(header[:]) != 3 {
							err = errors.New("invalid frame length")
						}
						if err == nil {
							var frame [3]byte
							_, err = io.ReadFull(response.Body, frame[:])
							if err == nil && frame != [3]byte{1, 2, 3} {
								err = errors.New("frame changed")
							}
						}
					}
				}
				result <- err
			}()
			if startup {
				select {
				case <-prepared:
				case <-time.After(time.Second):
					t.Fatal("preparation did not start")
				}
			} else {
				var relay *displayRelay
				select {
				case relay = <-opened:
				case <-time.After(time.Second):
					t.Fatal("capture did not start")
				}
				relay.frames <- []byte{1, 2, 3}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled stream retained capture")
			}
			if startup {
				<-result
			}
			if len(server.displayRelays) != 0 {
				t.Fatal("viewer slot retained")
			}
		})
	}
}

// TestDisplayStreamStartupFailureReleasesRelay verifies failures remain ordinary API responses.
func TestDisplayStreamStartupFailureReleasesRelay(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
	handler, token := testAPI(t, server)
	displayTestReplies(t, server, "error")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent/display/stream", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(server.displayRelays) != 0 {
		t.Fatalf("status=%d relays=%d", response.Code, len(server.displayRelays))
	}
}

// TestDisplayStreamFrameBounds checks wire framing and cleanup at the HTTP serialization boundary.
func TestDisplayStreamFrameBounds(t *testing.T) {
	for _, size := range []int{0, displayChunkBytes, displayChunkBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
			handler, token := testAPI(t, server)
			opened := displayTestReplies(t, server, "open")
			done := make(chan struct{})
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				handler.ServeHTTP(w, r)
			}))
			defer host.Close()
			client := host.Client()
			client.Timeout = 5 * time.Second
			request, err := http.NewRequest(http.MethodGet, host.URL+"/api/v1/agents/agent/display/stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status=%d", response.StatusCode)
			}
			relay := <-opened
			relay.frames <- make([]byte, size)
			var header [4]byte
			_, err = io.ReadFull(response.Body, header[:])
			if size == displayChunkBytes {
				if err != nil || binary.BigEndian.Uint32(header[:]) != uint32(displayChunkBytes) {
					t.Fatalf("maximum frame header=%v error=%v", header, err)
				}
				if n, err := io.CopyN(io.Discard, response.Body, int64(size)); err != nil || n != int64(size) {
					t.Fatalf("maximum frame bytes=%d error=%v", n, err)
				}
			} else if !errors.Is(err, io.EOF) {
				t.Fatalf("invalid frame reached the client: header=%v error=%v", header, err)
			}
			response.Body.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("closed stream retained capture")
			}
			if len(server.displayRelays) != 0 {
				t.Fatal("closed stream retained the viewer slot")
			}
		})
	}
}

// TestDisplayStreamRejectsRequestBody prevents browser input on the capture endpoint.
func TestDisplayStreamRejectsRequestBody(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
	handler, token := testAPI(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent/display/stream", strings.NewReader("input"))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(server.displayRelays) != 0 {
		t.Fatalf("status=%d", response.Code)
	}
}

// TestDisplayAuthorizationTracksAccountChanges rejects stale streaming authority.
func TestDisplayAuthorizationTracksAccountChanges(t *testing.T) {
	for _, change := range []string{"rotate", "delete", "disable", "scope", "expire", "unavailable"} {
		t.Run(change, func(t *testing.T) {
			server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
			ctx := context.Background()
			input := serviceAccountInput{Name: "viewer", Roles: []Role{RoleViewer}, Agents: []string{"agent"}}
			account, token, err := server.createServiceAccount(ctx, input, false)
			if err != nil {
				t.Fatal(err)
			}
			relay := &displayRelay{agentID: "agent", tokenID: strings.Split(token, "_")[1], tokenDigest: sha256.Sum256([]byte(token))}
			if !server.displayAuthorized(ctx, relay) {
				t.Fatal("fresh viewer rejected")
			}
			switch change {
			case "rotate":
				_, err = server.store.RotateAccountToken(ctx, account.ID, time.Now())
			case "delete":
				err = server.store.DeleteAccount(ctx, account.ID)
			case "unavailable":
				err = server.store.Close()
			default:
				switch change {
				case "disable":
					input.Disabled = true
				case "scope":
					input.Agents = nil
				case "expire":
					expired := time.Now().Add(-time.Minute)
					input.ExpiresAt = &expired
				}
				_, err = server.store.ReplaceAccount(ctx, account.ID, storeAccountInput(input), time.Now())
			}
			if err != nil {
				t.Fatal(err)
			}
			if server.displayAuthorized(ctx, relay) {
				t.Fatal("revoked viewer retained access")
			}
		})
	}
}

// TestOpenDisplayClosesAfterRevocation exercises account and agent revocation on real HTTP streams.
func TestOpenDisplayClosesAfterRevocation(t *testing.T) {
	for _, mode := range []string{"token", "agent rotation", "agent removal", "storage failure"} {
		t.Run(mode, func(t *testing.T) { testOpenDisplayRevocation(t, mode) })
	}
}

// testOpenDisplayRevocation verifies an idle stream loses authority without another agent status.
func testOpenDisplayRevocation(t *testing.T, mode string) {
	t.Helper()
	server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
	account, token, err := server.createServiceAccount(context.Background(), serviceAccountInput{Name: "viewer", Roles: []Role{RoleViewer}, AllAgents: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	opened := displayTestReplies(t, server, "open")
	done := make(chan struct{})
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		server.controllerHandler().ServeHTTP(w, r)
	}))
	defer host.Close()
	request, err := http.NewRequest(http.MethodGet, host.URL+"/api/v1/agents/agent/display/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := host.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	<-opened
	switch mode {
	case "token":
		_, err = server.store.RotateAccountToken(context.Background(), account.ID, time.Now())
	case "agent rotation":
		err = server.store.PutAgent(context.Background(), "agent", strings.Repeat("cd", 32), "10.99.0.2", true, time.Now())
	case "agent removal":
		err = server.store.RemoveAgent(context.Background(), "agent")
	case "storage failure":
		err = server.store.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(displayAuthorizationInterval + 2*time.Second):
		t.Fatal("revoked authority retained a live stream")
	}
	if len(server.displayRelays) != 0 {
		t.Fatal("revoked stream retained its viewer slot")
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
}

// TestRevokedAgentDisplay rejects revoked credentials before advancing or forwarding frames.
func TestRevokedAgentDisplay(t *testing.T) {
	for _, mode := range []string{"rotate", "remove", "unavailable"} {
		for _, direction := range []string{"receive", "send"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
				old := s.sessions["display"]
				relay := newDisplayRelay("display", strings.Repeat("a", 32), old)
				s.displayRelays[relay.streamID] = relay
				var err error
				switch mode {
				case "rotate":
					err = s.store.PutAgent(context.Background(), "display", strings.Repeat("cd", 32), "10.99.0.2", true, time.Now())
				case "remove":
					err = s.store.RemoveAgent(context.Background(), "display")
				case "unavailable":
					err = s.store.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				m := protocol.Display{Protocol: protocol.Version, AgentID: "display", SessionID: old.id, Sequence: 1, StreamID: relay.streamID, Action: "data", Data: []byte{1}, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
				m.Signature, err = protocol.SignDisplay(m, old.keys[keyderivation.TransportDisplay])
				if err != nil {
					t.Fatal(err)
				}
				if direction == "send" {
					if err := s.sendDisplayFrame(relay, "open", nil); err == nil {
						t.Fatal("sent to revoked agent")
					}
				} else if err := s.handleDisplayFrame("display", mustJSON(t, m)); err == nil || err.Error() != "agent session unavailable" {
					t.Errorf("revoked display after %s: error=%v sequence=%d queued=%d", mode, err, old.lastReceived, len(relay.frames))
				}
				if old.lastReceived != 0 || old.nextSend != 0 || len(relay.frames) != 0 {
					t.Fatal("revoked frame mutated stream state")
				}
				select {
				case <-relay.done:
				default:
					t.Fatal("revoked relay retained viewer slot")
				}
				if err := s.sendDisplayFrame(relay, "open", nil); err == nil {
					t.Fatal("sent command to revoked agent")
				}
			})
		}
	}
}

// TestDisplayStreamIdleDeadlineAndReplacement verifies idle capture survives ordinary HTTP write timeouts.
func TestDisplayStreamIdleDeadlineAndReplacement(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"agent": ""})
	handler, token := testAPI(t, server)
	opened := displayTestReplies(t, server, "open")
	closed := make(chan struct{}, 2)
	host := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { closed <- struct{}{} }()
		handler.ServeHTTP(w, r)
	}))
	host.Config.WriteTimeout = 50 * time.Millisecond
	host.Start()
	defer host.Close()
	request, err := http.NewRequest(http.MethodGet, host.URL+"/api/v1/agents/agent/display/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := host.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("status=%d headers=%v", response.StatusCode, response.Header)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("stream may be cached or buffered")
	}
	relay := <-opened
	busy, err := host.Client().Do(request.Clone(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	busy.Body.Close()
	if busy.StatusCode != http.StatusConflict {
		t.Fatalf("concurrent viewer status=%d", busy.StatusCode)
	}
	<-closed
	time.Sleep(100 * time.Millisecond)
	relay.frames <- []byte{1}
	var frame [5]byte
	if _, err := io.ReadFull(response.Body, frame[:]); err != nil {
		t.Fatal(err)
	}
	if frame != [5]byte{0, 0, 0, 1, 1} {
		t.Fatalf("frame=%v", frame)
	}
	relay.control <- protocol.Display{Action: "error", Error: "capture ended"}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("failed capture retained its HTTP handler")
	}
	if len(server.displayRelays) != 0 {
		t.Fatal("viewer slot retained after capture failure")
	}
	if !server.installDisplayRelay(&displayRelay{agentID: "agent", streamID: "replacement"}) {
		t.Fatal("replacement viewer rejected")
	}
}

// TestDisplayStreamAccessPolicy verifies the route uses ordinary bearer and agent-scope checks.
func TestDisplayStreamAccessPolicy(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"agent": "", "other": ""})
	_, token, err := server.createServiceAccount(context.Background(), serviceAccountInput{Name: "viewer", Roles: []Role{RoleViewer}, Agents: []string{"other"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		method, token string
		status        int
	}{
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodGet, token, http.StatusForbidden},
		{http.MethodPost, token, http.StatusMethodNotAllowed},
		{http.MethodDelete, token, http.StatusMethodNotAllowed},
	} {
		request := httptest.NewRequest(scenario.method, "/api/v1/agents/agent/display/stream", nil)
		if scenario.token != "" {
			request.Header.Set("Authorization", "Bearer "+scenario.token)
		}
		response := httptest.NewRecorder()
		server.controllerHandler().ServeHTTP(response, request)
		if response.Code != scenario.status {
			t.Fatalf("%s status=%d want=%d", scenario.method, response.Code, scenario.status)
		}
	}
}

// TestSlowViewerReceivesNewestFrame keeps a viewer that writes more slowly than
// the agent captures connected, replacing frames it has not written yet, while
// capture control messages still reach the stream.
func TestSlowViewerReceivesNewestFrame(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	session := server.sessions["display"]
	relay := newDisplayRelay("display", strings.Repeat("c", 32), session)
	if !server.installDisplayRelay(relay) {
		t.Fatal("relay was not installed")
	}
	send := func(sequence uint64, action string, data []byte) {
		t.Helper()
		message := protocol.Display{Protocol: protocol.Version, SessionID: session.id, Sequence: sequence, AgentID: "display",
			StreamID: relay.streamID, Action: action, Data: data, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		var err error
		if message.Signature, err = protocol.SignDisplay(message, session.keys[keyderivation.TransportDisplay]); err != nil {
			t.Fatal(err)
		}
		if err := server.handleDisplayFrame("display", mustJSON(t, message)); err != nil {
			t.Fatal(err)
		}
	}
	for width := 1; width <= 3; width++ {
		var frame bytes.Buffer
		if err := jpeg.Encode(&frame, image.NewGray(image.Rect(0, 0, width, 1)), nil); err != nil {
			t.Fatal(err)
		}
		send(uint64(width), "data", frame.Bytes())
	}
	select {
	case <-relay.done:
		t.Fatal("a slow viewer lost its stream")
	default:
	}
	geometry, err := jpeg.DecodeConfig(bytes.NewReader(<-relay.frames))
	if err != nil || geometry.Width != 3 {
		t.Fatalf("pending frame width=%d error=%v, want the newest frame", geometry.Width, err)
	}
	send(4, "close", nil)
	if message := <-relay.control; message.Action != "close" {
		t.Fatalf("control message = %+v", message)
	}
}
