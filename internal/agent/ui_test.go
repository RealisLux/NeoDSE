// File purpose: Verifies strict UI IPC responses and request bounds.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
)

// TestUIRequestCancellation interrupts an unresponsive renderer during shutdown.
func TestUIRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := &Agent{ctx: ctx}
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	listener, err := net.Listen("unix", agent.config.Agent.UISocket)
	if err != nil {
		t.Fatal(err)
	}
	requestRead := make(chan struct{})
	peerDone := make(chan struct{})
	releasePeer := make(chan struct{})
	defer func() { close(releasePeer); _ = listener.Close(); <-peerDone }()
	go func() {
		defer close(peerDone)
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, peer)
		close(requestRead)
		// Keep the renderer unresponsive even after the agent is cancelled.
		<-releasePeer
	}()
	requestDone := make(chan error, 1)
	go func() {
		_, err := agent.sendUIRequest(uiDefaultRequest{Command: "default"})
		requestDone <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(3 * time.Second):
		t.Fatal("renderer did not receive the request")
	}
	cancel()
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("cancelled UI request returned an acknowledgement")
		}
	case <-time.After(time.Second):
		t.Fatal("agent cancellation did not interrupt the renderer request")
	}
	// A new status update after cancellation must not dial the renderer again.
	if _, err := agent.sendUIRequest(uiDefaultRequest{Command: "default"}); err == nil {
		t.Fatal("cancelled agent started a new renderer request")
	}
}

// TestInitializeUIConnectionStates separates local renderer readiness from
// session authentication while retaining local retries and late-UI credentials.
func TestInitializeUIConnectionStates(t *testing.T) {
	for _, scenario := range []struct {
		name                        string
		connected, previouslyOnline bool
		rejectProxyOnce             bool
		wantStage                   string
	}{
		{"offline startup", false, false, false, "connecting_control"},
		{"renderer after connection", true, true, false, "waiting_for_playlist"},
		{"offline after disconnect", false, true, false, "connection_lost"},
		{"retry local failure", false, false, true, "connecting_control"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			agent := &Agent{}
			if scenario.connected {
				agent, _ = newSessionAgent(t)
			}
			agent.config.Agent.ID = "display-01"
			agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
			agent.config.Proxy.URL = "http://192.0.2.1:3128"
			agent.proxyRelayURL = "http://127.0.0.1:33407"
			agent.transportConnected.Store(scenario.connected)
			agent.transportConnectedOnce.Store(scenario.previouslyOnline)
			listener, err := net.Listen("unix", agent.config.Agent.UISocket)
			if err != nil {
				t.Fatal(err)
			}
			requests := make(chan map[string]string, 32)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				reject := scenario.rejectProxyOnce
				for {
					peer, err := listener.Accept()
					if err != nil {
						return
					}
					_ = peer.SetDeadline(time.Now().Add(time.Second))
					var request map[string]string
					if err := json.NewDecoder(peer).Decode(&request); err != nil {
						t.Errorf("decode renderer request: %v", err)
						_ = peer.Close()
						return
					}
					requests <- request
					response := uiResponse{Status: "accepted"}
					if reject && request["cmd"] == "proxy_config" {
						reject = false
						response = uiResponse{Status: "rejected", Error: "fixture proxy setup failure"}
					}
					if err := json.NewEncoder(peer).Encode(response); err != nil {
						t.Errorf("acknowledge renderer request: %v", err)
					}
					_ = peer.Close()
				}
			}()
			t.Cleanup(func() { _ = listener.Close(); <-stopped })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			agent.initializeUI(ctx)
			if ctx.Err() != nil {
				t.Fatal("local initialization kept retrying while waiting for transport authentication")
			}
			want := []string{"status:initializing", "proxy_config"}
			if scenario.rejectProxyOnce {
				want = append(want, "status:initializing", "proxy_config")
			}
			if scenario.connected {
				want = append(want, "proxy_auth")
			} else if err := agent.sendProxyAuthToUI(); err == nil {
				t.Fatal("offline initialization bypassed the proxy credential requirement")
			}
			want = append(want, "status:"+scenario.wantStage)
			for _, expected := range want {
				select {
				case request := <-requests:
					actual := request["cmd"]
					if actual == "status" {
						actual += ":" + request["stage"]
					}
					if actual != expected {
						t.Fatalf("UI command=%q, want=%q", actual, expected)
					}
					if actual == "proxy_config" && request["url"] != agent.proxyRelayURL {
						t.Fatal("UI did not receive the local proxy relay")
					}
					if actual == "proxy_auth" && (request["agent_id"] != agent.config.Agent.ID || len(request["token"]) != 64) {
						t.Fatal("connected renderer did not receive session credentials")
					}
				default:
					t.Fatalf("missing UI command %q", expected)
				}
			}
			if len(requests) != 0 {
				t.Fatal("initialization repeated completed UI setup")
			}
		})
	}
}

// TestPlaylistUIRequestExcludesControllerProxyPolicy keeps controller policy out of renderer IPC.
func TestPlaylistUIRequestExcludesControllerProxyPolicy(t *testing.T) {
	payload, err := json.Marshal(uiPlaylistRequest{
		Command: "playlist",
		URLs:    []string{"https://example.test/display"},
	})
	if err != nil {
		t.Fatalf("marshal UI playlist request: %v", err)
	}
	const expected = `{"cmd":"playlist","urls":["https://example.test/display"]}`
	if string(payload) != expected {
		t.Fatalf("UI playlist request = %s, want %s", payload, expected)
	}
}

// TestReloadUIRequestHasNoMutablePayload keeps reconnect reloads narrowly scoped.
func TestReloadUIRequestHasNoMutablePayload(t *testing.T) {
	payload, err := json.Marshal(uiReloadRequest{Command: "reload"})
	if err != nil {
		t.Fatalf("marshal UI reload request: %v", err)
	}
	if string(payload) != `{"cmd":"reload"}` {
		t.Fatalf("UI reload request = %s", payload)
	}
}

// TestDecodeUIResponse verifies strict, bounded, single-value response decoding.
func TestDecodeUIResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		limit   int64
		wantErr bool
	}{
		{name: "valid", input: `{"status":"accepted"}`, limit: 64},
		{name: "unknown field", input: `{"status":"accepted","extra":true}`, limit: 64, wantErr: true},
		{name: "multiple values", input: `{"status":"accepted"}{}`, limit: 64, wantErr: true},
		{name: "oversized", input: `{"status":"accepted"}`, limit: 8, wantErr: true},
		{name: "empty", input: "", limit: 64, wantErr: true},
		{name: "invalid limit", input: `{}`, limit: 0, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response, err := decodeUIResponse(strings.NewReader(test.input), test.limit)
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeUIResponse() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && response.Status != "accepted" {
				t.Fatalf("status = %q, want accepted", response.Status)
			}
		})
	}
}

// TestNotifyBootstrapUIReportsUnavailableRenderer verifies UI failures remain observable to bootstrap.
func TestNotifyBootstrapUIReportsUnavailableRenderer(t *testing.T) {
	cfg := config.Agent{}
	cfg.Agent.ID = "display-001"
	cfg.Agent.UISocket = filepath.Join(t.TempDir(), "missing.sock")
	if err := notifyBootstrapUI(cfg); err == nil {
		t.Fatal("unavailable renderer was reported as refreshed")
	}
}
