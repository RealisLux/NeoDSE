// File purpose: Exercises the real agent, controller, transport, and Unix IPC boundary together.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/agent"
	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/transport"
)

// agentUIFixture implements only the renderer's IPC boundary; GTK and browser
// confinement remain covered by the native and installed-host harnesses.
type agentUIFixture struct {
	path         string
	mu           sync.Mutex
	mode         string
	urls         []string
	proxyToken   string
	credentials  int
	updates      int
	failPlaylist atomic.Bool
	stop         func()
}

// newAgentUIFixture starts an isolated renderer fixture on a temporary socket.
func newAgentUIFixture(t *testing.T) *agentUIFixture {
	t.Helper()
	return newAgentUIFixtureAt(t, filepath.Join(t.TempDir(), "ui.sock"))
}

// newAgentUIFixtureAt can replace a renderer at its configured Unix socket path.
func newAgentUIFixtureAt(t *testing.T, path string) *agentUIFixture {
	t.Helper()
	ui := &agentUIFixture{path: path, mode: "waiting"}
	listener, err := net.Listen("unix", ui.path)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				data, err := io.ReadAll(io.LimitReader(conn, (1<<20)+1))
				if err != nil || len(data) > 1<<20 || !bytes.HasSuffix(data, []byte("\n")) {
					t.Error("agent sent invalid IPC framing")
					return
				}
				var request struct {
					Command string   `json:"cmd"`
					Token   string   `json:"token"`
					URLs    []string `json:"urls"`
				}
				if err := json.Unmarshal(data, &request); err != nil {
					t.Error("agent sent invalid IPC JSON")
					return
				}
				response := map[string]string{"status": "accepted"}
				switch request.Command {
				case "proxy_auth":
					ui.mu.Lock()
					ui.proxyToken = request.Token
					ui.credentials++
					ui.mu.Unlock()
				case "playlist", "default":
					if request.Command == "playlist" && ui.failPlaylist.Swap(false) {
						response = map[string]string{"status": "failed", "error": "simulated renderer failure"}
						break
					}
					ui.mu.Lock()
					ui.mode, ui.urls = request.Command, request.URLs
					ui.updates++
					ui.mu.Unlock()
				case "reload":
					ui.mu.Lock()
					ui.updates++
					ui.mu.Unlock()
				}
				if err := json.NewEncoder(conn).Encode(response); err != nil {
					t.Error(err)
				}
			}()
		}
	})
	var stopOnce sync.Once
	ui.stop = func() { stopOnce.Do(func() { _ = listener.Close(); workers.Wait() }) }
	t.Cleanup(ui.stop)
	return ui
}

// displaying reports whether the fixture currently renders exactly one URL.
func (ui *agentUIFixture) displaying(url string) bool {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	return ui.mode == "playlist" && len(ui.urls) == 1 && ui.urls[0] == url
}

// TestRealAgentIntegration covers authenticated application, receipt semantics,
// failed application, reconnect, restart, and joined shutdown.
func TestRealAgentIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	secret := strings.Repeat("cd", 32)
	controller := testServerWithAgents(t, Config{Server: config.ServerSettings{TransportURL: "ws://" + address, TransportPSK: secret}}, map[string]string{"real-display": ""})
	controller.clearSessions()
	path := filepath.Join(t.TempDir(), "transport.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("transport:\n  listen: %s\n  controller_psk: %s\n", address, secret)), 0o600); err != nil {
		t.Fatal(err)
	}
	transportDone := make(chan error, 1)
	go func() { transportDone <- transport.Run(ctx, []string{"--config", path}, "integration") }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-transportDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("transport did not join shutdown")
		}
	})
	controller.startBackgroundServices(ctx)
	t.Cleanup(func() { cancel(); controller.workers.Wait() })
	handler, token := testAPI(t, controller)
	api := httptest.NewTLSServer(handler)
	t.Cleanup(api.Close)
	client := api.Client()
	client.Timeout = 10 * time.Second
	t.Cleanup(client.CloseIdleConnections)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	t.Cleanup(proxy.Close)
	ui := newAgentUIFixture(t)
	agentPath := filepath.Join(t.TempDir(), "agent.yaml")
	agentConfig := []byte(fmt.Sprintf("agent:\n  id: real-display\n  psk: %s\n  wireguard_interface: wg0\n  ui_socket: %s\ntransport:\n  url: ws://%s\nproxy:\n  url: %s\ncec:\n  enabled: false\n", strings.Repeat("ab", 32), ui.path, address, proxy.URL))
	if err := os.WriteFile(agentPath, agentConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	startAgent := func() func() {
		agentContext, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- agent.Run(agentContext, []string{"--config", agentPath}, "integration-agent") }()
		var once sync.Once
		join := func() {
			once.Do(func() {
				stop()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					stacks := make([]byte, 1<<20)
					t.Errorf("agent did not join shutdown\n%s", stacks[:runtime.Stack(stacks, true)])
				}
			})
		}
		t.Cleanup(join)
		return join
	}
	stopAgent := startAgent()
	failures := make(chan error)
	fleetWait(t, failures, 15*time.Second, func() bool { return controller.sessionFor("real-display") != nil })
	fleetWait(t, failures, 15*time.Second, func() bool {
		statuses, err := controller.store.AgentStatuses(ctx)
		return err == nil && len(statuses) == 1 && statuses[0].Version == "integration-agent" && !statuses[0].LastSeen.IsZero()
	})
	assertProxySession := func() {
		t.Helper()
		fleetWait(t, failures, 15*time.Second, func() bool {
			session := controller.sessionFor("real-display")
			ui.mu.Lock()
			token := ui.proxyToken
			ui.mu.Unlock()
			return session != nil && token != "" && token == hex.EncodeToString(session.keys[keyderivation.ProxyClient])
		})
	}
	assertProxySession()
	const route = "/api/v1/agents/real-display"
	const firstURL = "https://display.example/first"
	event := fleetRequest(t, client, api.URL, token, "PUT", route+"/playlist", `{"urls":["`+firstURL+`"]}`)
	fleetWaitEvent(t, controller, failures, event, 1, "accepted")
	if !ui.displaying(firstURL) {
		t.Fatal("accepted desired state did not reach renderer IPC")
	}
	event = fleetRequest(t, client, api.URL, token, "POST", route+"/banner", `{"message":"integration","severity":"info","duration_seconds":1}`)
	fleetWaitEvent(t, controller, failures, event, 1, "completed")
	ui.failPlaylist.Store(true)
	const latestURL = "https://display.example/latest"
	event = fleetRequest(t, client, api.URL, token, "PUT", route+"/playlist", `{"urls":["`+latestURL+`"]}`)
	fleetWaitEvent(t, controller, failures, event, 1, "failed")
	if !ui.displaying(firstURL) {
		t.Fatal("failed application changed visible content")
	}
	// Failed application must recover without an operator forcing a reconnect.
	fleetWait(t, failures, 15*time.Second, func() bool { return ui.displaying(latestURL) })
	// Each reconnect installs a fresh proxy credential. The page reload that
	// follows reconciliation is deliberately spread over several seconds.
	// A forced reset must not race the handshake of the session it replaces: a
	// session reset before reconciliation publishes is rejected without progress,
	// and the agent doubles its reconnect delay each time. Slow storage widens
	// that window, so wait until the controller has sent the reconciled state.
	reconciled := func() bool {
		session := controller.sessionFor("real-display")
		if session == nil {
			return false
		}
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.nextSend > 0
	}
	for range 6 {
		fleetWait(t, failures, 15*time.Second, reconciled)
		ui.mu.Lock()
		before := ui.credentials
		previousToken := ui.proxyToken
		ui.mu.Unlock()
		previous := controller.sessionFor("real-display")
		controller.resetAgentConnection("real-display", previous)
		fleetWait(t, failures, 15*time.Second, func() bool {
			ui.mu.Lock()
			updated := ui.credentials > before
			ui.mu.Unlock()
			current := controller.sessionFor("real-display")
			return updated && current != nil && current != previous
		})
		assertProxySession()
		ui.mu.Lock()
		unchangedToken := ui.proxyToken == previousToken
		ui.mu.Unlock()
		if unchangedToken {
			t.Fatal("reconnect reused the previous proxy session credential")
		}
	}
	// A new renderer has no playlist even though the agent still remembers its revision.
	ui.stop()
	ui = newAgentUIFixtureAt(t, ui.path)
	// Renderer replacement is detected on the ten-second heartbeat. Allow three
	// complete periods because package-local runs every Go package concurrently.
	fleetWait(t, failures, 30*time.Second, func() bool { return ui.displaying(latestURL) })
	assertProxySession()
	stopAgent()
	ui.mu.Lock()
	ui.mode, ui.urls = "waiting", nil
	ui.mu.Unlock()
	startAgent()
	fleetWait(t, failures, 15*time.Second, func() bool { return ui.displaying(latestURL) })
	assertProxySession()
	if contents, err := os.ReadFile(agentPath); err != nil || !bytes.Equal(contents, agentConfig) {
		t.Fatal("routine agent operation modified enrollment configuration")
	}
}
