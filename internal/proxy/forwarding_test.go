// File purpose: Verifies that incomplete upstream responses remain failures for proxy clients and release capacity.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestHTTPStreamFailureAbortsResponse prevents a truncated chunked response
// from acquiring a successful end-of-body marker at the proxy boundary. The
// abort must still release the fleet slot, the display slot and the lease.
func TestHTTPStreamFailureAbortsResponse(t *testing.T) {
	const partial = "incomplete upstream content"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, partial)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(origin.Close)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
	}))
	t.Cleanup(backend.Close)
	var cfg Config
	cfg.Proxy.BackendURL = backend.URL
	p := &Proxy{config: cfg, backendClient: backend.Client(), internalToken: "internal", proxyClient: testOriginClient(t, origin),
		connections: make(chan struct{}, 1), agentLimit: 1}
	proxyServer := httptest.NewServer(http.HandlerFunc(p.handleProxy))
	t.Cleanup(proxyServer.Close)
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	t.Cleanup(client.CloseIdleConnections)
	credentials := "Basic " + base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("a", 64)))
	// With one slot of each kind, the second request is admitted only if the
	// first aborted stream released them before the client saw the abort.
	for attempt := 1; attempt <= 2; attempt++ {
		request, err := http.NewRequest(http.MethodGet, "http://content.example/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Proxy-Authorization", credentials)
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || string(body) != partial {
			t.Fatalf("attempt %d: status=%d body=%q, want forwarded prefix %q", attempt, response.StatusCode, body, partial)
		}
		if readErr == nil {
			t.Fatalf("attempt %d: truncated upstream stream appeared complete to the downstream client", attempt)
		}
	}
	p.leaseMu.Lock()
	leases := len(p.leases)
	p.leaseMu.Unlock()
	p.agentMu.Lock()
	displaySlots := len(p.agentConnections)
	p.agentMu.Unlock()
	if leases != 0 || displaySlots != 0 || len(p.connections) != 0 {
		t.Fatalf("aborted streams retained leases=%d display slots=%d fleet slots=%d", leases, displaySlots, len(p.connections))
	}
}
