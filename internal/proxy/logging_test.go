// File purpose: Verifies concise proxy request summaries and their privacy boundary.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

// TestProxyRequestSummaryFields verifies the normal logger receives one bounded field set.
func TestProxyRequestSummaryFields(t *testing.T) {
	output := captureProxyTestLogs(t)
	proxy := &Proxy{verbose: true}
	request := &proxyRequest{
		id: 474, started: time.Now().Add(-3 * time.Millisecond), outcome: "authorization_denied",
		agentID: "claimed-agent", token: "secret-token", loggedAgentID: "display-001",
		destinationHost: "www.example.com", destinationPort: "443", protocol: "https",
		bytesToDestination: 123, bytesToClient: 456,
	}
	proxy.logRequestSummary(request)
	logged := output.String()
	for _, required := range []string{
		`msg="proxy request"`, "request_id=474", "outcome=authorization_denied",
		"agent_id=display-001", "destination_host=www.example.com", "destination_port=443",
		"protocol=https", "bytes_to_destination=123", "bytes_to_client=456", "duration_ms=",
	} {
		if !strings.Contains(logged, required) {
			t.Fatalf("proxy summary missing %q: %s", required, logged)
		}
	}
	for _, forbidden := range []string{"claimed-agent", "secret-token", "source_address", "method=", "url="} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("proxy summary contains forbidden value %q: %s", forbidden, logged)
		}
	}
	if strings.Count(logged, "\n") != 1 {
		t.Fatalf("proxy summary record count = %d, want 1: %s", strings.Count(logged, "\n"), logged)
	}
}

// TestProxyRequestSummaryOutcomeVocabulary verifies every handler outcome remains observable.
func TestProxyRequestSummaryOutcomeVocabulary(t *testing.T) {
	for _, outcome := range []string{
		"capacity_rejected", "authentication_required", "authorization_denied", "invalid_target",
		"authorization_unavailable", "upstream_failed", "stream_failed", "tunnel_failed", "completed",
	} {
		t.Run(outcome, func(t *testing.T) {
			output := captureProxyTestLogs(t)
			proxy := &Proxy{verbose: true}
			proxy.logRequestSummary(&proxyRequest{id: 1, started: time.Now(), outcome: outcome})
			if got := output.String(); strings.Count(got, `msg="proxy request"`) != 1 || !strings.Contains(got, "outcome="+outcome) {
				t.Fatalf("summary for %s = %q", outcome, got)
			}
		})
	}
}

// TestMissingCredentialsProducePrivateVerboseSummary verifies early rejection logs no request data.
func TestMissingCredentialsProducePrivateVerboseSummary(t *testing.T) {
	output := captureProxyTestLogs(t)
	proxy := &Proxy{verbose: true}
	request := httptest.NewRequest(http.MethodGet, "http://example.net/private?q=secret", nil)
	request.RemoteAddr = "192.0.2.10:12345"
	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request)
	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", recorder.Code)
	}
	logged := output.String()
	if strings.Count(logged, `msg="proxy request"`) != 1 || !strings.Contains(logged, "outcome=authentication_required") {
		t.Fatalf("missing-credential summary = %q", logged)
	}
	for _, forbidden := range []string{"example.net", "private", "secret", "192.0.2.10", "agent_id", "destination_host"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("early rejection summary contains %q: %s", forbidden, logged)
		}
	}
}

// TestDebugLogsOmitClaimedIdentity keeps the privacy boundary in debug mode:
// a client-claimed agent ID reaches the logs only after the controller
// authenticates it, and rejected credentials never do.
func TestDebugLogsOmitClaimedIdentity(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.AuthorizeResponse{Authenticated: false})
	}))
	t.Cleanup(backend.Close)
	var proxyConfig Config
	proxyConfig.Proxy.BackendURL = backend.URL
	output := captureProxyTestLogs(t)
	proxy := &Proxy{config: proxyConfig, backendClient: backend.Client(), internalToken: "configured", debug: true}
	request := httptest.NewRequest(http.MethodGet, "http://example.net/content", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("claimed-display:" + strings.Repeat("c", 64)))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request)
	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("rejected credential status = %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	logged := output.String()
	if !strings.Contains(logged, "outcome=authentication_required") {
		t.Fatalf("debug output has no request summary: %s", logged)
	}
	if strings.Contains(logged, "claimed-display") {
		t.Fatalf("debug output contains the unauthenticated agent ID: %s", logged)
	}
}
