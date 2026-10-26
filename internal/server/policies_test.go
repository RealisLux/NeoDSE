// File purpose: Verifies canonical proxy targets and fail-closed backend authorization responses.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/destination"
	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/proxyauth"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// TestCanonicalProxyTarget verifies canonical proxy target.
func TestCanonicalProxyTarget(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		host   string
		port   string
		want   string
		valid  bool
	}{
		{name: "dns", scheme: "HTTPS", host: "Example.NET.", port: "443", want: "https://example.net:443", valid: true},
		{name: "ipv4 mapped", scheme: "http", host: "::ffff:192.0.2.1", port: "80"},
		{name: "ipv6", scheme: "https", host: "2001:db8::1", port: "443"},
		{name: "empty label", scheme: "https", host: "a..example", port: "443"},
		{name: "leading hyphen", scheme: "https", host: "-a.example", port: "443"},
		{name: "trailing hyphen", scheme: "https", host: "a-.example", port: "443"},
		{name: "non ascii", scheme: "https", host: "café.example", port: "443"},
		{name: "invalid port", scheme: "https", host: "example.net", port: "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := destination.Canonical(test.scheme, test.host, test.port)
			if test.valid && (err != nil || got != test.want) {
				t.Fatalf("destination.Canonical() = %q, %v; want %q", got, err, test.want)
			}
			if !test.valid && err == nil {
				t.Fatalf("destination.Canonical() accepted %q", test.host)
			}
		})
	}
}

// TestProxyAuthorizeHandlerRejectsMalformedOrUnauthorizedRequests verifies proxy authorize handler rejects malformed or unauthorized requests.
func TestProxyAuthorizeHandlerRejectsMalformedOrUnauthorizedRequests(t *testing.T) {
	const agentID = "display-01"
	psk := strings.Repeat("ab", 32)
	internalPSK := strings.Repeat("cd", 32)
	var cfg Config
	cfg.Server.ProxyInternalPSK = internalPSK
	s := testServerWithAgents(t, cfg, map[string]string{agentID: psk})
	internalToken, err := proxyauth.InternalToken(internalPSK)
	if err != nil {
		t.Fatal(err)
	}
	// The agent presents its session's proxy key, as the handler expects.
	clientToken := hex.EncodeToString(s.sessions[agentID].keys[keyderivation.ProxyClient])
	validBody := `{"agent_id":"display-01","token":"` + clientToken + `","host":"example.net","port":"443","scheme":"https"}`
	tests := []struct {
		name, method, contentType, internalToken, body string
		want                                           int
	}{
		{name: "method", method: http.MethodGet, contentType: "application/json", internalToken: internalToken, body: validBody, want: http.StatusMethodNotAllowed},
		{name: "internal credential", method: http.MethodPost, contentType: "application/json", internalToken: "invalid", body: validBody, want: http.StatusUnauthorized},
		{name: "content type", method: http.MethodPost, contentType: "text/plain", internalToken: internalToken, body: validBody, want: http.StatusUnsupportedMediaType},
		{name: "malformed", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: `{`, want: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: `{"agent_id":"display-01","token":"x","host":"example.net","port":"443","scheme":"https","extra":true}`, want: http.StatusBadRequest},
		{name: "multiple values", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: validBody + `{}`, want: http.StatusBadRequest},
		{name: "missing field", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: `{"agent_id":"display-01"}`, want: http.StatusBadRequest},
		{name: "scheme", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: `{"agent_id":"display-01","token":"x","host":"example.net","port":"443","scheme":"ftp"}`, want: http.StatusBadRequest},
		{name: "target", method: http.MethodPost, contentType: "application/json", internalToken: internalToken, body: `{"agent_id":"display-01","token":"` + clientToken + `","host":"example.net","port":"0","scheme":"https"}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/internal/v1/proxy/authorize", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("X-NeoDSE-Proxy-Token", test.internalToken)
			recorder := httptest.NewRecorder()
			s.proxyAuthorizeHandler(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

// TestProxyAuthorizeHandlerReturnsExplicitAuthenticationState verifies proxy authorize handler returns explicit authentication state.
func TestProxyAuthorizeHandlerReturnsExplicitAuthenticationState(t *testing.T) {
	const agentID = "display-01"
	psk := strings.Repeat("ab", 32)
	internalPSK := strings.Repeat("cd", 32)
	var cfg Config
	cfg.Server.ProxyInternalPSK = internalPSK
	s := testServerWithAgents(t, cfg, map[string]string{agentID: psk})
	internalToken, _ := proxyauth.InternalToken(internalPSK)
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/proxy/authorize", strings.NewReader(`{"agent_id":"missing","token":"invalid","host":"example.net","port":"443","scheme":"https"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-NeoDSE-Proxy-Token", internalToken)
	recorder := httptest.NewRecorder()
	s.proxyAuthorizeHandler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var response wire.AuthorizeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Authenticated || response.Allowed {
		t.Fatalf("response = %+v", response)
	}
}

// TestProxySessionAuthority rejects old credentials after disconnect, replacement, or durable revocation.
func TestProxySessionAuthority(t *testing.T) {
	for _, change := range []string{"disconnect", "reconnect", "rotate", "delete", "policy", "unavailable"} {
		t.Run(change, func(t *testing.T) {
			const id = "display-01"
			var cfg Config
			cfg.Server.ProxyInternalPSK = strings.Repeat("cd", 32)
			s := testServerWithAgents(t, cfg, map[string]string{id: ""})
			ctx := context.Background()
			content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://example.net"}}
			if _, err := s.store.UpdateDesiredStates(ctx, "policy", "test", []string{id}, store.DesiredChange{Content: &content}, time.Now()); err != nil {
				t.Fatal(err)
			}
			old := s.sessions[id]
			token := hex.EncodeToString(old.keys[keyderivation.ProxyClient])
			internalToken, _ := proxyauth.InternalToken(cfg.Server.ProxyInternalPSK)
			check := func(token string) wire.AuthorizeResponse {
				t.Helper()
				body, _ := json.Marshal(wire.AuthorizeRequest{AgentID: id, Token: token, Host: "example.net", Port: "443", Scheme: "https"})
				r := httptest.NewRequest(http.MethodPost, "/internal/v1/proxy/authorize", strings.NewReader(string(body)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-NeoDSE-Proxy-Token", internalToken)
				w := httptest.NewRecorder()
				s.proxyAuthorizeHandler(w, r)
				var result wire.AuthorizeResponse
				if w.Code != http.StatusOK {
					t.Fatalf("unexpected status %d", w.Code)
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			if result := check(strings.Repeat("00", 32)); result.Authenticated || result.Allowed {
				t.Fatal("invalid session token accepted")
			}
			if result := check(token); !result.Authenticated || !result.Allowed {
				t.Fatalf("live session rejected: %+v", result)
			}
			switch change {
			case "disconnect":
				s.clearSession(id, old)
			case "reconnect":
				psk, _ := keyderivation.ParsePSK(strings.Repeat("ab", 32))
				keys, err := keyderivation.DeriveSessionKeys(psk, id, strings.Repeat("33", 32), strings.Repeat("44", 32))
				if err != nil {
					t.Fatal(err)
				}
				s.sessions[id] = &agentSession{id: "replacement", credential: old.credential, keys: keys}
			case "rotate":
				if err := s.store.PutAgent(ctx, id, strings.Repeat("ef", 32), "10.99.0.2", true, time.Now()); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := s.store.RemoveAgent(ctx, id); err != nil {
					t.Fatal(err)
				}
			case "policy":
				if _, err := s.revokeProxyPolicy(ctx, id); err != nil {
					t.Fatal(err)
				}
			case "unavailable":
				if err := s.store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result := check(token)
			if result.Allowed || result.Authenticated != (change == "policy") {
				t.Fatalf("old authority survived %s: %+v", change, result)
			}
			if change == "reconnect" {
				fresh := hex.EncodeToString(s.sessions[id].keys[keyderivation.ProxyClient])
				if result := check(fresh); !result.Authenticated || !result.Allowed {
					t.Fatalf("replacement session rejected: %+v", result)
				}
			}
		})
	}
}
