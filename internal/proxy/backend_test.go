// File purpose: Verifies that authorization credentials stay on the configured controller endpoint.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

// TestProxyForwardsCredentialIdentityToAuthority exercises the public handler,
// so a claimed identity is sent for authentication before it becomes loggable.
func TestProxyForwardsCredentialIdentityToAuthority(t *testing.T) {
	const agentID = "display-01"
	token := strings.Repeat("a", 64)
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var input wire.AuthorizeRequest
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.AgentID != agentID || input.Token != token ||
					input.Host != "content.example" || input.Port != "443" || input.Scheme != "https" {
					t.Errorf("authorization did not receive the complete credential and target")
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"authenticated":true,"allowed":false}`))
			}))
			defer backend.Close()
			p := &Proxy{internalToken: "internal-test-credential", backendClient: backend.Client()}
			p.config.Proxy.BackendURL = backend.URL
			target := "https://content.example/page"
			if method == http.MethodConnect {
				target = "content.example:443"
			}
			request := httptest.NewRequest(method, target, nil)
			request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(agentID+":"+token)))
			response := httptest.NewRecorder()
			p.handleProxy(response, request)
			if response.Code != http.StatusForbidden || calls.Load() != 1 {
				t.Fatalf("status=%d authorization requests=%d; want an authenticated policy denial", response.Code, calls.Load())
			}
		})
	}
}

// TestBackendAuthorizationRejectsRedirects prevents credential disclosure and decisions from another endpoint.
func TestBackendAuthorizationRejectsRedirects(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var redirected atomic.Int32
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
			}))
			defer other.Close()
			controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-NeoDSE-Proxy-Token") != "internal-test-credential" {
					t.Error("controller request lacks its internal credential")
				}
				http.Redirect(w, r, other.URL, status)
			}))
			defer controller.Close()
			roots := x509.NewCertPool()
			roots.AddCert(controller.Certificate())
			roots.AddCert(other.Certificate())
			p := &Proxy{internalToken: "internal-test-credential", backendClient: newBackendClient(roots)}
			p.config.Proxy.BackendURL = controller.URL
			defer p.backendClient.CloseIdleConnections()
			decision := p.authorize(context.Background(), 1, "display", "client-test-credential", "example.com", "443", "https")
			if decision != authorizationUnavailable || redirected.Load() != 0 {
				t.Fatalf("redirect decision=%d requests_to_other_endpoint=%d; want unavailable and zero requests", decision, redirected.Load())
			}
		})
	}
}
