// File purpose: Verifies the dashboard route is safely served as a local application shell.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDashboardRoute verifies the operator console is available at the server root.
func TestDashboardRoute(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got != dashboardContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy = %q", got)
	}
	for _, value := range []string{"NeoDSE Control", "/dashboard/logo.png", "/dashboard/app.js", "token stays in this browser tab", "Log out", "Broadcast", "Broadcast mode", "Screen control", "Notifications", "Peripheral controller", "data-serial-command", "data-cec-badge", "data-cec-detail"} {
		if !strings.Contains(recorder.Body.String(), value) {
			t.Errorf("dashboard does not contain %q", value)
		}
	}
}

// TestDashboardLogoRoute verifies the embedded brand asset is served as a PNG.
func TestDashboardLogoRoute(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/logo.png", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", got)
	}
	if body := recorder.Body.Bytes(); len(body) < 8 || string(body[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("dashboard logo is not a PNG")
	}
}

// TestDashboardScriptRoute verifies the dashboard logic is a same-origin asset compatible with CSP.
func TestDashboardScriptRoute(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard/app.js", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	for _, path := range []string{"/dashboard/api.js", "/dashboard/events.js"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("missing module %s", path)
		}
	}
}

// TestDashboardRejectsOtherRoutesAndMethods verifies the dashboard does not capture unrelated paths.
func TestDashboardRejectsOtherRoutesAndMethods(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/", nil),
		httptest.NewRequest(http.MethodGet, "/unexpected", nil),
		httptest.NewRequest(http.MethodGet, "/dashboard/unexpected.js", nil),
	} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want %d", request.Method, request.URL.Path, recorder.Code, http.StatusNotFound)
		}
	}
}
