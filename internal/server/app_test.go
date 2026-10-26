// File purpose: Verifies server setup, API route registration, centralized errors, authorization, and typed state responses.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
	"go.yaml.in/yaml/v3"
)

// TestAPIDenialLogsRedactedOutcome verifies denied API outcomes use the shared logger.
func TestAPIDenialLogsRedactedOutcome(t *testing.T) {
	original := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	server := newServer(Config{}, "test")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/restart", nil)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, "request-1"))
	server.logAPIOutcome(request, "account-1", http.StatusForbidden)
	logged := output.String()
	for _, value := range []string{"API audit", "actor_id=account-1", "result=denied", "request_id=request-1", "status=403"} {
		if !strings.Contains(logged, value) {
			t.Fatalf("log = %q, want %q", logged, value)
		}
	}
}

// TestServiceAccountNameConflictsReturnConflict verifies duplicate creates and
// renames produce an actionable conflict response through the authenticated API.
func TestServiceAccountNameConflictsReturnConflict(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	handler, token := testAPI(t, server)
	input := serviceAccountInput{Name: "operator", Roles: []Role{RoleViewer}, AllAgents: true}
	if _, _, err := server.createServiceAccount(context.Background(), input, false); err != nil {
		t.Fatal(err)
	}
	input.Name = "second operator"
	second, _, err := server.createServiceAccount(context.Background(), input, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/service-accounts"},
		{http.MethodPut, "/api/v1/service-accounts/" + second.ID},
	} {
		request := httptest.NewRequest(operation.method, operation.path,
			strings.NewReader(`{"name":"operator","roles":["viewer"],"all_agents":true}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"conflict"`) {
			t.Fatalf("%s conflict status=%d body=%s", operation.method, response.Code, response.Body.String())
		}
	}
}

// TestServiceAccountNamesRejectNUL returns a client error before SQLite's
// NUL-terminated length checks can reject or truncate the apparent account name.
func TestServiceAccountNamesRejectNUL(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	handler, token := testAPI(t, server)
	account, _, err := server.createServiceAccount(context.Background(), serviceAccountInput{Name: "operator", Roles: []Role{RoleViewer}, AllAgents: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/service-accounts"},
		{http.MethodPut, "/api/v1/service-accounts/" + account.ID},
	} {
		for _, name := range []string{`\u0000operator`, `operator\u0000suffix`} {
			request := httptest.NewRequest(operation.method, operation.path,
				strings.NewReader(`{"name":"`+name+`","roles":["viewer"],"all_agents":true}`))
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s name=%s status=%d body=%s", operation.method, name, response.Code, response.Body.String())
			}
		}
	}
	stored, err := server.store.Account(context.Background(), account.ID)
	if err != nil || stored.Name != "operator" {
		t.Fatalf("rejected update changed the account: name=%q error=%v", stored.Name, err)
	}
}

// TestServiceAccountsReportAgentsAsArray keeps accounts without assigned agents
// within the OpenAPI contract, which requires an agents array, never null.
func TestServiceAccountsReportAgentsAsArray(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	handler, token := testAPI(t, server)
	call := func(method, path, body string) string {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK && response.Code != http.StatusCreated {
			t.Fatalf("%s %s status=%d", method, path, response.Code)
		}
		return response.Body.String()
	}
	body := `{"name":"content","roles":["content_manager"],"all_agents":true}`
	created := call(http.MethodPost, "/api/v1/service-accounts", body)
	var creation struct {
		ServiceAccount struct {
			ID string `json:"id"`
		} `json:"service_account"`
	}
	if err := json.Unmarshal([]byte(created), &creation); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/service-accounts/" + creation.ServiceAccount.ID
	for name, response := range map[string]string{
		"create": created,
		"list":   call(http.MethodGet, "/api/v1/service-accounts", ""),
		"get":    call(http.MethodGet, path, ""),
		"update": call(http.MethodPut, path, body),
	} {
		if strings.Contains(response, `"agents":null`) || !strings.Contains(response, `"agents":[]`) {
			t.Errorf("%s response does not report agents as an empty array", name)
		}
	}
}

// TestActiveAdministratorCannotRemoveItsOwnAccess keeps the signed-in
// administrator from disabling, demoting or setting an expiry on itself, while
// host-local recovery restores access when every administrator token is lost.
func TestActiveAdministratorCannotRemoveItsOwnAccess(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	handler, token := testAPI(t, server)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	var identity struct {
		ID string `json:"service_account_id"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/session", "").Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	for name, body := range map[string]string{
		"disable": `{"name":"test administrator","roles":["administrator"],"all_agents":true,"disabled":true}`,
		"demote":  `{"name":"test administrator","roles":["viewer"],"all_agents":true}`,
		"expire":  fmt.Sprintf(`{"name":"test administrator","roles":["administrator"],"all_agents":true,"expires_at":%q}`, expiry),
	} {
		if response := call(http.MethodPut, "/api/v1/service-accounts/"+identity.ID, body); response.Code != http.StatusConflict {
			t.Errorf("%s own account status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	if response := call(http.MethodPut, "/api/v1/service-accounts/"+identity.ID, `{"name":"renamed administrator","roles":["administrator"],"all_agents":true}`); response.Code != http.StatusOK {
		t.Fatalf("permitted self-update status=%d body=%s", response.Code, response.Body.String())
	}
	account, recovered, err := server.store.RestoreAdministrator(context.Background(), "renamed administrator", time.Now().UTC())
	if err != nil || account.ID != identity.ID {
		t.Fatalf("recovery account=%#v error=%v", account, err)
	}
	if response := call(http.MethodGet, "/api/v1/agents", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("token replaced by recovery still works: %d", response.Code)
	}
	token = recovered
	if response := call(http.MethodGet, "/api/v1/agents", ""); response.Code != http.StatusOK {
		t.Fatalf("recovered token status=%d", response.Code)
	}
}

// TestDefaultAuditRecordsMutationsAndReadDenials exercises middleware at the default log level.
func TestDefaultAuditRecordsMutationsAndReadDenials(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	_, token := testAPI(t, server)
	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	for _, item := range []struct {
		method        string
		status        int
		authenticated bool
	}{{"POST", 201, true}, {"GET", 403, true}, {"GET", 401, false}} {
		output.Reset()
		request := httptest.NewRequest(item.method, "/api/v1/test?secret=content-secret", strings.NewReader("content-secret"))
		request.Pattern = "/api/v1/test"
		if item.authenticated {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		server.authMiddleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(item.status) })(response, request)
		logged := output.String()
		if !strings.Contains(logged, "API audit") || !strings.Contains(logged, fmt.Sprintf("status=%d", item.status)) {
			t.Fatalf("missing default audit: %q", logged)
		}
		if strings.Contains(logged, token) || strings.Contains(logged, "content-secret") {
			t.Fatal("audit exposed credentials or content")
		}
	}
}

// TestUnauthenticatedAuditIsRateLimitedPerSource keeps requests without a valid
// token from flooding the journal while every source and suppression stays visible.
func TestUnauthenticatedAuditIsRateLimitedPerSource(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	request := func(source string) {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
		request.RemoteAddr = source + ":40000"
		request.Header.Set("Authorization", "Bearer nds_"+strings.Repeat("ab", 16)+"_"+strings.Repeat("cd", 32))
		server.authMiddleware(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated request reached its handler") })(httptest.NewRecorder(), request)
	}
	for range 3 {
		request("192.0.2.10")
	}
	request("192.0.2.11")
	if logged := output.String(); strings.Count(logged, "API audit") != 2 || !strings.Contains(logged, "source_address=192.0.2.11") {
		t.Fatalf("rate-limited audit = %q", logged)
	}
	output.Reset()
	now = now.Add(unauthenticatedAuditInterval)
	// Another source arriving first must not discard the pending count.
	request("192.0.2.11")
	request("192.0.2.10")
	if logged := output.String(); strings.Count(logged, "API audit") != 2 || !strings.Contains(logged, "suppressed=2") {
		t.Fatalf("next audit record did not report suppressed requests: %q", logged)
	}
}

// TestUnauthenticatedAuditTableEvictsOnlyWhenFull bounds tracked sources and
// admits a new source once older windows have expired.
func TestUnauthenticatedAuditTableEvictsOnlyWhenFull(t *testing.T) {
	server := testServerWithAgents(t, Config{}, nil)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	audit := func(source string) {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
		request.RemoteAddr = source + ":40000"
		server.logUnauthenticatedOutcome(request, http.StatusUnauthorized)
	}
	for index := range unauthenticatedAuditSources {
		audit(fmt.Sprintf("10.0.%d.%d", index/256, index%256))
	}
	output.Reset()
	audit("192.0.2.20")
	if output.Len() != 0 || len(server.authFailures) != unauthenticatedAuditSources {
		t.Fatalf("full audit table admitted a new source: %q", output.String())
	}
	now = now.Add(unauthenticatedAuditInterval)
	audit("192.0.2.20")
	if !strings.Contains(output.String(), "source_address=192.0.2.20") || len(server.authFailures) != 1 {
		t.Fatalf("expired windows were not evicted for a new source: %q", output.String())
	}
}

// TestServerListenAddressesAlwaysIncludesLoopback verifies custom API listeners do not disconnect the local proxy backend.
func TestServerListenAddressesAlwaysIncludesLoopback(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		want       []string
	}{
		{name: "default loopback", configured: "127.0.0.1:8443", want: []string{"127.0.0.1:8443"}},
		{name: "private interface", configured: "10.99.0.1:8443", want: []string{"10.99.0.1:8443", "127.0.0.1:8443"}},
		{name: "alternate loopback", configured: "127.0.0.2:9443", want: []string{"127.0.0.2:9443", "127.0.0.1:9443"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := serverListenAddresses(test.configured)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("serverListenAddresses(%q) = %v, want %v", test.configured, got, test.want)
			}
		})
	}
}

// TestServerDiagnosticLogLevels verifies server diagnostic log levels.
func TestServerDiagnosticLogLevels(t *testing.T) {
	var output bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(originalOutput)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})

	server := newServer(Config{}, "test")
	server.verbosef("verbose message")
	if output.Len() != 0 {
		t.Fatalf("info level emitted diagnostic output: %q", output.String())
	}
	server.verbose = true
	server.verbosef("verbose message")
	if got := output.String(); got != "verbose message\n" {
		t.Fatalf("verbose output = %q", got)
	}
	output.Reset()
	server.verbose = false
	server.debug = true
	server.verbosef("verbose message")
	if got := output.String(); got != "verbose message\n" {
		t.Fatalf("debug output = %q", got)
	}
}

// TestRunHelpDoesNotStartServer verifies run help does not start server.
func TestRunHelpDoesNotStartServer(t *testing.T) {
	if err := Run(context.Background(), []string{"-help"}, "test-version"); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Run(-help) error = %v, want flag.ErrHelp", err)
	}
}

// TestPrincipalContextRejectsUntypedValues verifies authorization accepts only middleware identities.
func TestPrincipalContextRejectsUntypedValues(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	untyped := request.WithContext(context.WithValue(request.Context(), authorizationContextKey{}, "*"))
	if _, ok := principalFor(untyped); ok {
		t.Fatal("untyped authorization context was accepted")
	}
	want := Principal{ServiceAccountID: "account-01", Roles: map[Role]bool{RoleViewer: true}, AllAgents: true}
	typed := request.WithContext(context.WithValue(request.Context(), authorizationContextKey{}, want))
	got, ok := principalFor(typed)
	if !ok || got.ServiceAccountID != want.ServiceAccountID || !got.AllAgents || !got.Roles[RoleViewer] {
		t.Fatalf("typed principal = %#v, accepted=%t", got, ok)
	}
}

// TestSecurityHeaders verifies security headers.
func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/docs/", nil))
	for header, want := range map[string]string{
		"Content-Security-Policy":      "frame-ancestors 'none'",
		"Strict-Transport-Security":    "max-age=31536000",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "camera=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	} {
		if got := recorder.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q; want substring %q", header, got, want)
		}
	}
}

// TestRouteRegistryContainsEveryDocumentedPath verifies route registry contains every documented path.
func TestRouteRegistryContainsEveryDocumentedPath(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	handler, token := testAPI(t, server)
	paths := []string{
		"/api/v1/agents", "/api/v1/agents/display-01", "/api/v1/agents/display-01/state",
		"/api/v1/agents/display-01/restart", "/api/v1/agents/display-01/reboot", "/api/v1/agents/display-01/shutdown",
		"/api/v1/agents/display-01/proxy/revoke",
		"/api/v1/agents/display-01/display/on", "/api/v1/agents/display-01/display/mute", "/api/v1/agents/display-01/display/volume",
		"/api/v1/agents/display-01/playlist", "/api/v1/agents/display-01/playlist/sync", "/api/v1/agents/display-01/playlist/reload",
		"/api/v1/agents/display-01/sound/info", "/api/v1/agents/display-01/serial",
		"/api/v1/agents/display-01/banner",
		"/api/v1/agents/broadcast/playlist", "/api/v1/agents/broadcast/playlist/sync", "/api/v1/agents/broadcast/playlist/reload",
		"/api/v1/agents/broadcast/display/on", "/api/v1/agents/broadcast/display/mute", "/api/v1/agents/broadcast/display/volume",
		"/api/v1/agents/broadcast/sound/info", "/api/v1/agents/broadcast/serial",
		"/api/v1/agents/broadcast/banner",
		"/api/v1/agents/broadcast/restart", "/api/v1/events/event-1",
		"/api/v1/agents/display-01/schedules",
		"/api/v1/service-accounts", "/api/v1/service-accounts/account-1", "/api/v1/service-accounts/account-1/rotate-token",
		"/api/v1/system/status",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, path, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") == "" || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("route response status=%d allow=%q type=%q body=%s", response.Code, response.Header().Get("Allow"), response.Header().Get("Content-Type"), response.Body.String())
			}
		})
	}
}

// TestOpenAPIMethodsMatchRegisteredRoutes verifies open api methods match registered routes.
func TestOpenAPIMethodsMatchRegisteredRoutes(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "swagger", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	handler, token := testAPI(t, server)
	for template, operations := range document.Paths {
		path := concreteOpenAPIPath(template)
		routeHandler := handler
		if template == "/healthz" {
			routeHandler = server.controllerHandler()
		}
		methods := make([]string, 0, len(operations))
		for method := range operations {
			switch strings.ToLower(method) {
			case "get", "put", "post", "delete", "patch", "head":
				methods = append(methods, strings.ToUpper(method))
			}
		}
		sort.Strings(methods)
		t.Run(template, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, path, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			routeHandler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("OPTIONS %s status=%d body=%s", path, response.Code, response.Body.String())
			}
			if got, want := response.Header().Get("Allow"), strings.Join(methods, ", "); got != want {
				t.Fatalf("OPTIONS %s Allow=%q, OpenAPI methods=%q", path, got, want)
			}
		})
	}
}

// concreteOpenAPIPath converts documented variables to valid registered route examples.
func concreteOpenAPIPath(template string) string {
	path := strings.NewReplacer(
		"{agentId}", "display-01",
		"{eventId}", "event-01",
		"{accountId}", "account-01",
		"{state}", "on",
		"{profile}", "info",
	).Replace(template)
	operation := "restart"
	if strings.Contains(path, "/display/") {
		operation = "mute"
	}
	return strings.ReplaceAll(path, "{operation}", operation)
}

// TestBroadcastReloadUsesContentCapability verifies broadcast reload authorization.
func TestBroadcastReloadUsesContentCapability(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	var delivered []instruction.CommandType
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type != "command" {
			t.Fatalf("unexpected frame=%#v", frame)
		}
		var message protocol.Command
		if err := protocol.Decode(frame.Payload, &message); err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, message.Command.Type())
		return nil
	}
	_, token, err := server.createServiceAccount(context.Background(), serviceAccountInput{
		Name: "content operator", Roles: []Role{RoleContentManager}, AllAgents: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.registerAPIRoutes(mux)
	handler := requestIDMiddleware(mux)

	reload := httptest.NewRequest(http.MethodPost, "/api/v1/agents/broadcast/playlist/reload", nil)
	reload.Header.Set("Authorization", "Bearer "+token)
	reloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(reloadResponse, reload)
	if reloadResponse.Code != http.StatusAccepted {
		t.Fatalf("reload status=%d body=%s", reloadResponse.Code, reloadResponse.Body.String())
	}
	if !reflect.DeepEqual(delivered, []instruction.CommandType{instruction.CommandReload}) {
		t.Fatalf("broadcast commands=%#v", delivered)
	}

	restart := httptest.NewRequest(http.MethodPost, "/api/v1/agents/broadcast/restart", nil)
	restart.Header.Set("Authorization", "Bearer "+token)
	restartResponse := httptest.NewRecorder()
	handler.ServeHTTP(restartResponse, restart)
	if restartResponse.Code != http.StatusForbidden {
		t.Fatalf("restart status=%d body=%s", restartResponse.Code, restartResponse.Body.String())
	}
}

// TestBannerRouteDispatchesTypedTransientCommand verifies the public banner contract.
func TestBannerRouteDispatchesTypedTransientCommand(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	var delivered protocol.Command
	server.sendOverride = func(agentID string, frame protocol.Frame) error {
		if agentID != "display-01" || frame.Type != "command" {
			t.Fatalf("delivery agent=%q frame=%#v", agentID, frame)
		}
		if err := protocol.Decode(frame.Payload, &delivered); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	handler, token := testAPI(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/banner",
		strings.NewReader(`{"message":"Maintenance soon","severity":"warning","duration_seconds":30}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("banner status=%d body=%s", response.Code, response.Body.String())
	}
	want := instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance soon", Severity: instruction.BannerWarning, DurationSeconds: 30})
	if delivered.Command != want {
		t.Fatalf("banner command=%#v want=%#v", delivered.Command, want)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/banner",
		strings.NewReader(`{"message":"bad","severity":"error","duration_seconds":30}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid banner status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestPlaylistReloadRouteDispatchesTypedOnlineCommand verifies the public
// reload contract without mutating controller-authoritative playlist state.
func TestPlaylistReloadRouteDispatchesTypedOnlineCommand(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	var delivered protocol.Command
	server.sendOverride = func(agentID string, frame protocol.Frame) error {
		if agentID != "display-01" || frame.Type != "command" {
			t.Fatalf("delivery agent=%q frame=%#v", agentID, frame)
		}
		if err := protocol.Decode(frame.Payload, &delivered); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	handler, token := testAPI(t, server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/playlist/reload", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("reload status=%d body=%s", response.Code, response.Body.String())
	}
	if delivered.Command.Type() != instruction.CommandReload {
		t.Fatalf("reload command=%#v", delivered.Command)
	}

	delete(server.sessions, "display-01")
	request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/playlist/reload", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"agent_offline"`) {
		t.Fatalf("offline reload status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestPlaylistSyncMarksTimingOnlyApplication verifies synchronization persists the
// authoritative clock without asking an active renderer to rebuild its views.
func TestPlaylistSyncMarksTimingOnlyApplication(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	var delivered protocol.DesiredState
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type != "desired_state" {
			t.Fatalf("frame type=%q", frame.Type)
		}
		return protocol.Decode(frame.Payload, &delivered)
	}
	handler, token := testAPI(t, server)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/agents/display-01/playlist",
		strings.NewReader(`{"urls":["https://example.test/display"]}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("playlist status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/playlist/sync",
		strings.NewReader(`{"start_at":"2026-08-28T12:00"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("sync status=%d body=%s", response.Code, response.Body.String())
	}
	if delivered.Apply != "playback" || delivered.State.Content.StartAt == 0 {
		t.Fatalf("sync desired state=%#v", delivered)
	}
}

// TestTypedPlaylistRouteUpdatesAuthoritativeState verifies typed playlist route updates authoritative state.
func TestTypedPlaylistRouteUpdatesAuthoritativeState(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	server.sendOverride = func(string, protocol.Frame) error { return nil }
	handler, token := testAPI(t, server)
	body := `{"urls":["https://example.test/display"],"proxy_allow":["https://example.test/assets/"],"start_at":1787929200}`
	request := httptest.NewRequest(http.MethodPut, "/api/v1/agents/display-01/playlist", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("playlist status=%d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/display-01/state", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("state status=%d body=%s", response.Code, response.Body.String())
	}
	var state struct {
		AgentID   string                   `json:"agent_id"`
		Revision  uint64                   `json:"revision"`
		Content   instruction.ContentState `json:"content"`
		UpdatedAt time.Time                `json:"updated_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if state.AgentID != "display-01" || state.Revision != 2 || state.Content.Mode != instruction.ContentPlaylist {
		t.Fatalf("state response = %#v", state)
	}
}

// TestPlaylistIntervalRules verifies that a single page has no interval and that
// several pages need one of at least the minimum.
func TestPlaylistIntervalRules(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	sent := 0
	server.sendOverride = func(string, protocol.Frame) error { sent++; return nil }
	handler, token := testAPI(t, server)
	const single, several = `"https://example.test/a"`, `"https://example.test/a","https://example.test/b"`
	for _, test := range []struct {
		route    string
		urls     string
		interval int
		status   int
		message  string
	}{
		{"/api/v1/agents/display-01/playlist", single, 0, http.StatusAccepted, ""},
		{"/api/v1/agents/display-01/playlist", single, 30, http.StatusBadRequest, "single-page playlist has no interval"},
		{"/api/v1/agents/display-01/playlist", several, 0, http.StatusBadRequest, "interval of 10-86400 seconds"},
		{"/api/v1/agents/display-01/playlist", several, instruction.MinPlaylistInterval - 1, http.StatusBadRequest, "interval of 10-86400 seconds"},
		{"/api/v1/agents/display-01/playlist", several, instruction.MinPlaylistInterval, http.StatusAccepted, ""},
		{"/api/v1/agents/display-01/playlist", several, instruction.MaxPlaylistInterval, http.StatusAccepted, ""},
		{"/api/v1/agents/broadcast/playlist", several, 5, http.StatusBadRequest, "interval of 10-86400 seconds"},
		{"/api/v1/agents/broadcast/playlist", single, 30, http.StatusBadRequest, "single-page playlist has no interval"},
	} {
		body := fmt.Sprintf(`{"urls":[%s],"interval":%d}`, test.urls, test.interval)
		request := httptest.NewRequest(http.MethodPut, test.route, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		before := sent
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s urls=%s interval=%d status=%d body=%s", test.route, test.urls, test.interval, response.Code, response.Body.String())
		}
		if test.status == http.StatusBadRequest && (!strings.Contains(response.Body.String(), test.message) || sent != before) {
			t.Fatalf("%s urls=%s interval=%d body=%s sent=%d", test.route, test.urls, test.interval, response.Body.String(), sent-before)
		}
	}
}

// TestRouteRegistryCentralizesAuthenticationAndMethods verifies route registry centralizes authentication and methods.
func TestRouteRegistryCentralizesAuthenticationAndMethods(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	handler, _ := testAPI(t, server)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", response.Code, response.Body.String())
	}
	var apiError map[string]string
	if err := json.NewDecoder(response.Body).Decode(&apiError); err != nil || apiError["request_id"] == "" {
		t.Fatalf("standard error=%#v decode_error=%v", apiError, err)
	}
}

// TestAgentRoutesReportMissingAgentsAndUnavailableStorage checks the 404 and
// 503 responses that the OpenAPI contract documents for agent-scoped routes.
func TestAgentRoutesReportMissingAgentsAndUnavailableStorage(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	handler, token := testAPI(t, server)
	operations := []struct{ method, operation, body string }{
		{http.MethodPost, "display/volume", `{"level":10}`},
		{http.MethodPost, "display/on", ""},
		{http.MethodPost, "sound/info", ""},
		{http.MethodPost, "serial", `{"command":"info"}`},
		{http.MethodPost, "banner", `{"message":"Notice","severity":"info","duration_seconds":5}`},
		{http.MethodGet, "schedules", ""},
		{http.MethodDelete, "schedules", ""},
	}
	send := func(method, path, body string) int {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	for _, operation := range operations {
		if status := send(operation.method, "/api/v1/agents/display-02/"+operation.operation, operation.body); status != http.StatusNotFound {
			t.Errorf("%s %s for an unprovisioned agent: status=%d, want 404", operation.method, operation.operation, status)
		}
	}
	if err := server.store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range operations {
		if status := send(operation.method, "/api/v1/agents/display-01/"+operation.operation, operation.body); status != http.StatusServiceUnavailable {
			t.Errorf("%s %s without storage: status=%d, want 503", operation.method, operation.operation, status)
		}
	}
}

// TestAgentProjectionUsesSQLiteAndSessionAuthority verifies no live status mirror is required.
func TestAgentProjectionUsesSQLiteAndSessionAuthority(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	now := time.Now().UTC()
	status := protocol.Status{
		Protocol: protocol.Version, AgentID: "display-01", FriendlyName: "Left lobby", Hostname: "display.local", Version: "1.0.0",
		Status: "online", StartedAt: now.Add(-time.Hour).Format(time.RFC3339), UptimeSeconds: 3600,
		Timestamp: now.Format(time.RFC3339Nano),
	}
	if err := server.store.SaveStatus(context.Background(), status, now); err != nil {
		t.Fatal(err)
	}
	states, err := server.loadAgentStates(context.Background(), Principal{AllAgents: true})
	if err != nil || len(states) != 1 || !states[0].IsAuthenticated || states[0].Status != "online" || states[0].Hostname != "display.local" || states[0].FriendlyName != "Left lobby" {
		t.Fatalf("connected projection=%#v error=%v", states, err)
	}
	if err := server.store.SaveStatus(context.Background(), status, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	states, err = server.loadAgentStates(context.Background(), Principal{AllAgents: true})
	if err != nil || len(states) != 1 || states[0].IsAuthenticated || states[0].Status != "offline" {
		t.Fatalf("future status projection=%#v error=%v", states, err)
	}
	if err := server.store.SaveStatus(context.Background(), status, now); err != nil {
		t.Fatal(err)
	}
	server.agentConnected("display-01")
	states, err = server.loadAgentStates(context.Background(), Principal{AllAgents: true})
	if err != nil || len(states) != 1 || states[0].IsAuthenticated || states[0].Status != "offline" || states[0].Hostname != "display.local" {
		t.Fatalf("disconnected projection=%#v error=%v", states, err)
	}
	server.sessions["display-01"] = &agentSession{id: "one"}
	server.sessions["display-02"] = &agentSession{id: "two"}
	server.clearSessions()
	if len(server.sessions) != 0 {
		t.Fatalf("transport reset retained sessions: %#v", server.sessions)
	}
}

// TestStrictJSONDecoderStandardizesBoundaryErrors verifies strict json decoder standardizes boundary errors.
func TestStrictJSONDecoderStandardizesBoundaryErrors(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{name: "valid", contentType: "application/json; charset=utf-8", body: `{"command":"status"}`, want: http.StatusOK},
		{name: "media type", contentType: "application/json; invalid", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "unknown field", contentType: "application/json", body: `{"unknown":true}`, want: http.StatusBadRequest},
		{name: "trailing value", contentType: "application/json", body: `{"command":"status"}{}`, want: http.StatusBadRequest},
		{name: "null", contentType: "application/json", body: `null`, want: http.StatusBadRequest},
		{name: "array", contentType: "application/json", body: `[]`, want: http.StatusBadRequest},
		{name: "leading JSON whitespace", contentType: "application/json", body: " \t\r\n{}", want: http.StatusOK},
		{name: "leading Unicode whitespace", contentType: "application/json", body: "\u00a0{}", want: http.StatusBadRequest},
		{name: "trailing Unicode whitespace", contentType: "application/json", body: "{}\u00a0", want: http.StatusBadRequest},
		{name: "oversized trailing whitespace", contentType: "application/json", body: `{"command":"status"}` + strings.Repeat(" ", 1<<20), want: http.StatusRequestEntityTooLarge},
		{name: "oversized", contentType: "application/json", body: `{"command":"status","unknown":"` + strings.Repeat("a", 1<<20) + `"}`, want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			var destination serialRequest
			if decodeJSONBody(response, request, &destination) {
				response.WriteHeader(http.StatusOK)
			}
			if response.Code != test.want {
				t.Fatalf("status=%d, want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

// testDatabaseKey is the fixed database key shared by controller tests.
var testDatabaseKey = bytes.Repeat([]byte{0x24}, store.KeySize)

// testServerWithAgents creates an isolated store and installs deterministic authenticated sessions.
func testServerWithAgents(t *testing.T, cfg Config, agents map[string]string) *Server {
	t.Helper()
	if cfg.Server.Database == "" {
		cfg.Server.Database = filepath.Join(t.TempDir(), "controller.db")
	}
	server := newServer(cfg, "test")
	database, err := store.Create(context.Background(), cfg.Server.Database, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	server.store = database
	t.Cleanup(func() { _ = server.store.Close() })
	for id, psk := range agents {
		if psk == "" {
			psk = strings.Repeat("ab", 32)
		}
		if err := server.createAgentCredential(id, psk, "10.99.0.2", false); err != nil {
			t.Fatal(err)
		}
		parsed, err := keyderivation.ParsePSK(psk)
		if err != nil {
			t.Fatal(err)
		}
		keys := make(map[keyderivation.Purpose][]byte, 5)
		for _, purpose := range []keyderivation.Purpose{keyderivation.TransportCommand, keyderivation.TransportStatus, keyderivation.TransportReceipt, keyderivation.TransportDisplay, keyderivation.ProxyClient} {
			keys[purpose], err = keyderivation.DeriveSession(parsed, id, strings.Repeat("11", 32), strings.Repeat("22", 32), purpose)
			if err != nil {
				t.Fatal(err)
			}
		}
		server.sessions[id] = &agentSession{id: "test-session-" + id, credential: sha256.Sum256(parsed), keys: keys}
	}
	return server
}

// testAPI returns the production route stack and a one-time administrator token.
func testAPI(t *testing.T, server *Server) (http.Handler, string) {
	t.Helper()
	_, token, err := server.createServiceAccount(context.Background(), serviceAccountInput{Name: "test administrator", Roles: []Role{RoleAdministrator}, AllAgents: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.registerAPIRoutes(mux)
	return requestIDMiddleware(mux), token
}
