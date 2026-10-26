// File purpose: Verifies proxy authentication, SSRF defenses, forwarding, limits, and tunnelling.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// TestProxyRejectsPositionalArguments prevents misplaced flags from being
// ignored before the proxy selects its credential-bearing configuration.
func TestProxyRejectsPositionalArguments(t *testing.T) {
	for _, args := range [][]string{
		{"proxy.yaml"},
		{"--config", "missing.yaml", "extra"},
		{"extra", "--config", "missing.yaml"},
	} {
		if err := Run(context.Background(), args, "test"); err == nil || !strings.Contains(err.Error(), "positional arguments") {
			t.Fatalf("Run(%q) = %v, want positional argument rejection", args, err)
		}
	}
}

// TestProxyDiagnosticLogLevels verifies proxy diagnostic log levels.
func TestProxyDiagnosticLogLevels(t *testing.T) {
	output := captureProxyTestLogs(t)
	proxy := &Proxy{}
	request := &proxyRequest{id: 7, started: time.Now(), outcome: "completed"}
	proxy.logRequestSummary(request)
	proxy.debugLog("debug message")
	if output.Len() != 0 {
		t.Fatalf("info level emitted diagnostic output: %q", output.String())
	}

	proxy.verbose = true
	proxy.logRequestSummary(request)
	proxy.debugLog("debug message")
	if got := output.String(); !strings.Contains(got, "proxy request") || strings.Contains(got, "debug message") {
		t.Fatalf("verbose output = %q", got)
	}

	output.Reset()
	proxy.verbose = false
	proxy.debug = true
	proxy.logRequestSummary(request)
	proxy.debugLog("debug message")
	if got := output.String(); !strings.Contains(got, "proxy request") || !strings.Contains(got, "debug message") {
		t.Fatalf("debug output = %q", got)
	}
}

// captureProxyTestLogs installs a temporary structured logger for one serial test.
func captureProxyTestLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	return &output
}

// TestReadTrustAnchorRejectsUnsafeFiles verifies read trust anchor rejects unsafe files.
func TestReadTrustAnchorRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	trusted := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(trusted, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := readTrustAnchor(trusted)
	if err != nil || string(contents) != "certificate" {
		t.Fatalf("readTrustAnchor() contents=%q error=%v", contents, err)
	}
	link := filepath.Join(directory, "ca-link.pem")
	if err := os.Symlink(trusted, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustAnchor(link); err == nil {
		t.Fatal("symlink trust anchor was accepted")
	}
	if err := os.Chmod(trusted, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustAnchor(trusted); err == nil {
		t.Fatal("writable trust anchor was accepted")
	}
}

// TestRunHelpDoesNotStartProxy verifies run help does not start proxy.
func TestRunHelpDoesNotStartProxy(t *testing.T) {
	if err := Run(context.Background(), []string{"-help"}, "test-version"); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Run(-help) error = %v, want flag.ErrHelp", err)
	}
}

// TestConfiguredProxyBuildsBoundedClients verifies runtime dependencies and explicit network policy are derived once.
func TestConfiguredProxyBuildsBoundedClients(t *testing.T) {
	var loaded Config
	loaded.Proxy.InternalPSK = strings.Repeat("ab", 32)
	loaded.Proxy.AuthorizedNetworks = []string{"10.20.0.0/16"}
	loaded.Proxy.LogLevel = "verbose"
	configured, err := newConfiguredProxy(loaded, proxyRunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if configured.backendClient == nil || configured.proxyClient == nil || configured.internalToken == "" ||
		len(configured.authorizedNetworks) != 1 || !configured.verbose || configured.debug {
		t.Fatalf("configured proxy = %+v", configured)
	}
	loaded.Proxy.InternalPSK = "invalid"
	if _, err := newConfiguredProxy(loaded, proxyRunOptions{}); err == nil {
		t.Fatal("invalid internal credential was accepted")
	}
}

// TestConfiguredProxyCapacityLimitsTunnels holds real CONNECT tunnels open, as
// browsers do for HTTPS pages and WebSockets, and checks the configured
// display and fleet limits together with their operator-visible warning, which
// must not repeat the unauthenticated agent claim.
func TestConfiguredProxyCapacityLimitsTunnels(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
	}))
	t.Cleanup(backend.Close)
	var loaded Config
	loaded.Proxy.BackendURL = backend.URL
	loaded.Proxy.InternalPSK = strings.Repeat("ab", 32)
	loaded.Proxy.MaxConnections = 3
	loaded.Proxy.MaxAgentConnections = 2
	proxy, err := newConfiguredProxy(loaded, proxyRunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proxy.backendClient = backend.Client()
	proxy.dialOverride = func(context.Context, string, string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		t.Cleanup(func() { _ = upstreamSide.Close() })
		return proxySide, nil
	}
	server := httptest.NewServer(http.HandlerFunc(proxy.handleProxy))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	open := func(agentID string) string {
		t.Helper()
		client, err := net.DialTimeout("tcp", address.Host, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		credentials := base64.StdEncoding.EncodeToString([]byte(agentID + ":" + strings.Repeat("a", 64)))
		if _, err := io.WriteString(client, "CONNECT dashboards.example:443 HTTP/1.1\r\nHost: dashboards.example:443\r\nProxy-Authorization: Basic "+credentials+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		status, err := bufio.NewReader(client).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	for _, step := range []struct {
		agentID string
		status  string
	}{
		{"display-01", " 200 "}, {"display-01", " 200 "}, {"display-01", " 503 "},
		{"display-02", " 200 "}, {"display-03", " 503 "},
	} {
		if status := open(step.agentID); !strings.Contains(status, step.status) {
			t.Fatalf("%s tunnel status = %q, want %q", step.agentID, status, step.status)
		}
	}
	output := logged.String()
	if strings.Count(output, "connection capacity reached") != 1 ||
		!strings.Contains(output, "! Proxy display connection capacity reached suppressed=0; raise proxy.max_agent_connections") ||
		strings.Contains(output, "display-01") {
		t.Fatalf("capacity warnings were not rate-limited operator diagnostics: %q", output)
	}
}

// TestProxyServeStopsWithContext verifies the listener follows bounded shutdown lifecycle.
func TestProxyServeStopsWithContext(t *testing.T) {
	var loaded Config
	loaded.Proxy.Listen = "127.0.0.1:0"
	loaded.Proxy.BackendURL = "https://127.0.0.1:8443"
	proxy := &Proxy{config: loaded}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := proxy.serve(ctx, "test"); err != nil {
		t.Fatalf("serve() shutdown error = %v", err)
	}
}

// TestRemoveHopByHopHeaders verifies remove hop by hop headers.
func TestRemoveHopByHopHeaders(t *testing.T) {
	header := make(http.Header)
	header.Set("Connection", "X-Internal-Header")
	header.Set("Keep-Alive", "timeout=5")
	header.Set("Proxy-Authorization", "Basic credentials")
	header.Set("Proxy-Connection", "keep-alive")
	header.Set("X-Internal-Header", "remove-me")
	header.Set("X-Request-ID", "keep-me")

	removeHopByHopHeaders(header)

	for _, key := range []string{
		"Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "X-Internal-Header",
	} {
		if header.Get(key) != "" {
			t.Errorf("header %q was not removed", key)
		}
	}
	if got := header.Get("X-Request-ID"); got != "keep-me" {
		t.Errorf("end-to-end header = %q, want keep-me", got)
	}
}

// TestProxyCredentialsRequireBoundedCanonicalValues verifies proxy credentials require bounded canonical values.
func TestProxyCredentialsRequireBoundedCanonicalValues(t *testing.T) {
	p := &Proxy{}
	valid := base64.StdEncoding.EncodeToString([]byte("display-01:" + strings.Repeat("a", 64)))
	request := httptest.NewRequest(http.MethodGet, "http://example.net", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+valid)
	agentID, token, reason := p.proxyCredentials(request)
	if reason != "" || agentID != "display-01" || token != strings.Repeat("a", 64) {
		t.Fatalf("valid credentials parsed as agent=%q token_length=%d reason=%q", agentID, len(token), reason)
	}

	for name, authorization := range map[string]string{
		"unsupported scheme": "Digest value",
		"invalid base64":     "Basic %%%",
		"oversized":          "Basic " + strings.Repeat("a", 257),
		"bad agent":          "Basic " + base64.StdEncoding.EncodeToString([]byte("../agent:"+strings.Repeat("a", 64))),
		"bad token":          "Basic " + base64.StdEncoding.EncodeToString([]byte("display-01:not-hex")),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.net", nil)
			request.Header.Set("Proxy-Authorization", authorization)
			if _, _, reason := p.proxyCredentials(request); reason == "" {
				t.Fatal("invalid proxy credentials were accepted")
			}
		})
	}
}

// FuzzProxyCredentials exercises the Proxy-Authorization parser that every
// request reaches before the controller authenticates it.
func FuzzProxyCredentials(f *testing.F) {
	valid := base64.StdEncoding.EncodeToString([]byte("display-01:" + strings.Repeat("a", 64)))
	f.Add("Basic " + valid)
	f.Add("basic  " + valid + " ")
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("broadcast:"+strings.Repeat("a", 64))))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("A", 64))))
	f.Add("Digest value")
	f.Add("")
	p := &Proxy{}
	f.Fuzz(func(t *testing.T, authorization string) {
		request := httptest.NewRequest(http.MethodGet, "http://content.example/", nil)
		request.Header.Set("Proxy-Authorization", authorization)
		agentID, token, reason := p.proxyCredentials(request)
		if reason != "" {
			if agentID != "" || token != "" {
				t.Fatalf("rejected credentials returned values: reason=%s", reason)
			}
			return
		}
		if !identity.ValidAgentID(agentID) || !proxyTokenPattern.MatchString(token) {
			t.Fatalf("accepted noncanonical credentials: agent=%q token_length=%d", agentID, len(token))
		}
	})
}

// TestRevokedProxyCredentialReturnsAuthenticationChallenge verifies revoked proxy credentials require authentication.
func TestRevokedProxyCredentialReturnsAuthenticationChallenge(t *testing.T) {
	response := wire.AuthorizeResponse{Authenticated: false, Allowed: false}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(backend.Close)

	var proxyConfig Config
	proxyConfig.Proxy.BackendURL = backend.URL
	output := captureProxyTestLogs(t)
	proxy := &Proxy{
		config: proxyConfig, backendClient: backend.Client(), internalToken: "configured", verbose: true,
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.net/content", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("display-01:" + strings.Repeat("b", 64)))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request)

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("revoked credential status = %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="NeoDSE"` {
		t.Fatalf("Proxy-Authenticate = %q", got)
	}

	response = wire.AuthorizeResponse{Authenticated: true, Allowed: false}
	recorder = httptest.NewRecorder()
	proxy.handleProxy(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("denied destination status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	logs := output.String()
	if strings.Count(logs, `msg="proxy request"`) != 2 ||
		!strings.Contains(logs, "outcome=authentication_required") ||
		!strings.Contains(logs, "outcome=authorization_denied") ||
		!strings.Contains(logs, "agent_id=display-01") ||
		!strings.Contains(logs, "destination_host=example.net") ||
		!strings.Contains(logs, "destination_port=80") ||
		!strings.Contains(logs, "protocol=http") {
		t.Fatalf("authorization summaries = %q", logs)
	}
	if strings.Contains(logs, "/content") || strings.Contains(logs, request.RemoteAddr) ||
		strings.Count(logs, "agent_id=display-01") != 1 {
		t.Fatalf("authorization summary leaked unauthenticated or request data: %s", logs)
	}
}

// TestHTTPRedirectIsReturnedToClient verifies http redirect is returned to client.
func TestHTTPRedirectIsReturnedToClient(t *testing.T) {
	var redirectedRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(redirectTarget.Close)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirectTarget.URL+"/private")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.AuthorizeResponse{Authenticated: true, Allowed: true})
	}))
	t.Cleanup(backend.Close)

	var proxyConfig Config
	proxyConfig.Proxy.BackendURL = backend.URL
	proxy := &Proxy{
		config:        proxyConfig,
		backendClient: backend.Client(),
		internalToken: "configured",
		proxyClient:   testOriginClient(t, origin),
	}

	request := httptest.NewRequest(http.MethodGet, "http://approved.example/content", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("display-01:" + strings.Repeat("a", 64)))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("redirect status = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got, want := recorder.Header().Get("Location"), redirectTarget.URL+"/private"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

// TestPermittedAddress verifies explicit networks for DNS results and IP literals.
func TestPermittedAddress(t *testing.T) {
	networks := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("8.8.8.0/24")}
	tests := []struct {
		address string
		want    bool
	}{
		{address: "8.8.8.8", want: true},
		{address: "8.8.4.4"},
		{address: "10.20.1.5", want: true},
		{address: "::ffff:10.20.1.5", want: true},
		{address: "10.21.1.5"},
		{address: "127.0.0.1"},
		{address: "169.254.1.1"},
		{address: "2001:db8::1"},
	}
	proxy := &Proxy{authorizedNetworks: networks}
	for _, test := range tests {
		if got := proxy.permittedAddress(netip.MustParseAddr(test.address)); got != test.want {
			t.Errorf("permittedAddress(%s) = %t, want %t", test.address, got, test.want)
		}
	}
	proxy.authorizedNetworks = nil
	if proxy.permittedAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("empty list permitted a destination")
	}
	proxy.authorizedNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if proxy.permittedAddress(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback address was enabled by a covering network")
	}
}

// TestParseTargetsAcceptIPv4Literals ensures proxying does not require a FQDN.
func TestParseTargetsAcceptIPv4Literals(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://10.20.1.5:8080/status", nil)
	target, err := parseHTTPProxyTarget(request)
	if err != nil || target.host != "10.20.1.5" || target.address != "10.20.1.5:8080" {
		t.Fatalf("parseHTTPProxyTarget() = %+v, %v", target, err)
	}
	target, err = parseConnectTarget("10.20.1.5:443")
	if err != nil || target.host != "10.20.1.5" || target.address != "10.20.1.5:443" {
		t.Fatalf("parseConnectTarget() = %+v, %v", target, err)
	}
}

// TestIsHopByHopHeader verifies is hop by hop header.
func TestIsHopByHopHeader(t *testing.T) {
	for _, header := range []string{"Transfer-Encoding", "transfer-encoding", "Proxy-Connection"} {
		if !isHopByHopHeader(header) {
			t.Fatalf("%s must be treated as a hop-by-hop header", header)
		}
	}
	if isHopByHopHeader("Content-Type") {
		t.Fatal("Content-Type must not be treated as a hop-by-hop header")
	}
}

// TestAuthorizeFailsClosedOnInvalidBackendResponses verifies authorize fails closed on invalid backend responses.
func TestAuthorizeFailsClosedOnInvalidBackendResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        authorizationDecision
	}{
		{name: "allowed", status: http.StatusOK, contentType: "application/json; charset=utf-8", body: `{"authenticated":true,"allowed":true}`, want: authorizationAllowed},
		{name: "destination denied", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":true,"allowed":false}`, want: authorizationDenied},
		{name: "credential rejected", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":false,"allowed":false}`, want: authorizationCredentialsRejected},
		{name: "backend failure", status: http.StatusServiceUnavailable, contentType: "application/json", body: `{}`, want: authorizationUnavailable},
		{name: "wrong content type", status: http.StatusOK, contentType: "text/plain", body: `{"authenticated":true,"allowed":true}`, want: authorizationUnavailable},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":true,"allowed":true,"extra":true}`, want: authorizationUnavailable},
		{name: "multiple values", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":true,"allowed":true}{}`, want: authorizationUnavailable},
		{name: "malformed", status: http.StatusOK, contentType: "application/json", body: `{`, want: authorizationUnavailable},
		{name: "oversized trailing whitespace", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":true,"allowed":true}` + strings.Repeat(" ", 64<<10), want: authorizationUnavailable},
		{name: "hidden trailing value", status: http.StatusOK, contentType: "application/json", body: `{"authenticated":true,"allowed":true}` + strings.Repeat(" ", 64<<10) + `{}`, want: authorizationUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/proxy/authorize" {
					t.Errorf("authorization request = %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-NeoDSE-Proxy-Token") != "internal" {
					t.Error("authorization request omitted internal credential")
				}
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(backend.Close)
			var cfg Config
			cfg.Proxy.BackendURL = backend.URL
			proxy := &Proxy{config: cfg, backendClient: backend.Client(), internalToken: "internal"}
			if got := proxy.authorize(context.Background(), 1, "display-01", strings.Repeat("a", 64), "example.net", "443", "https"); got != test.want {
				t.Fatalf("authorize() = %d, want %d", got, test.want)
			}
		})
	}
}

// TestAuthorizeRejectsMissingConfiguration verifies authorize rejects missing configuration.
func TestAuthorizeRejectsMissingConfiguration(t *testing.T) {
	t.Parallel()
	for name, proxy := range map[string]*Proxy{
		"backend URL":         {internalToken: "internal", backendClient: http.DefaultClient},
		"internal credential": {config: func() Config { var cfg Config; cfg.Proxy.BackendURL = "https://backend.invalid"; return cfg }(), backendClient: http.DefaultClient},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := proxy.authorize(context.Background(), 1, "display-01", strings.Repeat("a", 64), "example.net", "443", "https"); got != authorizationUnavailable {
				t.Fatalf("authorize() = %d, want unavailable", got)
			}
		})
	}
}

// TestAuthorizationOutageWarningsAreBoundedAndAnonymous keeps a locked or
// unreachable controller from producing one warning per proxied request, and
// keeps identities that the controller never authenticated out of the journal.
func TestAuthorizationOutageWarningsAreBoundedAndAnonymous(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })
	backend := httptest.NewServer(http.NotFoundHandler())
	unreachable := backend.URL
	backend.Close()
	var cfg Config
	cfg.Proxy.BackendURL = unreachable
	proxy := &Proxy{config: cfg, backendClient: &http.Client{Timeout: time.Second}, internalToken: "internal"}
	authorize := func(ctx context.Context, agentID string) {
		t.Helper()
		if got := proxy.authorize(ctx, 1, agentID, strings.Repeat("a", 64), "example.net", "443", "https"); got != authorizationUnavailable {
			t.Fatalf("authorize() = %d, want unavailable", got)
		}
	}
	authorize(context.Background(), "display-01")
	authorize(context.Background(), "display-02")
	// A client that disconnects ends its own lookup; that is not an outage.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	authorize(cancelled, "display-03")
	if output := logged.String(); strings.Count(output, "! Proxy authorization unavailable") != 1 ||
		!strings.Contains(output, "reason=backend_unreachable") || !strings.Contains(output, "suppressed=0") ||
		strings.Contains(output, "display-") {
		t.Fatalf("authorization outage warnings were not bounded and anonymous: %q", output)
	}
	// The next interval's warning reports the repeat that the limiter suppressed.
	logged.Reset()
	proxy.backendWarnings.logged = time.Now().Add(-warningLogInterval)
	authorize(context.Background(), "display-04")
	if output := logged.String(); strings.Count(output, "! Proxy authorization unavailable") != 1 ||
		!strings.Contains(output, "suppressed=1") || strings.Contains(output, "display-") {
		t.Fatalf("suppressed authorization warnings were not counted: %q", output)
	}
}

// TestProxyRejectsRequestsBeforeForwarding verifies proxy rejects requests before forwarding.
func TestProxyRejectsRequestsBeforeForwarding(t *testing.T) {
	t.Parallel()
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("a", 64)))

	t.Run("missing credentials", func(t *testing.T) {
		proxy := &Proxy{}
		recorder := httptest.NewRecorder()
		proxy.handleProxy(recorder, httptest.NewRequest(http.MethodGet, "http://example.net", nil))
		if recorder.Code != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", recorder.Code)
		}
	})

	t.Run("global capacity", func(t *testing.T) {
		capacity := make(chan struct{}, 1)
		capacity <- struct{}{}
		proxy := &Proxy{connections: capacity}
		recorder := httptest.NewRecorder()
		proxy.handleProxy(recorder, httptest.NewRequest(http.MethodGet, "http://example.net", nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", recorder.Code)
		}
	})

	for name, target := range map[string]*url.URL{
		"relative URL":   {Path: "/relative"},
		"invalid scheme": {Scheme: "ftp", Host: "example.net"},
		"URL user info":  {Scheme: "https", Host: "example.net", User: url.User("operator")},
	} {
		t.Run(name, func(t *testing.T) {
			proxy := &Proxy{}
			request := httptest.NewRequest(http.MethodGet, "http://example.net", nil)
			request.URL = target
			request.Header.Set("Proxy-Authorization", credential)
			recorder := httptest.NewRecorder()
			proxy.handleProxy(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
		})
	}
}

// TestProxyStripsHopHeadersInBothDirections verifies proxy strips hop headers in both directions.
func TestProxyStripsHopHeadersInBothDirections(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("proxy-only request headers reached origin")
		}
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "remove")
		w.Header().Set("X-End-To-End", "keep")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
	}))
	t.Cleanup(backend.Close)
	var cfg Config
	cfg.Proxy.BackendURL = backend.URL
	proxy := &Proxy{config: cfg, backendClient: backend.Client(), internalToken: "internal", proxyClient: testOriginClient(t, origin)}
	request := httptest.NewRequest(http.MethodGet, "http://approved.example/content", nil)
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "remove")
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("a", 64))))
	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("Connection") != "" || recorder.Header().Get("X-Origin-Hop") != "" {
		t.Fatal("hop-by-hop response headers reached client")
	}
	if recorder.Header().Get("X-End-To-End") != "keep" {
		t.Fatal("end-to-end response header was removed")
	}
}

// TestProxyBindsForwardedHostToAuthorizedTarget verifies a client cannot select
// another virtual host after the controller authorizes the URL destination.
func TestProxyBindsForwardedHostToAuthorizedTarget(t *testing.T) {
	var authorizedHost string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Host, authorizedHost; got != want {
			t.Errorf("forwarded Host = %q, want authorized host %q", got, want)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)
	authorizedHost = "approved.example:80"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
	}))
	t.Cleanup(backend.Close)

	var cfg Config
	cfg.Proxy.BackendURL = backend.URL
	proxy := &Proxy{
		config:        cfg,
		backendClient: backend.Client(),
		internalToken: "internal",
		proxyClient:   testOriginClient(t, origin),
	}
	request := httptest.NewRequest(http.MethodGet, "http://approved.example/content", nil)
	request.Host = "unapproved.example"
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("a", 64))))
	recorder := httptest.NewRecorder()

	proxy.handleProxy(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

// TestSafeDialRejectsLocalAndMalformedDestinations verifies safe dial rejects local and malformed destinations.
func TestSafeDialRejectsLocalAndMalformedDestinations(t *testing.T) {
	t.Parallel()
	proxy := &Proxy{}
	for name, address := range map[string]string{"malformed": "missing-port", "loopback": "127.0.0.1:80", "unspecified": "0.0.0.0:80"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if connection, err := proxy.dialDestination(ctx, "tcp", address); err == nil {
				_ = connection.Close()
				t.Fatal("denied destination was dialed")
			}
		})
	}
}

// TestConnectTunnelRelaysBytesAfterAuthorization verifies connect tunnel relays bytes after authorization.
func TestConnectTunnelRelaysBytesAfterAuthorization(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true}`))
	}))
	t.Cleanup(backend.Close)
	upstreamConnections := make(chan net.Conn, 1)
	var cfg Config
	cfg.Proxy.BackendURL = backend.URL
	proxy := &Proxy{
		config:        cfg,
		backendClient: backend.Client(),
		internalToken: "internal",
		dialOverride: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "example.net:443" {
				t.Errorf("dial target = %s %s", network, address)
			}
			proxySide, upstreamSide := net.Pipe()
			upstreamConnections <- upstreamSide
			return proxySide, nil
		},
	}
	proxyServer := httptest.NewServer(http.HandlerFunc(proxy.handleProxy))
	t.Cleanup(proxyServer.Close)
	parsed, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", parsed.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	credentials := base64.StdEncoding.EncodeToString([]byte("display-01:" + strings.Repeat("a", 64)))
	request := "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT response = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	upstream := <-upstreamConnections
	t.Cleanup(func() { _ = upstream.Close() })
	upstreamDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(upstream, buffer); err != nil {
			upstreamDone <- err
			return
		}
		_, err := upstream.Write([]byte("pong"))
		upstreamDone <- err
	}()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(reader, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("tunnel response = %q", response)
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

// TestRelayTunnelKeepsOneWayStreamsOpen verifies that data in either direction
// keeps a tunnel open, as for long downloads or server-sent events, and that the
// tunnel closes once neither direction has transferred data for the idle period.
func TestRelayTunnelKeepsOneWayStreamsOpen(t *testing.T) {
	const idle = 500 * time.Millisecond
	clientApplication, clientSide := net.Pipe()
	upstreamSide, upstreamApplication := net.Pipe()
	defer clientApplication.Close()
	defer upstreamApplication.Close()
	results := make(chan []tunnelCopyResult, 1)
	go func() { results <- (&Proxy{}).relayTunnel(clientSide, upstreamSide, &proxyRequest{}, idle) }()
	received := make(chan int64, 1)
	go func() {
		count, _ := io.Copy(io.Discard, clientApplication)
		received <- count
	}()
	var sent int64
	for started := time.Now(); time.Since(started) < 3*idle; sent++ {
		if _, err := upstreamApplication.Write([]byte{'x'}); err != nil {
			t.Fatalf("one-way stream closed after %d bytes while data was flowing: %v", sent, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case tunnel := <-results:
		if !errors.Is(tunnel[0].err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle tunnel ended with %v, want an idle timeout", tunnel[0].err)
		}
	case <-time.After(idle + 5*time.Second):
		t.Fatal("tunnel stayed open after both directions were idle")
	}
	if count := <-received; count != sent {
		t.Fatalf("client received %d of %d streamed bytes", count, sent)
	}
}

// TestConnectFailsClosedAtEveryBoundary verifies connect fails closed at every boundary.
func TestConnectFailsClosedAtEveryBoundary(t *testing.T) {
	response := wire.AuthorizeResponse{Authenticated: true, Allowed: true}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(backend.Close)
	var cfg Config
	cfg.Proxy.BackendURL = backend.URL
	proxy := &Proxy{
		config:        cfg,
		backendClient: backend.Client(),
		internalToken: "internal",
		dialOverride: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial denied")
		},
	}
	credentials := "Basic " + base64.StdEncoding.EncodeToString([]byte("display-01:"+strings.Repeat("a", 64)))
	request := func(host string) *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
		r.Host = host
		r.Header.Set("Proxy-Authorization", credentials)
		return r
	}

	recorder := httptest.NewRecorder()
	proxy.handleProxy(recorder, request("invalid-target"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid target status = %d, want 400", recorder.Code)
	}

	response = wire.AuthorizeResponse{Authenticated: false, Allowed: false}
	recorder = httptest.NewRecorder()
	proxy.handleProxy(recorder, request("example.net:443"))
	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("revoked credential status = %d, want 407", recorder.Code)
	}

	response = wire.AuthorizeResponse{Authenticated: true, Allowed: false}
	recorder = httptest.NewRecorder()
	proxy.handleProxy(recorder, request("example.net:443"))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("denied destination status = %d, want 403", recorder.Code)
	}

	response = wire.AuthorizeResponse{Authenticated: true, Allowed: true}
	recorder = httptest.NewRecorder()
	proxy.handleProxy(recorder, request("example.net:443"))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("dial failure status = %d, want 502", recorder.Code)
	}

	proxy.dialOverride = func(context.Context, string, string) (net.Conn, error) {
		proxySide, peerSide := net.Pipe()
		_ = peerSide.Close()
		return proxySide, nil
	}
	recorder = httptest.NewRecorder()
	proxy.handleProxy(recorder, request("example.net:443"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("non-hijacking writer status = %d, want 500", recorder.Code)
	}
}

// testOriginClient maps an approved logical origin to a controlled local fixture.
func testOriginClient(t *testing.T, origin *httptest.Server) *http.Client {
	t.Helper()
	client := &http.Client{CheckRedirect: returnRedirectResponse, Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
	}}}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

// TestReadTrustAnchorRejectsFIFOWithoutWriter bounds invalid trust-file handling.
func TestReadTrustAnchorRejectsFIFOWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readTrustAnchor(path); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatal("trust anchor load blocked opening a FIFO")
	}
}
