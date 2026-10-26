// File purpose: Verifies vendored Swagger integrity, security headers, and OpenAPI references.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package swagger

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/protocol"
	"go.yaml.in/yaml/v3"
)

// TestOpenAPISpecificationParses verifies open api specification parses.
func TestOpenAPISpecificationParses(t *testing.T) {
	var document struct {
		OpenAPI string `yaml:"openapi"`
		Info    struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPISpec, &document); err != nil {
		t.Fatalf("parse embedded OpenAPI specification: %v", err)
	}
	if document.OpenAPI != "3.0.3" || document.Info.Version != "1.0.0" {
		t.Fatalf("unexpected OpenAPI metadata: format=%q version=%q", document.OpenAPI, document.Info.Version)
	}
	for _, path := range []string{
		"/healthz",
		"/api/v1/agents/{agentId}",
		"/api/v1/agents/{agentId}/{operation}",
		"/api/v1/agents/broadcast/{operation}",
		"/api/v1/events/{eventId}",
		"/api/v1/agents/{agentId}/state",
		"/api/v1/system/status",
		"/api/v1/agents/{agentId}/display/stream",
	} {
		if _, ok := document.Paths[path]; !ok {
			t.Errorf("OpenAPI specification does not document %s", path)
		}
	}

	for _, response := range []struct {
		path   string
		method string
		status string
	}{
		{path: "/api/v1/agents/{agentId}/proxy/revoke", method: "post", status: "202"},
		{path: "/api/v1/agents/{agentId}/proxy/revoke", method: "post", status: "204"},
		{path: "/api/v1/agents/{agentId}/proxy/revoke", method: "post", status: "404"},
		{path: "/api/v1/agents/{agentId}/proxy/revoke", method: "post", status: "500"},
		{path: "/api/v1/agents/broadcast/playlist", method: "put", status: "400"},
		{path: "/api/v1/agents/{agentId}/display/stream", method: "get", status: "200"},
		{path: "/api/v1/agents/{agentId}/display/stream", method: "get", status: "503"},
		{path: "/api/v1/agents/{agentId}/display/stream", method: "get", status: "504"},
	} {
		operation, ok := document.Paths[response.path][response.method].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI specification does not document %s %s", response.method, response.path)
			continue
		}
		responses, ok := operation["responses"].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI specification does not document responses for %s %s", response.method, response.path)
			continue
		}
		if _, ok := responses[response.status]; !ok {
			t.Errorf("OpenAPI specification does not document %s for %s %s", response.status, response.method, response.path)
		}
	}
}

// TestPlaylistStartExamplesDoNotScheduleFuturePlayback verifies playlist start examples do not schedule future playback.
func TestPlaylistStartExamplesDoNotScheduleFuturePlayback(t *testing.T) {
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openAPISpec, &document); err != nil {
		t.Fatalf("parse embedded OpenAPI specification: %v", err)
	}
	for _, schema := range []string{"PlaylistRequest"} {
		startAt, ok := document.Components.Schemas[schema].Properties["start_at"]
		if !ok {
			t.Fatalf("%s has no start_at property", schema)
		}
		example, exists := startAt["example"]
		value, numeric := example.(int)
		if !exists || !numeric || value != 0 {
			t.Errorf("%s start_at example must be the immediate value 0", schema)
		}
	}
	syncStartAt := document.Components.Schemas["SyncRequest"].Properties["start_at"]
	if syncStartAt["example"] != "2026-09-21T15:00" {
		t.Errorf("SyncRequest start_at example must be a controller-local date and time")
	}
	if _, ok := syncStartAt["format"]; ok {
		t.Error("SyncRequest start_at must not use RFC 3339 date-time format for a local time")
	}
}

// TestCanonicalTimestampSchemaDocumentsPublicFormat verifies exact response timestamp precision and zone.
func TestCanonicalTimestampSchemaDocumentsPublicFormat(t *testing.T) {
	var document struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openAPISpec, &document); err != nil {
		t.Fatal(err)
	}
	timestamp := document.Components.Schemas["CanonicalTimestamp"]
	if timestamp["format"] != "date-time" || timestamp["pattern"] != `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` || timestamp["example"] != "2026-08-31T18:05:42Z" {
		t.Fatalf("canonical timestamp schema=%#v", timestamp)
	}
}

// TestAgentStateSchemaDocumentsReportedFields checks current protocol, labels, and not-yet-reported timestamps.
func TestAgentStateSchemaDocumentsReportedFields(t *testing.T) {
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `yaml:"properties"`
				OneOf      []map[string]any          `yaml:"oneOf"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(openAPISpec, &document); err != nil {
		t.Fatal(err)
	}
	properties := document.Components.Schemas["AgentState"].Properties
	if properties["protocol"]["example"] != protocol.Version {
		t.Fatalf("documented agent protocol=%v, current=%d", properties["protocol"]["example"], protocol.Version)
	}
	if friendlyName := properties["friendly_name"]; friendlyName["type"] != "string" || friendlyName["maxLength"] != 32 {
		t.Fatalf("friendly_name schema=%#v", friendlyName)
	}
	if properties["started_at"]["$ref"] != "#/components/schemas/AgentReportedTimestamp" {
		t.Fatal("agent startup timestamp does not allow an unreported value")
	}
	timestamp, ok := properties["timestamp"]["allOf"].([]any)
	var reportedTimestamp map[string]any
	if ok && len(timestamp) == 1 {
		reportedTimestamp, _ = timestamp[0].(map[string]any)
	}
	if reportedTimestamp["$ref"] != "#/components/schemas/AgentReportedTimestamp" {
		t.Fatal("agent status timestamp does not allow an unreported value")
	}
	var canonical, empty bool
	for _, branch := range document.Components.Schemas["AgentReportedTimestamp"].OneOf {
		canonical = canonical || branch["$ref"] == "#/components/schemas/CanonicalTimestamp"
		values, ok := branch["enum"].([]any)
		empty = empty || (ok && branch["type"] == "string" && len(values) == 1 && values[0] == "")
	}
	if !canonical || !empty {
		t.Fatal("reported timestamp must accept canonical UTC and empty values")
	}
}

// TestOpenAPIReferencesAndAuthenticatedOperations verifies open api references and authenticated operations.
func TestOpenAPIReferencesAndAuthenticatedOperations(t *testing.T) {
	var document map[string]any
	if err := yaml.Unmarshal(openAPISpec, &document); err != nil {
		t.Fatal(err)
	}

	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "$ref" {
					ref, ok := child.(string)
					if !ok || !openAPIReferenceExists(document, ref) {
						t.Errorf("unresolved OpenAPI reference %v", child)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(document)

	paths, ok := document["paths"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI paths are unavailable")
	}
	for path, rawPath := range paths {
		if !strings.HasPrefix(path, "/api/") {
			continue
		}
		pathItem, ok := rawPath.(map[string]any)
		if !ok {
			t.Errorf("invalid path item %s", path)
			continue
		}
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			rawOperation, exists := pathItem[method]
			if !exists {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				t.Errorf("invalid operation %s %s", method, path)
				continue
			}
			responses, ok := operation["responses"].(map[string]any)
			if !ok {
				t.Errorf("operation %s %s has no responses", method, path)
				continue
			}
			if _, ok := responses["401"]; !ok {
				t.Errorf("authenticated operation %s %s does not document 401", method, path)
			}
			// The router checks scope, agent existence and storage before
			// any agent-scoped handler runs.
			if strings.Contains(path, "{agentId}") {
				for _, status := range []string{"403", "404", "503"} {
					if _, ok := responses[status]; !ok {
						t.Errorf("agent-scoped operation %s %s does not document %s", method, path, status)
					}
				}
			}
		}
	}
}

// openAPIReferenceExists follows one local component reference in the parsed contract.
func openAPIReferenceExists(document map[string]any, ref string) bool {
	if !strings.HasPrefix(ref, "#/") {
		return false
	}
	var current any = document
	for segment := range strings.SplitSeq(strings.TrimPrefix(ref, "#/"), "/") {
		segment = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		mapping, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = mapping[segment]
		if !ok {
			return false
		}
	}
	return true
}

// TestRoutes verifies routes.
func TestRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	tests := []struct {
		name        string
		path        string
		contentType string
		contains    string
		containsAll []string
	}{
		{
			name:        "specification",
			path:        "/openapi.yaml",
			contentType: "application/vnd.oai.openapi;version=3.0.3",
			contains:    "openapi: 3.0.3",
		},
		{
			name:        "user interface",
			path:        "/docs/",
			contentType: "text/html; charset=utf-8",
			contains:    "swagger-ui",
		},
		{
			name:        "local bundle",
			path:        "/docs/swagger-ui-bundle.js",
			contentType: "application/javascript; charset=utf-8",
			contains:    "SwaggerUIBundle",
		},
		{
			name:        "bundle dependency notices",
			path:        "/docs/swagger-ui-bundle.js.LICENSE.txt",
			contentType: "text/plain; charset=utf-8",
			contains:    "DOMPurify",
			containsAll: []string{
				string(swaggerLicense),
				string(swaggerSupplementalNotices),
				"Copyright 2020-2021 SmartBear Software Inc.",
				"Copyright 2008 Fair Oaks Labs, Inc.",
				"Redistributions in binary form must reproduce the above copyright notice",
				"IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
			}
			if got := recorder.Header().Get("Content-Type"); got != test.contentType {
				t.Fatalf("Content-Type = %q, want %q", got, test.contentType)
			}
			if !strings.Contains(recorder.Body.String(), test.contains) {
				t.Fatalf("response does not contain %q", test.contains)
			}
			for _, notice := range test.containsAll {
				if !strings.Contains(recorder.Body.String(), notice) {
					t.Errorf("response omits required third-party notice: %q", notice)
				}
			}
		})
	}
}

// TestUserInterfaceSecurityPolicy verifies user interface security policy.
func TestUserInterfaceSecurityPolicy(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/docs/", nil)
	mux.ServeHTTP(recorder, request)

	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "img-src 'self' data: blob:") {
		t.Fatal("Swagger UI CSP does not allow local binary image previews")
	}
}

// TestDocumentationRoutesRejectUnsupportedMethods verifies documentation routes reject unsupported methods.
func TestDocumentationRoutesRejectUnsupportedMethods(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	for _, path := range []string{"/docs", "/docs/", "/openapi.yaml"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, path, nil)
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusMethodNotAllowed && recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 or 405", recorder.Code)
			}
			if recorder.Code == http.StatusMethodNotAllowed && recorder.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("405 response Allow = %q, want GET", recorder.Header().Get("Allow"))
			}
		})
	}
}
