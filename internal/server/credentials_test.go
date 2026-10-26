// File purpose: Verifies agent credential creation, rotation, removal, and WireGuard metadata parsing.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestBroadcastIdentifierCannotBecomeAnAgent prevents an individual device's
// API paths from dispatching commands to the entire fleet.
func TestBroadcastIdentifierCannotBecomeAnAgent(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": "", "display-02": ""})
	if err := server.createAgentCredential("broadcast", strings.Repeat("ab", 32), "10.99.0.2", false); err == nil {
		t.Error("reserved broadcast route name was provisioned as an individual agent")
	}
	handler, token := testAPI(t, server)
	server.sendOverride = func(string, protocol.Frame) error { return nil }
	request := httptest.NewRequest(http.MethodPut, "/api/v1/agents/broadcast/playlist", strings.NewReader(`{"urls":["https://example.test/display"]}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("broadcast failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var accepted struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	event, err := server.store.Event(context.Background(), accepted.EventID)
	if err != nil || !reflect.DeepEqual(event.Targets, []string{"display-01", "display-02"}) {
		t.Fatalf("broadcast route collided with an agent: targets=%v error=%v", event.Targets, err)
	}
}

// TestAgentCredentialsStoredInDatabase verifies agent credentials stored in database.
func TestAgentCredentialsStoredInDatabase(t *testing.T) {
	s := testServerWithAgents(t, Config{}, nil)
	first := strings.Repeat("ab", 32)
	second := strings.Repeat("cd", 32)
	if err := s.createAgentCredential("display-01", first, "10.99.0.2", false); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.agentPSKValue(context.Background(), "display-01"); !ok || got != first {
		t.Fatalf("stored credential = %q, %t", got, ok)
	}
	for _, address := range []string{"", "203.0.113.5", "fd00::1", "10.99.0"} {
		if err := s.createAgentCredential("display-02", first, address, false); err == nil {
			t.Fatalf("tunnel address %q was accepted", address)
		}
	}
	if err := s.createAgentCredential("display-01", second, "10.99.0.2", false); err == nil {
		t.Fatal("duplicate credential was accepted")
	}
	if err := s.createAgentCredential("display-01", second, "10.99.0.2", true); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.agentPSKValue(context.Background(), "display-01"); !ok || got != second {
		t.Fatalf("replaced credential = %q, %t", got, ok)
	}
	if err := s.deleteAgentCredential("display-01"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.agentPSKValue(context.Background(), "display-01"); ok {
		t.Fatal("deleted credential still exists")
	}
}

// TestWireGuardEndpointMetadata verifies wire guard endpoint metadata.
func TestWireGuardEndpointMetadata(t *testing.T) {
	contents := "# NeoDSEEndpoint = vpn.example:51820\n[Interface]\nAddress = 10.99.0.1/24\n"
	if got := wireGuardMetadata(contents, "NeoDSEEndpoint"); got != "vpn.example:51820" {
		t.Fatalf("endpoint metadata = %q", got)
	}
	if got := wireGuardMetadata(contents, "Missing"); got != "" {
		t.Fatalf("missing metadata = %q", got)
	}
}
