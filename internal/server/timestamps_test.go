// File purpose: Verifies canonical public timestamp projections across API response families.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/store"
)

const canonicalTimestamp = "2026-08-31T18:05:42Z"

// timestampFixture returns one offset timestamp with nanosecond precision.
func timestampFixture(t *testing.T) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339Nano, "2026-08-31T11:05:42.987654321-07:00")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// TestFormatAPITimestampCanonicalizesZoneAndPrecision verifies the shared output contract.
func TestFormatAPITimestampCanonicalizesZoneAndPrecision(t *testing.T) {
	value := timestampFixture(t)
	if got := formatAPITimestamp(value); got != canonicalTimestamp {
		t.Fatalf("formatAPITimestamp()=%q want=%q", got, canonicalTimestamp)
	}
	if got := formatAPIStoredTimestamp("2026-08-31T11:05:42.987654321-07:00"); got != canonicalTimestamp {
		t.Fatalf("formatAPIStoredTimestamp()=%q want=%q", got, canonicalTimestamp)
	}
	if got := formatAPIStoredTimestamp(""); got != "" {
		t.Fatalf("empty stored timestamp=%q", got)
	}
	if got := formatAPIOptionalTimestamp(nil); got != nil {
		t.Fatalf("nil optional timestamp=%v", got)
	}
}

// TestTimestampResponseProjectionsNormalizeEveryField verifies JSON response model conversion.
func TestTimestampResponseProjectionsNormalizeEveryField(t *testing.T) {
	value := timestampFixture(t)
	agent := newAgentResponse(AgentState{
		StartedAt: "2026-08-31T11:05:42.987654321-07:00", LastSeen: value,
		Timestamp: "2026-08-31T18:05:42.123456789Z",
	})
	if agent.StartedAt != canonicalTimestamp || agent.LastSeen != canonicalTimestamp || agent.Timestamp != canonicalTimestamp {
		t.Fatalf("agent timestamps=%#v", agent)
	}

	account := serverAccount(store.Account{CreatedAt: value, UpdatedAt: value, ExpiresAt: &value, LastUsedAt: &value})
	if account.CreatedAt != canonicalTimestamp || account.UpdatedAt != canonicalTimestamp ||
		account.ExpiresAt == nil || *account.ExpiresAt != canonicalTimestamp || account.LastUsedAt == nil || *account.LastUsedAt != canonicalTimestamp {
		t.Fatalf("account timestamps=%#v", account)
	}
	withoutOptional := serverAccount(store.Account{CreatedAt: value, UpdatedAt: value})
	encoded, err := json.Marshal(withoutOptional)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["expires_at"]; exists {
		t.Fatal("nil expires_at was not omitted")
	}
	if _, exists := fields["last_used_at"]; exists {
		t.Fatal("nil last_used_at was not omitted")
	}

	event := newEventStateResponse(store.EventState{
		CreatedAt: value, UpdatedAt: value,
		Receipts: []store.Receipt{{Timestamp: value}},
	})
	if event.CreatedAt != canonicalTimestamp || event.UpdatedAt != canonicalTimestamp || event.Receipts[0].Timestamp != canonicalTimestamp {
		t.Fatalf("event timestamps=%#v", event)
	}
}

// TestDesiredStateResponseUsesCanonicalTimestamps verifies handler-level output.
func TestDesiredStateResponseUsesCanonicalTimestamps(t *testing.T) {
	server := testServerWithAgents(t, Config{}, map[string]string{"display-01": ""})
	record, err := server.store.DesiredState(context.Background(), "display-01")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents/display-01/state", nil)
	response := httptest.NewRecorder()
	server.getAgentDesiredState(response, request, "display-01")
	var state struct {
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if want := formatAPITimestamp(record.UpdatedAt); state.UpdatedAt != want {
		t.Fatalf("desired state updated_at=%q want=%q", state.UpdatedAt, want)
	}
}
