// File purpose: Verifies complete reconnect reconciliation and superseded state delivery outcomes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
)

// TestReconnectSendsOneCompleteAuthoritativeState verifies reconnect sends one complete authoritative state.
func TestReconnectSendsOneCompleteAuthoritativeState(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	content := instruction.ContentState{
		Mode:       instruction.ContentPlaylist,
		URLs:       []string{"https://display.example/page"},
		ProxyAllow: []string{"https://display.example/assets/"},
		StartAt:    1787932800,
	}
	records, err := server.store.UpdateDesiredStates(context.Background(), "evt-state", "test", []string{agentID}, store.DesiredChange{Content: &content}, time.Now().UTC())
	if err != nil || len(records) != 1 {
		t.Fatalf("state update records=%#v error=%v", records, err)
	}
	var frames []protocol.Frame
	server.sendOverride = func(deliveredAgent string, frame protocol.Frame) error {
		if deliveredAgent != agentID {
			t.Fatalf("state delivered to %q", deliveredAgent)
		}
		frames = append(frames, frame)
		return nil
	}
	if err := server.sendDesiredState(agentID); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].Type != "desired_state" {
		t.Fatalf("reconciliation frames=%#v", frames)
	}
	var message protocol.DesiredState
	if err := protocol.Decode(frames[0].Payload, &message); err != nil {
		t.Fatal(err)
	}
	if message.AgentID != agentID || message.Revision != records[0].Revision || message.Generation != records[0].Generation ||
		message.State.Content.Mode != instruction.ContentPlaylist ||
		len(message.State.Content.URLs) != 1 || len(message.State.Content.ProxyAllow) != 0 {
		t.Fatalf("incomplete reconciliation message=%#v", message)
	}
	for index, status := range []string{"received", "accepted"} {
		receipt := protocol.Receipt{
			Protocol: protocol.Version, SessionID: server.sessions[agentID].id, Sequence: uint64(index + 1),
			EventID: message.EventID, AgentID: agentID, Status: status, Operation: "desired_state",
			Timestamp: time.Now().UTC().Add(time.Duration(index) * time.Nanosecond).Format(time.RFC3339Nano),
		}
		receipt.Signature, err = protocol.SignReceipt(receipt, server.sessions[agentID].keys[keyderivation.TransportReceipt])
		if err != nil {
			t.Fatal(err)
		}
		if err := server.handleReceipt(agentID, mustJSON(t, receipt)); err != nil {
			t.Fatalf("authenticated reconciliation receipt %q was rejected", status)
		}
	}
	event, err := server.store.Event(context.Background(), message.EventID)
	if err != nil || len(event.Receipts) != 2 || event.Receipts[1].Status != "accepted" {
		t.Fatalf("reconciliation event=%#v error=%v", event, err)
	}
}

// TestSupersededPlaybackHintIsCleared verifies that a concurrent playlist edit
// cannot inherit a timing-only hint from an earlier synchronization request.
func TestSupersededPlaybackHintIsCleared(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	ctx := context.Background()
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/old"}}
	_, err := server.store.UpdateDesiredStates(ctx, "initial", "test", []string{agentID}, store.DesiredChange{Content: &content}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	start := int64(1787932800)
	records, err := server.store.UpdateDesiredStates(ctx, "sync", "test", []string{agentID}, store.DesiredChange{StartAt: &start}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	content.URLs = []string{"https://example.test/new"}
	latest, err := server.store.UpdateDesiredStates(ctx, "replacement", "test", []string{agentID}, store.DesiredChange{Content: &content}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var message protocol.DesiredState
	server.sendOverride = func(_ string, frame protocol.Frame) error { return protocol.Decode(frame.Payload, &message) }
	if err := server.publishDesiredStateWithApply(records[0], "sync", "playback"); err != nil {
		t.Fatal(err)
	}
	if message.Apply != "" || message.Revision != latest[0].Revision || message.State.Content.URLs[0] != content.URLs[0] {
		t.Fatalf("superseded timing hint escaped into latest state: %#v", message)
	}
	if err := server.publishDesiredStateWithApply(latest[0], "replacement", "playback"); err != nil {
		t.Fatal(err)
	}
	if message.Apply != "playback" {
		t.Fatal("current timing hint was discarded")
	}
}

// TestSupersededDispatchResolvesDeliveredRevision covers an edit committed
// while an earlier publication waits for dispatch. The earlier event sends the
// latest complete state under a reconciliation event, whose acceptance expires
// the superseded publication and settles the newer edit.
func TestSupersededDispatchResolvesDeliveredRevision(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	ctx := context.Background()
	now := time.Now().UTC()
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://display.example/old"}}
	initial, err := server.store.UpdateDesiredStates(ctx, "earlier", "test", []string{agentID}, store.DesiredChange{Content: &content}, now)
	if err != nil {
		t.Fatal(err)
	}
	content.URLs = []string{"https://display.example/latest"}
	latest, err := server.store.UpdateDesiredStates(ctx, "latest", "test", []string{agentID}, store.DesiredChange{Content: &content}, now)
	if err != nil {
		t.Fatal(err)
	}
	var message protocol.DesiredState
	server.sendOverride = func(_ string, frame protocol.Frame) error { return protocol.Decode(frame.Payload, &message) }
	if err := server.publishDesiredState(initial[0], "earlier"); err != nil {
		t.Fatal(err)
	}
	if message.Revision != latest[0].Revision || message.EventID == "earlier" {
		t.Fatalf("delivered state=%#v, want revision %d under a reconciliation event", message, latest[0].Revision)
	}
	if _, err := server.recordCommandReceipt(protocol.Receipt{AgentID: agentID, EventID: message.EventID, Status: "accepted", Operation: "desired_state", Timestamp: now.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	event, err := server.store.Event(ctx, "latest")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "accepted" {
		t.Fatalf("delivered latest publication remains unresolved: %#v, error=%v", event.Deliveries, err)
	}
	event, err = server.store.Event(ctx, "earlier")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "expired" ||
		!strings.HasPrefix(event.Deliveries[0].Reason, "superseded by revision ") {
		t.Fatalf("superseded publication was not expired: %#v, error=%v", event.Deliveries, err)
	}
	// A later publication has not been sent and must remain queued.
	if _, err := server.store.UpdateDesiredStates(ctx, "unsent", "test", []string{agentID}, store.DesiredChange{Content: &content}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := server.recordCommandReceipt(protocol.Receipt{AgentID: agentID, EventID: message.EventID, Status: "completed", Operation: "desired_state", Timestamp: now.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	event, err = server.store.Event(ctx, "unsent")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "queued" {
		t.Fatalf("unsent publication was resolved: %#v, error=%v", event.Deliveries, err)
	}
}

// TestOfflinePublicationResolvesAfterReconnect keeps the event returned for a
// change published while its display was offline from staying queued after
// the display applies the change through reconnect reconciliation.
func TestOfflinePublicationResolvesAfterReconnect(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	session := server.sessions[agentID]
	delete(server.sessions, agentID)
	handler, token := testAPI(t, server)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/agents/"+agentID+"/playlist", strings.NewReader(`{"urls":["https://display.example/a"]}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var published struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &published); err != nil || response.Code != http.StatusAccepted {
		t.Fatalf("offline publication status=%d body=%s", response.Code, response.Body.String())
	}
	var reconciliation string
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		var message protocol.DesiredState
		if err := protocol.Decode(frame.Payload, &message); err != nil {
			return err
		}
		reconciliation = message.EventID
		return nil
	}
	server.sessions[agentID] = session
	if err := server.sendDesiredState(agentID); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"received", "accepted"} {
		receipt := protocol.Receipt{AgentID: agentID, EventID: reconciliation, Status: status, Operation: "desired_state", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		if _, err := server.recordCommandReceipt(receipt); err != nil {
			t.Fatal(err)
		}
	}
	event, err := server.store.EventAt(context.Background(), published.EventID, time.Now().UTC())
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "accepted" ||
		event.Deliveries[0].Reason != "applied through event "+reconciliation {
		t.Fatalf("offline publication outcome=%#v error=%v", event.Deliveries, err)
	}
}
