// File purpose: Exercises pre-send durable claims and offline hardware behavior.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
)

// TestCommittedBroadcastFinishesAfterRequestCancellation keeps client disconnects
// from abandoning targets after the complete operation has committed to SQLite.
func TestCommittedBroadcastFinishesAfterRequestCancellation(t *testing.T) {
	for _, operation := range []struct {
		name, method, path, body, frameType string
	}{
		{"playlist", http.MethodPut, "/api/v1/agents/broadcast/playlist", `{"urls":["https://display.example/page"]}`, "desired_state"},
		{"banner", http.MethodPost, "/api/v1/agents/broadcast/banner", `{"message":"Maintenance","severity":"info","duration_seconds":30}`, "command"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			s := testServerWithAgents(t, Config{}, map[string]string{"display-a": "", "display-b": ""})
			handler, token := testAPI(t, s)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body)).WithContext(ctx)
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			sent := make(map[string]string)
			s.sendOverride = func(agentID string, frame protocol.Frame) error {
				if frame.Type != operation.frameType {
					t.Fatalf("unexpected frame type %q", frame.Type)
				}
				var metadata struct {
					EventID string `json:"event_id"`
				}
				if err := json.Unmarshal(frame.Payload, &metadata); err != nil {
					t.Fatal(err)
				}
				if _, duplicate := sent[agentID]; duplicate {
					t.Fatalf("duplicate attempt for %s", agentID)
				}
				sent[agentID] = metadata.EventID
				if len(sent) == 1 {
					cancel()
				}
				return nil
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if ctx.Err() == nil || response.Code != http.StatusAccepted || len(sent) != 2 {
				t.Fatalf("cancelled broadcast status=%d attempts=%v body=%s", response.Code, sent, response.Body.String())
			}
			var accepted struct {
				EventID string `json:"event_id"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil || accepted.EventID == "" {
				t.Fatalf("invalid accepted event: %s error=%v", response.Body.String(), err)
			}
			event, err := s.store.Event(context.Background(), accepted.EventID)
			if err != nil || len(event.Targets) != 2 || len(event.Deliveries) != 2 {
				t.Fatalf("committed targets=%v deliveries=%v error=%v", event.Targets, event.Deliveries, err)
			}
			for _, delivery := range event.Deliveries {
				if sent[delivery.AgentID] != accepted.EventID {
					t.Fatalf("committed target %s did not receive its event", delivery.AgentID)
				}
				if operation.name == "playlist" {
					state, err := s.store.DesiredState(context.Background(), delivery.AgentID)
					if err != nil || len(state.State.Content.URLs) != 1 || state.State.Content.URLs[0] != "https://display.example/page" {
						t.Fatalf("target %s lost committed playlist: %+v error=%v", delivery.AgentID, state, err)
					}
				} else {
					pending, err := s.store.PendingCommands(context.Background(), delivery.AgentID, time.Now(), 128)
					if err != nil || len(pending) != 0 || delivery.Status != "uncertain" {
						t.Fatalf("target %s attempt outcome=%s pending=%v error=%v", delivery.AgentID, delivery.Status, pending, err)
					}
				}
			}
		})
	}
}

// TestProvisioningDatabaseOpenPreservesLiveDeliveries distinguishes maintenance
// access from a controller process restart while another controller is running.
func TestProvisioningDatabaseOpenPreservesLiveDeliveries(t *testing.T) {
	controller := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := controller.store.CreateCommand(ctx, "live-event", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	maintenance := newServer(controller.config, "provisioning")
	if err := maintenance.openDatabase(testDatabaseKey); err != nil {
		t.Fatal(err)
	}
	defer maintenance.store.Close()
	event, err := controller.store.Event(ctx, "live-event")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "queued" {
		t.Fatalf("maintenance open changed live delivery: %+v, %v", event.Deliveries, err)
	}
	if claimed, err := controller.store.ClaimDelivery(ctx, "live-event", "display", now); err != nil || !claimed {
		t.Fatalf("live delivery no longer claimable: %v", err)
	}
}

// TestOfflineAPIOutcomes distinguishes a single conflict from broadcast per-target rejection.
func TestOfflineAPIOutcomes(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"online": "", "offline": ""})
	delete(s.sessions, "offline")
	handler, token := testAPI(t, s)
	sent := 0
	s.sendOverride = func(id string, _ protocol.Frame) error {
		if id != "online" {
			t.Error("offline target transmitted")
		}
		sent++
		return nil
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/offline/reboot", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"agent_offline"`) {
		t.Fatalf("offline response %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/offline/banner",
		strings.NewReader(`{"message":"Maintenance","severity":"info","duration_seconds":30}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"agent_offline"`) {
		t.Fatalf("offline banner response %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/agents/broadcast/reboot", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("broadcast status %d", response.Code)
	}
	var accepted struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	event, err := s.store.Event(context.Background(), accepted.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Deliveries) != 2 || event.Deliveries[0].AgentID != "offline" || event.Deliveries[0].Status != "rejected" || event.Deliveries[1].Status != "uncertain" || sent != 1 {
		t.Fatalf("broadcast outcomes %+v sends=%d", event.Deliveries, sent)
	}
}

// TestDeliveryIsConsumedBeforeWrite checks the actual external-side-effect seam.
func TestDeliveryIsConsumedBeforeWrite(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	ctx := context.Background()
	now := time.Now().UTC()
	records, err := s.store.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.sendOverride = func(_ string, _ protocol.Frame) error {
		calls++
		pending, err := s.store.PendingCommands(ctx, "display", now, 128)
		if err != nil || len(pending) != 0 {
			t.Fatalf("write before commit: %#v %v", pending, err)
		}
		event, err := s.store.Event(ctx, "event")
		if err != nil || event.Deliveries[0].Status != "uncertain" {
			t.Fatalf("write outcome: %#v %v", event, err)
		}
		return errors.New("ambiguous write")
	}
	s.deliverCommand(records[0])
	s.deliverCommand(records[0])
	s.rejectPendingDeliveries("display")
	if calls != 1 {
		t.Fatalf("attempts: %d", calls)
	}
}

// TestOfflineHardwareIsNeverReplayed retains its rejection across reconnect.
func TestOfflineHardwareIsNeverReplayed(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	session := s.sessions["display"]
	delete(s.sessions, "display")
	ctx := context.Background()
	now := time.Now().UTC()
	records, err := s.store.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.SerialCommand{Command: instruction.SerialStatus}), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s.deliverCommand(records[0])
	s.sessions["display"] = session
	s.sendOverride = func(string, protocol.Frame) error { t.Fatal("offline hardware replayed"); return nil }
	s.rejectPendingDeliveries("display")
	event, err := s.store.Event(ctx, "event")
	if err != nil || event.Deliveries[0].Status != "rejected" {
		t.Fatalf("rejection %#v %v", event, err)
	}
}

// TestPublicationUsesNewestCommittedState prevents stale concurrent handlers from winning.
func TestPublicationUsesNewestCommittedState(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	ctx := context.Background()
	now := time.Now().UTC()
	first := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://one.example"}}
	old, err := s.store.UpdateDesiredStates(ctx, "old", "test", []string{"display"}, store.DesiredChange{Content: &first}, now)
	if err != nil {
		t.Fatal(err)
	}
	next := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://two.example"}}
	latest, err := s.store.UpdateDesiredStates(ctx, "new", "test", []string{"display"}, store.DesiredChange{Content: &next}, now)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.sendOverride = func(_ string, f protocol.Frame) error {
		calls++
		var state protocol.DesiredState
		if err := protocol.Decode(f.Payload, &state); err != nil {
			t.Fatal(err)
		}
		if state.Revision != latest[0].Revision || state.State.Content.URLs[0] != next.URLs[0] {
			t.Fatalf("stale publication %#v", state)
		}
		return nil
	}
	if err := s.publishDesiredState(old[0], "old"); err != nil {
		t.Fatal(err)
	}
	if err := s.publishDesiredState(latest[0], "new"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("missing event publications %d", calls)
	}
}
