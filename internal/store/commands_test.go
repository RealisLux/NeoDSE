// File purpose: Verifies durable command dispatch, bounded pending delivery, receipts, and transactional rollback.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestReceiptHistoryKeepsEachStateOnce verifies duplicates preserve the first
// diagnostic and terminal outcome while late intermediate statuses remain visible.
func TestReceiptHistoryKeepsEachStateOnce(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := store.CreateStateEvent(ctx, "event-bounded", "test", "display-01", now); err != nil {
		t.Fatal(err)
	}
	statuses := []string{"completed", "received", "accepted", "failed", "expired", "unsupported"}
	for _, status := range statuses {
		for attempt := range 3 {
			details := "first diagnostic"
			if attempt > 0 {
				details = "duplicate diagnostic"
			}
			receipt := Receipt{AgentID: "display-01", Status: status, Operation: "desired_state", Details: details, Timestamp: now.Add(time.Duration(attempt) * time.Second)}
			recorded, err := store.SaveReceipt(ctx, "event-bounded", receipt)
			if err != nil || recorded != (attempt == 0) {
				t.Fatalf("status=%s attempt=%d recorded=%t error=%v", status, attempt, recorded, err)
			}
		}
	}
	event, err := store.Event(ctx, "event-bounded")
	if err != nil || len(event.Receipts) != len(statuses) || event.Deliveries[0].Status != "completed" {
		t.Fatalf("receipt lifecycle=%#v error=%v", event, err)
	}
	for index, receipt := range event.Receipts {
		if receipt.Status != statuses[index] || receipt.Details != "first diagnostic" || !receipt.Timestamp.Equal(now) {
			t.Fatalf("duplicate changed history: %#v", receipt)
		}
	}
}

// TestDisplayFailureRetainsBoundedStatusAndFullReceipt verifies a valid failure
// diagnostic cannot overflow the narrower CEC status projection and roll back its receipt.
func TestDisplayFailureRetainsBoundedStatusAndFullReceipt(t *testing.T) {
	for _, test := range []struct {
		name, diagnostic string
	}{
		{"ASCII", strings.Repeat("x", protocol.ReceiptErrorMaxBytes)},
		{"UTF-8", "x" + strings.Repeat("界", 341)},
	} {
		t.Run(test.name, func(t *testing.T) {
			diagnostic := test.diagnostic
			store := openTestStore(t)
			putTestAgent(t, store, "display-01")
			ctx := context.Background()
			now := time.Now().UTC()
			if err := store.SaveStatus(ctx, protocol.Status{AgentID: "display-01", CECPower: "on"}, now); err != nil {
				t.Fatal(err)
			}
			command := instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayOff})
			if _, err := store.CreateCommand(ctx, "event-display-failure", "test", []string{"display-01"}, command, now, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			receipt := Receipt{AgentID: "display-01", Status: "failed", Operation: "display", Error: diagnostic, Timestamp: now.Add(time.Second)}
			if _, err := store.SaveReceipt(ctx, "event-display-failure", receipt); err != nil {
				t.Fatal(err)
			}
			event, err := store.Event(ctx, "event-display-failure")
			if err != nil || len(event.Receipts) != 1 || event.Receipts[0].Error != diagnostic || event.Deliveries[0].Status != "failed" {
				t.Fatalf("event=%#v error=%v", event, err)
			}
			status, err := store.CECStatus(ctx, "display-01")
			if err != nil || status.CECPower != "unknown" || len(status.CECOutput) > protocol.ReceiptDetailsMaxBytes || !utf8.ValidString(status.CECOutput) || !strings.HasPrefix(diagnostic, status.CECOutput) || len(status.CECOutput) < protocol.ReceiptDetailsMaxBytes-utf8.UTFMax+1 {
				t.Fatalf("CEC status=%#v error=%v", status, err)
			}
		})
	}
}

// TestCommandDeliveryAndReceiptLifecycle verifies command delivery and receipt lifecycle.
func TestCommandDeliveryAndReceiptLifecycle(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC)
	command := instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayOn})
	created, err := store.CreateCommand(ctx, "event-command", "test", []string{"display-01"}, command, now, now.Add(time.Minute))
	if err != nil || len(created) != 1 {
		t.Fatalf("CreateCommand() records=%#v error=%v", created, err)
	}
	pending, err := store.PendingCommands(ctx, "display-01", now, 10)
	if err != nil || len(pending) != 1 || pending[0].Command != command {
		t.Fatalf("PendingCommands() records=%#v error=%v", pending, err)
	}
	if claimed, err := store.ClaimDelivery(ctx, "event-command", "display-01", now); err != nil || !claimed {
		t.Fatal(err)
	}
	receipt := Receipt{AgentID: "display-01", Status: "completed", Operation: "display", Details: "power status: on", Value: "on", Timestamp: now.Add(time.Second)}
	if _, err := store.SaveReceipt(ctx, "event-command", receipt); err != nil {
		t.Fatal(err)
	}
	state, err := store.Event(ctx, "event-command")
	if err != nil || len(state.Targets) != 1 || len(state.Receipts) != 1 || state.Receipts[0].Operation != "display" || state.Receipts[0].Details != "power status: on" || state.Receipts[0].Value != "on" {
		t.Fatalf("Event() state=%#v error=%v", state, err)
	}

	pending, err = store.PendingCommands(ctx, "display-01", now, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("completed command remained pending: %#v error=%v", pending, err)
	}
}

// TestCommandsUseCanonicalJSONStorage verifies every command type uses the same bounded SQLite representation.
func TestCommandsUseCanonicalJSONStorage(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	command := instruction.NewCommand(instruction.DisplayVolumeCommand{Level: 42})
	if _, err := store.CreateCommand(context.Background(), "event-json", "test", []string{"display-01"}, command, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := store.db.QueryRow(`SELECT command_json FROM pending_deliveries WHERE event_id=?`, "event-json").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != `{"type":"display_volume","payload":{"level":42}}` {
		t.Fatalf("command_json = %q", stored)
	}
	if _, err := store.db.Exec(`UPDATE pending_deliveries SET command_json=? WHERE event_id=?`, `{"type":"restart"}`, "event-json"); err == nil {
		t.Fatal("mismatched command type bypassed the schema constraint")
	}
	if _, err := decodeStoredCommand(instruction.CommandDisplayVolume, `{"type":"restart"}`); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("mismatched decoded command error = %v", err)
	}
	if _, err := decodeStoredCommand(instruction.CommandDisplayVolume, `{"type":"display_volume","payload":{"level":42,"unknown":true}}`); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown stored command field error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE pending_deliveries SET command_json=? WHERE event_id=?`, strings.Repeat("x", maxStoredCommandBytes+1), "event-json"); err == nil {
		t.Fatal("invalid command JSON bypassed the schema constraint")
	}
	if _, err := decodeStoredCommand(instruction.CommandDisplayVolume, strings.Repeat("x", maxStoredCommandBytes+1)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("oversized stored command error = %v", err)
	}
}

// TestSerialCommandRoundTrip preserves structured peripheral intent through storage.
func TestSerialCommandRoundTrip(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	command := instruction.NewCommand(instruction.SerialCommand{Command: instruction.SerialBeacon, State: instruction.PeripheralBlink, PeriodMS: 60000})
	if _, err := store.CreateCommand(context.Background(), "event-max-serial", "test", []string{"display-01"}, command, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingCommands(context.Background(), "display-01", now, 10)
	if err != nil || len(pending) != 1 || pending[0].Command != command {
		t.Fatalf("serial round trip=%#v error=%v", pending, err)
	}
}

// TestBannerCommandRoundTrip preserves all structured transient display fields.
func TestBannerCommandRoundTrip(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	command := instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance soon", Severity: instruction.BannerWarning, DurationSeconds: 30})
	if _, err := store.CreateCommand(context.Background(), "event-banner", "test", []string{"display-01"}, command, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingCommands(context.Background(), "display-01", now, 10)
	if err != nil || len(pending) != 1 || pending[0].Command != command {
		t.Fatalf("banner round trip=%#v error=%v", pending, err)
	}
	receipt := Receipt{AgentID: "display-01", Status: "completed", Operation: "banner", Timestamp: now.Add(time.Second)}
	if _, err := store.SaveReceipt(context.Background(), "event-banner", receipt); err != nil {
		t.Fatal(err)
	}
}

// TestStateEventExistsBeforeAuthenticatedReceipt verifies state event exists before authenticated receipt.
func TestStateEventExistsBeforeAuthenticatedReceipt(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	if _, err := store.CreateStateEvent(context.Background(), "event-reconcile", "reconciliation", "display-01", now); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{AgentID: "display-01", Status: "accepted", Operation: "desired_state", Timestamp: now.Add(time.Second)}
	if _, err := store.SaveReceipt(context.Background(), "event-reconcile", receipt); err != nil {
		t.Fatal(err)
	}
	event, err := store.Event(context.Background(), "event-reconcile")
	if err != nil || len(event.Targets) != 1 || len(event.Receipts) != 1 || event.Targets[0] != "display-01" {
		t.Fatalf("state event=%#v error=%v", event, err)
	}
}

// TestAcceptedDesiredStateResolvesEarlierDeliveries keeps the events returned
// to operators meaningful when a display applies changes after reconnecting.
func TestAcceptedDesiredStateResolvesEarlierDeliveries(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	publish := func(eventID, url string) {
		t.Helper()
		content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{url}}
		if _, err := store.UpdateDesiredStates(ctx, eventID, "http-api", []string{"display-01"}, DesiredChange{Content: &content}, now); err != nil {
			t.Fatal(err)
		}
	}
	publish("event-superseded", "https://display.example/first")
	// The display received the first change before its connection dropped.
	if _, err := store.SaveReceipt(ctx, "event-superseded", Receipt{AgentID: "display-01", Status: "received", Operation: "desired_state", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	publish("event-latest", "https://display.example/latest")
	command := instruction.NewCommand(instruction.BannerCommand{Message: "unrelated", Severity: "info", DurationSeconds: 5})
	if _, err := store.CreateCommand(ctx, "event-command", "http-api", []string{"display-01"}, command, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateStateEvent(ctx, "event-reconcile", "reconciliation", "display-01", now); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"received", "accepted"} {
		receipt := Receipt{AgentID: "display-01", Status: status, Operation: "desired_state", Timestamp: now.Add(time.Second)}
		if _, err := store.SaveReceipt(ctx, "event-reconcile", receipt); err != nil {
			t.Fatal(err)
		}
	}
	for eventID, want := range map[string]Delivery{
		"event-reconcile":  {AgentID: "display-01", Status: "accepted"},
		"event-latest":     {AgentID: "display-01", Status: "accepted", Reason: "applied through event event-reconcile"},
		"event-superseded": {AgentID: "display-01", Status: "expired", Reason: "superseded by revision 3"},
		"event-command":    {AgentID: "display-01", Status: "queued"},
	} {
		event, err := store.EventAt(ctx, eventID, now)
		if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0] != want {
			t.Errorf("%s deliveries=%#v error=%v, want %#v", eventID, event.Deliveries, err, want)
		}
	}
	latest, err := store.Event(ctx, "event-latest")
	if err != nil || !latest.UpdatedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("resolved event update time=%s error=%v", latest.UpdatedAt, err)
	}
}

// TestStateEventValidationAndRollback verifies malformed or unknown targets cannot leave partial events.
func TestStateEventValidationAndRollback(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()
	if _, err := store.CreateStateEvent(context.Background(), "", "reconciliation", "display-01", now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid state event error = %v", err)
	}
	if _, err := store.CreateStateEvent(context.Background(), "event-missing-agent", "reconciliation", "display-01", now); err == nil {
		t.Fatal("unknown state-event target was accepted")
	}
	if _, err := store.Event(context.Background(), "event-missing-agent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial state event error = %v", err)
	}
}

// TestCreateCommandRollsBackOnInvalidTarget verifies create command rolls back on invalid target.
func TestCreateCommandRollsBackOnInvalidTarget(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	_, err := store.CreateCommand(context.Background(), "event-rollback", "test", []string{"display-01", "missing"}, instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Minute))
	if err == nil {
		t.Fatal("invalid target was accepted")
	}
	if _, eventErr := store.Event(context.Background(), "event-rollback"); !errors.Is(eventErr, ErrNotFound) {
		t.Fatalf("rolled-back command event error = %v, want not found", eventErr)
	}
}

// TestCommandValidationAndExpiryAreEnforced verifies command validation and expiry are enforced.
func TestCommandValidationAndExpiryAreEnforced(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	_, err := store.CreateCommand(context.Background(), "event-invalid", "test", []string{"display-01"}, instruction.Command{}, now, now.Add(time.Minute))
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid command error = %v, want invalid state", err)
	}
	if _, err := store.PendingCommands(context.Background(), "display-01", now, 0); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid limit error = %v, want invalid state", err)
	}
	if _, err := store.CreateCommand(context.Background(), "event-expire", "test", []string{"display-01"}, instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingCommands(context.Background(), "display-01", now.Add(2*time.Second), 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expired pending commands=%#v error=%v", pending, err)
	}
}

// TestReceiptRequiresExistingEventTarget verifies receipt requires existing event target.
func TestReceiptRequiresExistingEventTarget(t *testing.T) {
	store := openTestStore(t)
	_, err := store.SaveReceipt(context.Background(), "missing", Receipt{AgentID: "missing", Status: "failed", Operation: "restart", Timestamp: time.Now().UTC()})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing receipt target error=%v", err)
	}
}

// TestReceiptValidationRejectsInvalidDurableData verifies receipt validation rejects invalid durable data.
func TestReceiptValidationRejectsInvalidDurableData(t *testing.T) {
	store := openTestStore(t)
	for name, receipt := range map[string]Receipt{
		"missing timestamp": {AgentID: "display-01", Status: "failed", Operation: "restart"},
		"unknown status":    {AgentID: "display-01", Status: "unknown", Operation: "restart", Timestamp: time.Now().UTC()},
		"unknown operation": {AgentID: "display-01", Status: "failed", Operation: "execute", Timestamp: time.Now().UTC()},
		"nul error":         {AgentID: "display-01", Status: "failed", Operation: "restart", Error: "bad\x00value", Timestamp: time.Now().UTC()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.SaveReceipt(context.Background(), "event", receipt); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("SaveReceipt() error=%v, want invalid state", err)
			}
		})
	}
}
