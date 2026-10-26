// File purpose: Tests crash recovery, exclusive claims, expiry, and receipt resolution.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// TestDeliveryTransitionsRollbackOnStorageFailure checks both halves of each atomic transition.
func TestDeliveryTransitionsRollbackOnStorageFailure(t *testing.T) {
	for _, table := range []string{"event_targets", "pending_deliveries"} {
		for _, operation := range []string{"claim", "reject", "expire", "recover"} {
			t.Run(table+"/"+operation, func(t *testing.T) {
				db := openTestStore(t)
				putTestAgent(t, db, "display")
				ctx := context.Background()
				now := time.Now().UTC()
				if _, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				verb := "UPDATE"
				if table == "pending_deliveries" {
					verb = "DELETE"
				}
				if _, err := db.db.Exec(fmt.Sprintf(`CREATE TRIGGER fail_transition BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'simulated write failure'); END`, verb, table)); err != nil {
					t.Fatal(err)
				}
				var err error
				switch operation {
				case "claim":
					var claimed bool
					claimed, err = db.ClaimDelivery(ctx, "event", "display", now)
					if claimed {
						t.Fatal("failed claim allowed transmission")
					}
				case "reject":
					err = db.RejectDelivery(ctx, "event", "display")
				case "expire":
					err = db.ExpireDeliveries(ctx, now.Add(2*time.Minute))
				case "recover":
					err = db.RecoverDeliveries(ctx)
				}
				if err == nil {
					t.Fatal("storage failure was hidden")
				}
				state, err := db.Event(ctx, "event")
				if err != nil || state.Deliveries[0].Status != "queued" {
					t.Fatal("partial outcome committed")
				}
				var count int
				if err := db.db.QueryRow(`SELECT count(*) FROM pending_deliveries`).Scan(&count); err != nil || count != 1 {
					t.Fatal("payload lost despite rollback")
				}
			})
		}
	}
}

// TestCancelledDeliveryWorkCannotClaimAuthority verifies shutdown cancellation at the store boundary.
func TestCancelledDeliveryWorkCannotClaimAuthority(t *testing.T) {
	db := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if claimed, err := db.ClaimDelivery(ctx, "event", "display", time.Now()); claimed || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled claim: %t %v", claimed, err)
	}
	for _, err := range []error{db.RejectDelivery(ctx, "event", "display"), db.ExpireDeliveries(ctx, time.Now()), db.RecoverDeliveries(ctx)} {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled work: %v", err)
		}
	}
	if _, err := db.EventAt(ctx, "event", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := db.Deliveries(ctx, "event"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestClaimRollbackLeavesNoAttempt proves a failing delete cannot commit uncertainty or permit sending.
func TestClaimRollbackLeavesNoAttempt(t *testing.T) {
	db := openTestStore(t)
	putTestAgent(t, db, "display")
	ctx := context.Background()
	now := time.Now().UTC()
	_, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER fail_delivery_delete BEFORE DELETE ON pending_deliveries BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	if claimed, err := db.ClaimDelivery(ctx, "event", "display", now); err == nil || claimed {
		t.Fatal("failed transaction claimed delivery")
	}
	state, err := db.Event(ctx, "event")
	if err != nil || state.Deliveries[0].Status != "queued" {
		t.Fatalf("partial claim survived rollback: %+v %v", state, err)
	}
}

// TestRestartRecoveryRejectsOnlineOnlyCommands preserves only offline-safe expiring queues.
func TestRestartRecoveryRejectsOnlineOnlyCommands(t *testing.T) {
	db := openTestStore(t)
	putTestAgent(t, db, "display")
	ctx := context.Background()
	now := time.Now().UTC()
	for id, command := range map[string]instruction.Command{
		"hardware": instruction.NewCommand(instruction.RebootCommand{}),
		"banner":   instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance", Severity: instruction.BannerInfo, DurationSeconds: 30}),
	} {
		if _, err := db.CreateCommand(ctx, id, "test", []string{"display"}, command, now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecoverDeliveries(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := db.Event(ctx, "hardware")
	if err != nil || state.Deliveries[0].Status != "rejected" {
		t.Fatal("hardware remained retryable after recovery")
	}
	state, err = db.Event(ctx, "banner")
	if err != nil || state.Deliveries[0].Status != "rejected" {
		t.Fatal("banner remained retryable after recovery")
	}
	pending, err := db.PendingCommands(ctx, "display", now, 128)
	if err != nil || len(pending) != 0 {
		t.Fatalf("online-only queue remained: %+v %v", pending, err)
	}
}

// TestClaimSurvivesReopen models death after commit but before or after transmission.
func TestClaimSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	db, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.PutAgent(ctx, "display", strings.Repeat("ab", 32), "10.99.0.2", false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimDelivery(ctx, "event", "display", now)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pending, err := db.PendingCommands(ctx, "display", now, 128)
	if err != nil || len(pending) != 0 {
		t.Fatalf("retry after crash: %v %v", pending, err)
	}
	event, err := db.Event(ctx, "event")
	if err != nil || event.Deliveries[0].Status != "uncertain" {
		t.Fatalf("outcome: %#v %v", event, err)
	}
	if _, err := db.SaveReceipt(ctx, "event", Receipt{AgentID: "display", Status: "completed", Operation: "reboot", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveReceipt(ctx, "event", Receipt{AgentID: "display", Status: "received", Operation: "reboot", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	event, err = db.Event(ctx, "event")
	if err != nil || event.Deliveries[0].Status != "completed" {
		t.Fatalf("receipt regression: %#v %v", event, err)
	}
}

// TestConcurrentDeliveryClaims permits exactly one claimant for an event target.
func TestConcurrentDeliveryClaims(t *testing.T) {
	db := openTestStore(t)
	putTestAgent(t, db, "display")
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.ReloadCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			claimed, err := db.ClaimDelivery(ctx, "event", "display", now)
			if err != nil {
				t.Error(err)
			}
			if claimed {
				winners.Add(1)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("claimants: %d", winners.Load())
	}
}

// TestExpiredClaimCannotSend checks expiry without relying on retention scheduling.
func TestExpiredClaimCannotSend(t *testing.T) {
	db := openTestStore(t)
	putTestAgent(t, db, "display")
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.ReloadCommand{}), now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if claimed, err := db.ClaimDelivery(ctx, "event", "display", now.Add(2*time.Second)); err != nil || claimed {
		t.Fatalf("expired claim %v %v", claimed, err)
	}
	if err := db.ExpireDeliveries(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	event, err := db.Event(ctx, "event")
	if err != nil || event.Deliveries[0].Status != "expired" {
		t.Fatalf("expiry %#v %v", event, err)
	}
}

// TestPendingCommandsWithinExpirySecond keeps live commands with variable timestamp precision visible.
func TestPendingCommandsWithinExpirySecond(t *testing.T) {
	for _, fraction := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			db := openTestStore(t)
			putTestAgent(t, db, "display")
			ctx := context.Background()
			now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC).Add(fraction)
			expires := now.Add(50 * time.Millisecond)
			if _, err := db.CreateCommand(ctx, "event", "test", []string{"display"}, instruction.NewCommand(instruction.ReloadCommand{}), now.Add(-time.Second), expires); err != nil {
				t.Fatal(err)
			}
			pending, err := db.PendingCommands(ctx, "display", now, 128)
			if err != nil || len(pending) != 1 {
				t.Fatalf("live command hidden: %#v, %v", pending, err)
			}
			pending, err = db.PendingCommands(ctx, "display", expires, 128)
			if err != nil || len(pending) != 0 {
				t.Fatalf("expired command visible: %#v, %v", pending, err)
			}
		})
	}
}

// TestPendingCommandsOrderWithinSecond uses time order despite varying RFC3339 precision.
func TestPendingCommandsOrderWithinSecond(t *testing.T) {
	db := openTestStore(t)
	putTestAgent(t, db, "display")
	ctx := context.Background()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for index, offset := range []time.Duration{0, 100 * time.Millisecond, 150 * time.Millisecond} {
		if _, err := db.CreateCommand(ctx, fmt.Sprintf("event-%d", index), "test", []string{"display"}, instruction.NewCommand(instruction.ReloadCommand{}), now.Add(offset), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := db.PendingCommands(ctx, "display", now.Add(time.Second), 128)
	if err != nil || len(pending) != 3 {
		t.Fatalf("pending commands = %#v, %v", pending, err)
	}
	for index, record := range pending {
		if record.EventID != fmt.Sprintf("event-%d", index) {
			t.Fatalf("pending commands out of time order: %#v", pending)
		}
	}
}
