// File purpose: Verifies bounded event retention behavior.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// TestRetentionCommitsBatchesAndResumes verifies failures do not roll back earlier
// batches, each failed batch remains intact, and a later pass finishes cleanup.
func TestRetentionCommitsBatchesAndResumes(t *testing.T) {
	s := openTestStore(t)
	putTestAgent(t, s, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 70 {
		event := fmt.Sprintf("expired-%03d", i)
		if _, err := s.CreateStateEvent(ctx, event, "test", "display-01", now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SaveReceipt(ctx, event, Receipt{AgentID: "display-01", Status: "completed", Operation: "desired_state", Timestamp: now.Add(-2 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateStateEvent(ctx, "retained", "test", "display-01", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_later_batch BEFORE DELETE ON command_events WHEN OLD.event_id='expired-040' BEGIN SELECT RAISE(ABORT,'simulated retention write failure'); END`); err != nil {
		t.Fatal(err)
	}
	retention := Retention{Events: time.Hour}
	if err := s.Cleanup(ctx, now, retention); err == nil {
		t.Fatal("retention ignored write failure")
	}
	for _, table := range []string{"command_events", "event_targets"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 39 {
			t.Fatalf("%s records after failed second batch: %d, error %v", table, count, err)
		}
	}
	var receipts int
	if err := s.db.QueryRow(`SELECT count(*) FROM command_receipts`).Scan(&receipts); err != nil || receipts != 38 {
		t.Fatalf("receipts after failed second batch: %d, error %v", receipts, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_later_batch`); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(ctx, now, retention); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Event(ctx, "retained"); err != nil {
		t.Fatal("retention removed a current event:", err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM command_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("retention left expired receipts: %d, error %v", receipts, err)
	}
}

// TestProxyRevocation verifies proxy-policy revocation.
func TestProxyRevocation(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/display"},
		ProxyAllow: []string{"https://assets.example.test"}}
	if _, err := store.UpdateDesiredStates(ctx, "event-policy", "test", []string{"display-01"}, DesiredChange{Content: &content}, now); err != nil {
		t.Fatal(err)
	}
	allowed, err := store.ProxyAllowed(ctx, "display-01", "https://example.test:443")
	if err != nil || !allowed {
		t.Fatalf("playlist origin policy allowed=%t error=%v", allowed, err)
	}
	allowed, err = store.ProxyAllowed(ctx, "display-01", "https://unapproved.example:443")
	if err != nil || allowed {
		t.Fatalf("unlisted proxy policy allowed=%t error=%v", allowed, err)
	}
	revoked, err := store.RevokeProxyPolicy(ctx, "display-01")
	if err != nil || !revoked {
		t.Fatalf("RevokeProxyPolicy()=%t error=%v", revoked, err)
	}
	startAt := now.Add(time.Minute).Unix()
	if _, err := store.UpdateDesiredStates(ctx, "event-sync", "test", []string{"display-01"}, DesiredChange{StartAt: &startAt}, now); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://example.test:443", "https://assets.example.test:443"} {
		if allowed, err := store.ProxyAllowed(ctx, "display-01", target); err != nil || allowed {
			t.Errorf("playlist synchronization restored revoked grant %s: allowed=%t error=%v", target, allowed, err)
		}
	}
	record, err := store.DesiredState(ctx, "display-01")
	if err != nil || record.State.Content.StartAt != startAt || len(record.State.Content.URLs) != 1 || len(record.State.Content.ProxyAllow) != 1 {
		t.Fatalf("synchronization lost desired content: %#v, %v", record, err)
	}
	// Only an explicit content publication may authorize these destinations again.
	if _, err := store.UpdateDesiredStates(ctx, "event-republish", "test", []string{"display-01"}, DesiredChange{Content: &content}, now); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://example.test:443", "https://assets.example.test:443"} {
		if allowed, err := store.ProxyAllowed(ctx, "display-01", target); err != nil || !allowed {
			t.Errorf("explicit publication did not restore %s: allowed=%t error=%v", target, allowed, err)
		}
	}
}

// TestRetentionWithinCutoffSecond preserves records newer than a whole-second cutoff.
func TestRetentionWithinCutoffSecond(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for index, offset := range []time.Duration{-time.Millisecond * 50, 0, time.Millisecond * 50} {
		id := fmt.Sprintf("display-%d", index)
		putTestAgent(t, db, id)
		at := now.Add(-time.Minute).Add(offset)
		if _, err := db.CreateStateEvent(ctx, id, "test", id, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Cleanup(ctx, now, Retention{Events: time.Minute}); err != nil {
		t.Fatal(err)
	}
	for index := range 3 {
		id := fmt.Sprintf("display-%d", index)
		_, eventErr := db.Event(ctx, id)
		if index == 0 {
			if !errors.Is(eventErr, ErrNotFound) {
				t.Fatalf("expired record retained: %v", eventErr)
			}
		} else if eventErr != nil {
			t.Fatalf("current record removed: %v", eventErr)
		}
	}
}
