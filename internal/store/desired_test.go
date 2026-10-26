// File purpose: Verifies atomic desired-state updates, normalized playlist storage, proxy policy derivation, and rollback.
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

// TestUpdateDesiredStatesPersistsCompleteTypedState verifies update desired states persists complete typed state.
func TestUpdateDesiredStatesPersistsCompleteTypedState(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	content := instruction.ContentState{
		Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/display"},
		ProxyAllow: []string{"https://example.test/assets/"}, StartAt: now.Unix(),
	}
	records, err := store.UpdateDesiredStates(ctx, "event-state", "test", []string{"display-01"}, DesiredChange{Content: &content}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Revision != 2 {
		t.Fatalf("updated records = %#v", records)
	}
	restored, err := store.DesiredState(ctx, "display-01")
	if err != nil {
		t.Fatal(err)
	}
	if restored.State.Content.URLs[0] != content.URLs[0] || restored.State.Content.ProxyAllow[0] != content.ProxyAllow[0] {
		t.Fatalf("normalized content was not restored: %#v", restored.State.Content)
	}
	allowed, err := store.ProxyAllowed(ctx, "display-01", "https://example.test:443")
	if err != nil || !allowed {
		t.Fatalf("derived proxy target allowed=%t error=%v", allowed, err)
	}
}

// TestDesiredStateUpdateRollsBackAllTargets verifies desired state update rolls back all targets.
func TestDesiredStateUpdateRollsBackAllTargets(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test"}}
	_, err := store.UpdateDesiredStates(context.Background(), "event-rollback", "test", []string{"display-01", "missing"}, DesiredChange{Content: &content}, time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("multi-target error = %v, want not found", err)
	}
	restored, loadErr := store.DesiredState(context.Background(), "display-01")
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if restored.Revision != 1 || restored.State.Content.Mode != instruction.ContentDefault {
		t.Fatalf("partial state escaped rollback: %#v", restored)
	}
	if _, eventErr := store.Event(context.Background(), "event-rollback"); !errors.Is(eventErr, ErrNotFound) {
		t.Fatalf("rolled-back event error = %v, want not found", eventErr)
	}
}

// TestDesiredStateUpdateRejectsNoTargets verifies an update cannot create an event without an owner.
func TestDesiredStateUpdateRejectsNoTargets(t *testing.T) {
	store := openTestStore(t)
	_, err := store.UpdateDesiredStates(context.Background(), "event-no-targets", "test", nil, DesiredChange{}, time.Now())
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("empty targets error = %v, want invalid state", err)
	}
	if _, eventErr := store.Event(context.Background(), "event-no-targets"); !errors.Is(eventErr, ErrNotFound) {
		t.Fatalf("unwritten event error = %v, want not found", eventErr)
	}
}

// TestDesiredStateUpdateRejectsDuplicateEventsAndUnknownTargets verifies failed updates leave no state behind.
func TestDesiredStateUpdateRejectsDuplicateEventsAndUnknownTargets(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := store.UpdateDesiredStates(ctx, "event-unique", "test", []string{"display-01"}, DesiredChange{}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateDesiredStates(ctx, "event-unique", "test", []string{"display-01"}, DesiredChange{}, now); err == nil {
		t.Fatal("duplicate event was accepted")
	}
	if _, err := store.UpdateDesiredStates(ctx, "event-missing-target", "test", []string{"missing"}, DesiredChange{}, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target error = %v, want not found", err)
	}
	if _, err := store.Event(ctx, "event-missing-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial event error = %v, want not found", err)
	}
}

// TestPlaylistTimingRequiresAuthoritativePlaylist verifies playlist timing requires authoritative playlist.
func TestPlaylistTimingRequiresAuthoritativePlaylist(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	startAt := time.Now().Unix()
	_, err := store.UpdateDesiredStates(context.Background(), "event-sync", "test", []string{"display-01"}, DesiredChange{StartAt: &startAt}, time.Now())
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("default-state sync error = %v, want conflict", err)
	}
}

// TestDesiredStateRejectsInvalidChangeAndCorruptTimestamp verifies desired state rejects invalid change and corrupt timestamp.
func TestDesiredStateRejectsInvalidChangeAndCorruptTimestamp(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	invalid := instruction.ContentState{Mode: instruction.ContentDefault, URLs: []string{"https://example.test"}}
	_, err := store.UpdateDesiredStates(context.Background(), "event-invalid", "test", []string{"display-01"}, DesiredChange{Content: &invalid}, time.Now())
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid desired change error=%v", err)
	}
	if _, err := store.db.Exec(`UPDATE desired_states SET updated_at='not-a-time' WHERE agent_id='display-01'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DesiredState(context.Background(), "display-01"); err == nil {
		t.Fatal("corrupt desired-state timestamp was accepted")
	}
}

// TestDesiredStateReadsOneSnapshot checks that concurrent edits never combine
// one revision's metadata with another revision's playlist or proxy policy.
func TestDesiredStateReadsOneSnapshot(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		for i := 1; i <= 200; i++ {
			origin := fmt.Sprintf("https://revision-%d.example.test", i)
			content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{origin, origin + "/b"}, ProxyAllow: []string{origin}, Interval: instruction.MinPlaylistInterval + i}
			if _, err := store.UpdateDesiredStates(ctx, fmt.Sprintf("event-%d", i), "test", []string{"display-01"}, DesiredChange{Content: &content}, time.Now()); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	// Join the writer even when an inconsistent read makes the test fail early.
	defer func() {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for range 200 {
		record, err := store.DesiredState(ctx, "display-01")
		if err != nil {
			t.Fatal(err)
		}
		if record.Revision == 1 {
			continue
		}
		origin := fmt.Sprintf("https://revision-%d.example.test", record.Revision-1)
		content := record.State.Content
		if content.Interval != instruction.MinPlaylistInterval+int(record.Revision-1) || len(content.URLs) != 2 || content.URLs[0] != origin || len(content.ProxyAllow) != 1 || content.ProxyAllow[0] != origin {
			t.Fatalf("read combined different committed revisions: %#v", record)
		}
	}
}
