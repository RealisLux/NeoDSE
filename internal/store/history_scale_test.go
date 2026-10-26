// File purpose: Verifies fleet reconciliation remains bounded as retained event history grows.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

func TestReconciliationWithRetainedHistory(t *testing.T) {
	s := openTestStore(t)
	for i := range 100 {
		putTestAgent(t, s, fmt.Sprintf("display-%03d", i))
	}
	retained, budget := historyScale(t)
	// Seed completed history in one transaction; the measured phase executes
	// production store operations, with the controller's six-second budget.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<?)
		INSERT INTO command_events SELECT printf('history-%06d',n),'test',?,? FROM seq`, retained, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO event_targets(event_id,agent_id,delivery_status)
		SELECT event_id,'display-000','completed' FROM command_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO command_receipts(event_id,agent_id,status,operation,reported_at)
		SELECT event_id,agent_id,'completed','desired_state',? FROM event_targets`, stamp); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Offline targets leave a nonempty outbox during a real fleet reconnect.
	// An empty subquery can hide history scans in an otherwise slow query plan.
	for i := range 100 {
		command := instruction.NewCommand(instruction.BannerCommand{Message: "waiting", Severity: "info", DurationSeconds: 1})
		if _, err := s.CreateCommand(context.Background(), fmt.Sprintf("pending-%03d", i), "test", []string{"display-099"}, command, time.Now(), time.Now().Add(5*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	started := time.Now()
	var workers sync.WaitGroup
	failures := make(chan error, 100)
	for i := range 100 {
		workers.Go(func() {
			agentID := fmt.Sprintf("display-%03d", i)
			eventID := fmt.Sprintf("reconciliation-%03d", i)
			if _, err := s.CreateStateEvent(ctx, eventID, "reconciliation", agentID, time.Now()); err != nil {
				failures <- err
				return
			}
			if _, err := s.PendingCommands(ctx, agentID, time.Now(), 128); err != nil {
				failures <- err
				return
			}
			if _, err := s.Event(ctx, eventID); err != nil {
				failures <- err
			}
		})
	}
	workers.Wait()
	close(failures)
	t.Logf("100 reconciliations with %d retained targets and receipts completed in %s", retained, time.Since(started))
	if len(failures) != 0 {
		t.Fatalf("%d reconciliations failed; first error: %v", len(failures), <-failures)
	}
	// Broadcasting and receipt persistence share the same connection as
	// reconciliation. Retained history must not make these writes scan history.
	ctx, cancel = context.WithTimeout(context.Background(), budget)
	defer cancel()
	targets := make([]string, 100)
	for i := range targets {
		targets[i] = fmt.Sprintf("display-%03d", i)
	}
	started = time.Now()
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://display.example/integration"}}
	if _, err := s.UpdateDesiredStates(ctx, "broadcast-history", "test", targets, DesiredChange{Content: &content}, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Logf("100-target state publication with retained history completed in %s", time.Since(started))
	started = time.Now()
	for _, agentID := range targets {
		if _, err := s.SaveReceipt(ctx, "broadcast-history", Receipt{AgentID: agentID, Status: "completed", Operation: "desired_state", Timestamp: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("100 receipts with retained history completed in %s", time.Since(started))
}

// historyScale returns the retained history and the time budget for the measured
// phases. The race detector slows the SQLite engine by more than an order of
// magnitude, so that run keeps a tenth of the history and five times the budget:
// it checks concurrency, while the plain run checks the scale and the
// controller's six-second budget.
func historyScale(t *testing.T) (retained int, budget time.Duration) {
	t.Helper()
	if raceDetectorEnabled(t) {
		return 5000, 30 * time.Second
	}
	return 50000, 6 * time.Second
}

// raceDetectorEnabled records the actual compiler setting rather than trusting an environment label.
func raceDetectorEnabled(t *testing.T) bool {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("test binary build information unavailable")
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}
