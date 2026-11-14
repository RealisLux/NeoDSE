// File purpose: Verifies screen-border schema upgrades preserve deliveries, receipts and constraints.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

func TestScreenBorderMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	if err := createEmptyFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema, err := migrationFiles.ReadFile("migrations/0001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL); INSERT INTO schema_migrations VALUES(1,'2026-11-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	statements, err := prepareStatements(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Store{db: db, statements: statements}
	putTestAgent(t, legacy, "display-01")
	now := time.Now().UTC()
	banner := instruction.NewCommand(instruction.BannerCommand{Message: "notice", Severity: "info", DurationSeconds: 30})
	if _, err := legacy.CreateCommand(ctx, "legacy", "test", []string{"display-01"}, banner, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.SaveReceipt(ctx, "legacy", Receipt{AgentID: "display-01", Status: "received", Operation: "banner", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.CreateCommand(ctx, "legacy-queued", "test", []string{"display-01"}, banner, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	event, err := upgraded.Event(ctx, "legacy")
	if err != nil || len(event.Receipts) != 1 || len(event.Deliveries) != 1 {
		t.Fatalf("migration lost event history: %#v %v", event, err)
	}
	pending, err := upgraded.PendingCommands(ctx, "display-01", now, 10)
	if err != nil || len(pending) != 1 || pending[0].EventID != "legacy-queued" || pending[0].Command != banner {
		t.Fatalf("migration lost pending command: %#v %v", pending, err)
	}
	border := instruction.NewCommand(instruction.BorderCommand{Severity: "warning", DurationSeconds: 30})
	if _, err := upgraded.CreateCommand(ctx, "border", "test", []string{"display-01"}, border, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.SaveReceipt(ctx, "border", Receipt{AgentID: "display-01", Status: "completed", Operation: "border", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.db.ExecContext(ctx, `UPDATE command_receipts SET operation='unknown' WHERE event_id='legacy'`); err == nil {
		t.Fatal("migration lost receipt operation constraint")
	}
	if _, err := upgraded.db.ExecContext(ctx, `UPDATE pending_deliveries SET command_type='unknown' WHERE event_id='legacy-queued'`); err == nil {
		t.Fatal("migration lost command type constraint")
	}
	if _, err := upgraded.db.ExecContext(ctx, `DELETE FROM command_events WHERE event_id IN ('legacy','legacy-queued')`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"command_receipts", "pending_deliveries"} {
		var count int
		if err := upgraded.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE event_id IN ('legacy','legacy-queued')").Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s cascade lost: count=%d error=%v", table, count, err)
		}
	}
}
