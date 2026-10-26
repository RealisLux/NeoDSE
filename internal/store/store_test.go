// File purpose: Verifies database creation, agent lifecycle, durable restoration, and test-store setup.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestStoppedDatabaseBackupRestoresAuthority verifies a copied backup on a distinct path.
func TestStoppedDatabaseBackupRestoresAuthority(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now().UTC()
	psk := strings.Repeat("ab", 32)
	if err := database.PutAgent(ctx, "display", psk, "10.99.0.2", false, now); err != nil {
		t.Fatal(err)
	}
	account, token, err := database.CreateAccount(ctx, AccountInput{Name: "viewer", Roles: []string{"viewer"}, Agents: []string{"display"}}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://display.example/"}}
	if _, err := database.UpdateDesiredStates(ctx, "content", "test", []string{"display"}, DesiredChange{Content: &content}, now); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertSchedule(ctx, Schedule{AgentID: "display", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateCommand(ctx, "hardware", "test", []string{"display"}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if claimed, err := database.ClaimDelivery(ctx, "hardware", "display", now); err != nil || !claimed {
		t.Fatalf("claim: %t %v", claimed, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restoredPath, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, restoredPath, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	auth, err := restored.AuthenticateAccount(ctx, strings.Split(token, "_")[1], token, now)
	if err != nil || auth.AccountID != account.ID || auth.AllAgents || len(auth.Agents) != 1 || auth.Agents[0] != "display" || len(auth.Roles) != 1 || auth.Roles[0] != "viewer" {
		t.Fatalf("restored scope differs: %#v %v", auth, err)
	}
	if got, err := restored.AgentPSK(ctx, "display"); err != nil || got != psk {
		t.Fatal("agent credential was not restored")
	}
	state, err := restored.DesiredState(ctx, "display")
	if err != nil || state.State.Content.Mode != content.Mode || len(state.State.Content.URLs) != 1 || state.State.Content.URLs[0] != content.URLs[0] {
		t.Fatalf("desired content was not restored: %#v %v", state, err)
	}
	if allowed, err := restored.ProxyAllowed(ctx, "display", "https://display.example:443"); err != nil || !allowed {
		t.Fatal("proxy policy was not restored")
	}
	if jobs, err := restored.EnabledSchedules(ctx); err != nil || len(jobs) != 1 || jobs[0].AgentID != "display" {
		t.Fatalf("schedule was not restored: %#v %v", jobs, err)
	}
	if err := restored.RecoverDeliveries(ctx); err != nil {
		t.Fatal(err)
	}
	if queued, err := restored.PendingCommands(ctx, "display", now, 128); err != nil || len(queued) != 0 {
		t.Fatalf("restore reopened an attempted hardware action: %#v %v", queued, err)
	}
	event, err := restored.Event(ctx, "hardware")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "uncertain" {
		t.Fatalf("restore lost uncertainty: %#v %v", event, err)
	}
}

// TestAgentStateSurvivesDatabaseReopen verifies agent state survives database reopen.
func TestAgentStateSurvivesDatabaseReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	if err := store.PutAgent(ctx, "display-01", strings.Repeat("ab", 32), "10.99.0.2", false, now); err != nil {
		t.Fatal(err)
	}
	initial, err := store.DesiredState(ctx, "display-01")
	if err != nil {
		t.Fatal(err)
	}
	if initial.State.Content.Mode != instruction.ContentDefault || len(initial.State.Content.URLs) != 0 || len(initial.State.Content.ProxyAllow) != 0 {
		t.Fatalf("unsafe initial state: %#v", initial.State)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restored, err := reopened.DesiredState(ctx, "display-01")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Generation != initial.Generation || restored.Revision != initial.Revision || restored.State.Content.Mode != initial.State.Content.Mode {
		t.Fatalf("restored state = %#v, want %#v", restored, initial)
	}
}

// TestOpenRejectsInvalidMigrationHistory verifies open rejects invalid migration history.
func TestOpenRejectsInvalidMigrationHistory(t *testing.T) {
	for name, versions := range map[string][]int{"newer": {3}, "gap": {1, 3}} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller.db")
			if err := createEmptyFile(path); err != nil {
				t.Fatal(err)
			}
			database, err := openDatabase(context.Background(), path, testKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			for _, version := range versions {
				if _, err := database.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(context.Background(), path, testKey); err == nil {
				_ = opened.Close()
				t.Fatal("invalid migration history was accepted")
			}
		})
	}
}

// TestAgentQueriesAndStatusProjection verifies agent queries and status projection.
func TestAgentQueriesAndStatusProjection(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-b")
	putTestAgent(t, store, "display-a")
	ctx := context.Background()
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	identifiers, err := store.AgentIDs(ctx)
	if err != nil || strings.Join(identifiers, ",") != "display-a,display-b" {
		t.Fatalf("AgentIDs()=%v error=%v", identifiers, err)
	}
	exists, err := store.AgentExists(ctx, "display-a")
	if err != nil || !exists {
		t.Fatalf("AgentExists()=%t error=%v", exists, err)
	}
	psk, err := store.AgentPSK(ctx, "display-a")
	if err != nil || len(psk) != 64 {
		t.Fatalf("AgentPSK() length=%d error=%v", len(psk), err)
	}
	now := time.Now().UTC()
	report := protocol.Status{Protocol: protocol.Version, AgentID: "display-a", Hostname: "screen.local", Version: "1.0.0", Status: "online", StartedAt: now.Add(-time.Hour).Format(time.RFC3339), UptimeSeconds: 3600, CECEnabled: true, CECPower: "on", CECOutput: "power status: on", CECCheckedAt: now.Format(time.RFC3339Nano), Timestamp: now.Format(time.RFC3339Nano)}
	if err := store.SaveStatus(ctx, report, now); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.AgentStatuses(ctx)
	if err != nil || len(statuses) != 2 || statuses[0].Hostname != "screen.local" || statuses[0].Status != "offline" {
		t.Fatalf("AgentStatuses()=%#v error=%v", statuses, err)
	}
	cec, err := store.CECStatus(ctx, "display-a")
	if err != nil || !cec.CECEnabled || cec.CECPower != "on" || cec.CECOutput != "power status: on" || cec.CECCheckedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("CECStatus()=%#v error=%v", cec, err)
	}
}

// TestAgentLifecycleReturnsTypedErrors verifies agent lifecycle returns typed errors.
func TestAgentLifecycleReturnsTypedErrors(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	putTestAgent(t, store, "display-01")
	if err := store.PutAgent(ctx, "display-01", strings.Repeat("cd", 32), "10.99.0.2", false, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate agent error = %v, want conflict", err)
	}
	if address, err := store.AgentTunnelAddress(ctx, "display-01"); err != nil || address != "10.99.0.2" {
		t.Fatalf("enrolled tunnel address=%q error=%v", address, err)
	}
	if err := store.PutAgent(ctx, "display-01", strings.Repeat("cd", 32), "10.99.0.7", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if psk, err := store.AgentPSK(ctx, "display-01"); err != nil || psk != strings.Repeat("cd", 32) {
		t.Fatalf("rotated agent PSK=%q error=%v", psk, err)
	}
	if address, err := store.AgentTunnelAddress(ctx, "display-01"); err != nil || address != "10.99.0.7" {
		t.Fatalf("re-enrolled tunnel address=%q error=%v", address, err)
	}
	if err := store.PutAgent(ctx, "display-02", strings.Repeat("cd", 32), "", false, time.Now()); err == nil {
		t.Fatal("agent without a tunnel address was enrolled")
	}
	if _, err := store.AgentTunnelAddress(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing agent address error = %v, want not found", err)
	}
	if err := store.RemoveAgent(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing agent error = %v, want not found", err)
	}
	if err := store.RemoveAgent(ctx, "display-01"); err != nil {
		t.Fatal(err)
	}
	if exists, err := store.AgentExists(ctx, "display-01"); err != nil || exists {
		t.Fatalf("removed agent exists=%t error=%v", exists, err)
	}
	if _, err := store.DesiredState(ctx, "display-01"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cascaded desired state error = %v, want not found", err)
	}
}

// TestReplacementConnectionsRetainSQLiteSecurityPragmas verifies replacement
// connections preserve confinement and can reprepare authenticated operations.
func TestReplacementConnectionsRetainSQLiteSecurityPragmas(t *testing.T) {
	db := openTestStore(t)
	db.db.SetMaxIdleConns(0)
	for _, check := range []struct {
		query string
		want  int
	}{{"PRAGMA foreign_keys", 1}, {"PRAGMA trusted_schema", 0}, {"PRAGMA synchronous", 2}, {"PRAGMA busy_timeout", 5000}} {
		var got int
		if err := db.db.QueryRow(check.query).Scan(&got); err != nil || got != check.want {
			t.Fatalf("%s = %d, error %v", check.query, got, err)
		}
	}
	if _, err := db.db.Exec(`INSERT INTO event_targets(event_id,agent_id) VALUES('missing','missing')`); err == nil {
		t.Fatal("replacement connection disabled foreign keys")
	}
	putTestAgent(t, db, "display-01")
	ctx := context.Background()
	for _, key := range []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)} {
		if err := db.PutAgent(ctx, "display-01", key, "10.99.0.2", true, time.Now()); err != nil {
			t.Fatal(err)
		}
		if actual, err := db.AgentPSK(ctx, "display-01"); err != nil || actual != key {
			t.Fatalf("prepared credential lookup on replacement connection failed: %v", err)
		}
	}
	now := time.Now()
	if _, err := db.CreateCommand(ctx, "replacement", "test", []string{"display-01"}, instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if claimed, err := db.ClaimDelivery(ctx, "replacement", "display-01", now); err != nil || !claimed {
		t.Fatalf("prepared delivery claim on replacement connection: claimed=%v error=%v", claimed, err)
	}
	if _, err := db.SaveReceipt(ctx, "replacement", Receipt{AgentID: "display-01", Status: "completed", Operation: "restart", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	event, err := db.Event(ctx, "replacement")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "completed" {
		t.Fatalf("prepared receipt on replacement connection: event=%+v error=%v", event, err)
	}
}

// TestOpenRejectsDirectoryPath verifies open rejects directory path.
func TestOpenRejectsDirectoryPath(t *testing.T) {
	if store, err := Open(context.Background(), t.TempDir(), testKey); err == nil {
		_ = store.Close()
		t.Fatal("directory path was accepted as a database")
	}
}

// TestStoreNilCloseAndClosedPing verifies store nil close and closed ping.
func TestStoreNilCloseAndClosedPing(t *testing.T) {
	var absent *Store
	if err := absent.Close(); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("closed database reported ready")
	}
}

// TestClosedStoreReturnsUnavailable verifies closed store returns unavailable.
func TestClosedStoreReturnsUnavailable(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store ping error = %v, want unavailable", err)
	}
	if _, err := store.AgentPSK(context.Background(), "display-01"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store query error = %v, want unavailable", err)
	}
	if _, err := store.AgentExists(context.Background(), "display-01"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store existence error = %v, want unavailable", err)
	}
}

// testKey is the fixed database key shared by store tests.
var testKey = bytes.Repeat([]byte{0x42}, KeySize)

// openTestStore creates an isolated migrated database and registers cleanup.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Create(context.Background(), filepath.Join(t.TempDir(), "controller.db"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// putTestAgent provisions one deterministic agent for dependent store tests.
func putTestAgent(t *testing.T, store *Store, agentID string) {
	t.Helper()
	if err := store.PutAgent(context.Background(), agentID, strings.Repeat("ab", 32), "10.99.0.2", false, time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}
