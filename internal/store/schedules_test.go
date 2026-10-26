// File purpose: Verifies schedule persistence and atomic schedule-to-display transitions.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// TestScheduleTransitionIsAtomicAndIdempotent verifies schedule transition is atomic and idempotent.
func TestScheduleTransitionIsAtomicAndIdempotent(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	schedule := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	record, err := store.ApplyScheduledDisplay(ctx, schedule, "on", "2026-08-31", "event-schedule", instruction.DisplayOn, now)
	if err != nil || record.Command.Type() != instruction.CommandDisplay {
		t.Fatalf("ApplyScheduledDisplay() record=%#v error=%v", record, err)
	}
	_, err = store.ApplyScheduledDisplay(ctx, schedule, "on", "2026-08-31", "event-repeat", instruction.DisplayOn, now)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated occurrence error = %v, want conflict", err)
	}
	if _, eventErr := store.Event(ctx, "event-repeat"); !errors.Is(eventErr, ErrNotFound) {
		t.Fatalf("repeated transition persisted an event: %v", eventErr)
	}
}

// TestScheduleWarningIsAtomicAndIdempotent verifies warning checkpoint and command persistence.
func TestScheduleWarningIsAtomicAndIdempotent(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	schedule := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 17, 55, 0, 0, time.UTC)
	expiresAt := now.Add(time.Minute)
	command := instruction.NewCommand(instruction.BannerCommand{Message: "Screen will turn off in 5 minutes", Severity: instruction.BannerWarning, DurationSeconds: 300})
	record, err := store.ApplyScheduledWarning(ctx, schedule, "2026-08-31T18:00-warning", "event-warning", command, now, expiresAt)
	if err != nil || record.Command != command || !record.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ApplyScheduledWarning() record=%#v error=%v", record, err)
	}
	pending, err := store.PendingCommands(ctx, schedule.AgentID, now, 10)
	if err != nil || len(pending) != 1 || pending[0].Command != command {
		t.Fatalf("PendingCommands()=%#v error=%v", pending, err)
	}
	_, err = store.ApplyScheduledWarning(ctx, schedule, "2026-08-31T18:00-warning", "event-repeat", command, now, expiresAt)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated warning error=%v, want conflict", err)
	}
	if _, eventErr := store.Event(ctx, "event-repeat"); !errors.Is(eventErr, ErrNotFound) {
		t.Fatalf("repeated warning persisted an event: %v", eventErr)
	}
	stale, err := store.PendingCommands(ctx, schedule.AgentID, expiresAt, 10)
	if err != nil || len(stale) != 0 {
		t.Fatalf("expired warning commands=%#v error=%v", stale, err)
	}
}

// TestScheduleWarningRollbackDoesNotClaimOccurrence verifies a failed insert rolls back its checkpoint.
func TestScheduleWarningRollbackDoesNotClaimOccurrence(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	schedule := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 17, 55, 0, 0, time.UTC)
	if _, err := store.CreateStateEvent(ctx, "event-existing", "test", schedule.AgentID, now); err != nil {
		t.Fatal(err)
	}
	command := instruction.NewCommand(instruction.BannerCommand{Message: "Screen will turn off in 5 minutes", Severity: instruction.BannerWarning, DurationSeconds: 300})
	if _, err := store.ApplyScheduledWarning(ctx, schedule, "2026-08-31T18:00-warning", "event-existing", command, now, now.Add(time.Minute)); err == nil {
		t.Fatal("warning with duplicate event unexpectedly succeeded")
	}
	all, err := store.Schedules(ctx, schedule.AgentID)
	if err != nil || len(all) != 1 || all[0].LastWarningOccurrence != "" {
		t.Fatalf("rolled-back warning schedule=%#v error=%v", all, err)
	}
}

// TestScheduledOperationsRejectInvalidInputs verifies malformed scheduler work is never queued.
func TestScheduledOperationsRejectInvalidInputs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	banner := instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance", Severity: instruction.BannerWarning, DurationSeconds: 30})
	if _, err := store.ApplyScheduledWarning(ctx, Schedule{ID: "schedule-1", AgentID: "display-01"}, "occurrence", "", banner, now, now.Add(time.Minute)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing warning event ID error = %v, want invalid state", err)
	}
	if _, err := store.ApplyScheduledWarning(ctx, Schedule{ID: "schedule-1", AgentID: "display-01"}, "occurrence", "event-warning", instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Minute)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid warning command error = %v, want invalid state", err)
	}
	if _, err := store.ApplyScheduledDisplay(ctx, Schedule{ID: "schedule-1", AgentID: "display-01"}, "on", "occurrence", "event-display", instruction.DisplayOperation("invalid"), now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid display mode error = %v, want invalid state", err)
	}
	if _, err := store.ApplyScheduledDisplay(ctx, Schedule{ID: "schedule-1", AgentID: "display-01"}, "warning", "occurrence", "event-display", instruction.DisplayOn, now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid display occurrence kind error = %v, want invalid state", err)
	}
	if _, err := store.Event(ctx, "event-warning"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid warning persisted an event: %v", err)
	}
}

// TestScheduleCRUDAndOccurrenceKinds verifies schedule crud and occurrence kinds.
func TestScheduleCRUDAndOccurrenceKinds(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	schedule := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday", "friday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	all, err := store.Schedules(ctx, "display-01")
	if err != nil || len(all) != 1 || len(all[0].Days) != 2 {
		t.Fatalf("Schedules()=%#v error=%v", all, err)
	}
	enabled, err := store.EnabledSchedules(ctx)
	if err != nil || len(enabled) != 1 {
		t.Fatalf("EnabledSchedules()=%#v error=%v", enabled, err)
	}
	if _, err := store.ApplyScheduledDisplay(ctx, schedule, "off", "occurrence-1", "event-off", instruction.DisplayOff, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyScheduledWarning(ctx, schedule, "warning-1", "event-warning", instruction.NewCommand(instruction.BannerCommand{Message: "Warning", Severity: instruction.BannerWarning, DurationSeconds: 30}), time.Now(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	schedule.PowerOn = "09:00"
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	all, err = store.Schedules(ctx, "display-01")
	if err != nil || len(all) != 1 || all[0].LastOffOccurrence != "occurrence-1" || all[0].LastWarningOccurrence != "warning-1" {
		t.Fatalf("UpsertSchedule() checkpoints=%#v error=%v", all, err)
	}
	schedule.Enabled = false
	if err := store.UpsertSchedule(ctx, schedule); err != nil {
		t.Fatal(err)
	}
	enabled, err = store.EnabledSchedules(ctx)
	if err != nil || len(enabled) != 0 {
		t.Fatalf("disabled schedule remains enabled: %#v, %v", enabled, err)
	}
	if err := store.DeleteSchedule(ctx, schedule.AgentID, schedule.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSchedule(ctx, schedule.AgentID, schedule.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete error=%v", err)
	}
}

// TestUpsertScheduleCreatesAndReplaces verifies agent-owned schedules replace by agent ID.
func TestUpsertScheduleCreatesAndReplaces(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	job := Schedule{AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := store.UpsertSchedule(ctx, job); err != nil {
		t.Fatal(err)
	}
	job.PowerOn = "09:00"
	if err := store.UpsertSchedule(ctx, job); err != nil {
		t.Fatal(err)
	}
	all, err := store.Schedules(ctx, "display-01")
	if err != nil || len(all) != 1 || all[0].PowerOn != "09:00" {
		t.Fatalf("Schedules()=%#v error=%v", all, err)
	}
}

// TestScheduleEditsPreserveExecutedOccurrences prevents repeated saves from replaying a transition.
func TestScheduleEditsPreserveExecutedOccurrences(t *testing.T) {
	database := openTestStore(t)
	putTestAgent(t, database, "display-01")
	ctx := context.Background()
	job := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if err := database.UpsertSchedule(ctx, job); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	occurrence := "2026-08-31T08:00-on"
	if _, err := database.ApplyScheduledDisplay(ctx, job, "on", occurrence, "first-event", instruction.DisplayOn, now); err != nil {
		t.Fatal(err)
	}
	job.Enabled = false
	for _, enabled := range []bool{false, true} {
		job.Enabled = enabled
		err := database.UpsertSchedule(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
	}
	all, err := database.Schedules(ctx, job.AgentID)
	if err != nil || len(all) != 1 || all[0].LastOnOccurrence != occurrence {
		t.Fatalf("saved schedule lost occurrence: %#v, %v", all, err)
	}
	if _, err := database.ApplyScheduledDisplay(ctx, job, "on", occurrence, "repeated-event", instruction.DisplayOn, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated transition: %v", err)
	}
	if _, err := database.Event(ctx, "repeated-event"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated event persisted: %v", err)
	}
	// A different scheduled time remains eligible after an edit.
	job.PowerOn = "09:00"
	if err := database.UpsertSchedule(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ApplyScheduledDisplay(ctx, job, "on", "2026-08-31T09:00-on", "next-event", instruction.DisplayOn, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// TestChangedScheduleRejectsPreviouslySelectedWork covers edits after scheduler selection.
func TestChangedScheduleRejectsPreviouslySelectedWork(t *testing.T) {
	for _, change := range []string{"disabled", "days", "power on", "power off"} {
		for _, kind := range []string{"on", "off", "warning"} {
			t.Run(change+"/"+kind, func(t *testing.T) {
				database := openTestStore(t)
				putTestAgent(t, database, "display-01")
				ctx := context.Background()
				job := Schedule{ID: "display-01", AgentID: "display-01", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
				if err := database.UpsertSchedule(ctx, job); err != nil {
					t.Fatal(err)
				}
				selected, err := database.EnabledSchedules(ctx)
				if err != nil || len(selected) != 1 {
					t.Fatalf("selected jobs = %#v, %v", selected, err)
				}
				switch change {
				case "disabled":
					job.Enabled = false
				case "days":
					job.Days = []string{"tuesday"}
				case "power on":
					job.PowerOn = "09:00"
				case "power off":
					job.PowerOff = "19:00"
				}
				if err := database.UpsertSchedule(ctx, job); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				if kind == "warning" {
					command := instruction.NewCommand(instruction.BannerCommand{Message: "Warning", Severity: instruction.BannerWarning, DurationSeconds: 30})
					_, err = database.ApplyScheduledWarning(ctx, selected[0], "occurrence", "event-disabled", command, now, now.Add(time.Minute))
				} else {
					_, err = database.ApplyScheduledDisplay(ctx, selected[0], kind, "occurrence", "event-disabled", instruction.DisplayOperation(kind), now)
				}
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("stale work error = %v, want conflict", err)
				}
				if _, err := database.Event(ctx, "event-disabled"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("stale work persisted an event: %v", err)
				}
				jobs, err := database.Schedules(ctx, job.AgentID)
				if err != nil || len(jobs) != 1 || jobs[0].LastOnOccurrence != "" || jobs[0].LastOffOccurrence != "" || jobs[0].LastWarningOccurrence != "" {
					t.Fatalf("stale work changed checkpoints: %#v, %v", jobs, err)
				}
			})
		}
	}
}
