// File purpose: Persists display schedules and their last executed occurrences.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// Schedule is the complete durable schedule record.
type Schedule struct {
	ID                    string   `json:"-"`
	AgentID               string   `json:"-"`
	Days                  []string `json:"days"`
	PowerOn               string   `json:"power_on"`
	PowerOff              string   `json:"power_off"`
	Enabled               bool     `json:"enabled"`
	ReminderEnabled       bool     `json:"reminder_enabled"`
	LastOnOccurrence      string   `json:"last_on_occurrence,omitempty"`
	LastOffOccurrence     string   `json:"last_off_occurrence,omitempty"`
	LastWarningOccurrence string   `json:"-"`
}

// Schedules returns an agent's single optional schedule in stable identifier order.
func (store *Store) Schedules(ctx context.Context, agentID string) ([]Schedule, error) {
	return store.querySchedules(ctx, `SELECT id,agent_id,days,power_on,power_off,enabled,reminder_enabled,COALESCE(last_on_occurrence,''),COALESCE(last_off_occurrence,''),COALESCE(last_warning_occurrence,'') FROM schedules WHERE agent_id=? ORDER BY id`, agentID)
}

// EnabledSchedules returns all jobs considered by the scheduler.
func (store *Store) EnabledSchedules(ctx context.Context) ([]Schedule, error) {
	return store.querySchedules(ctx, `SELECT id,agent_id,days,power_on,power_off,enabled,reminder_enabled,COALESCE(last_on_occurrence,''),COALESCE(last_off_occurrence,''),COALESCE(last_warning_occurrence,'') FROM schedules WHERE enabled=1 ORDER BY id`)
}

// UpsertSchedule creates or replaces the schedule identified by its agent ID.
func (store *Store) UpsertSchedule(ctx context.Context, schedule Schedule) error {
	days, err := json.Marshal(schedule.Days)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO schedules(id,agent_id,days,power_on,power_off,enabled,reminder_enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET days=excluded.days,power_on=excluded.power_on,power_off=excluded.power_off,enabled=excluded.enabled,reminder_enabled=excluded.reminder_enabled`,
		schedule.AgentID, schedule.AgentID, string(days), schedule.PowerOn, schedule.PowerOff, schedule.Enabled, schedule.ReminderEnabled)
	return err
}

// DeleteSchedule removes one agent-owned schedule.
func (store *Store) DeleteSchedule(ctx context.Context, agentID, id string) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM schedules WHERE id=? AND agent_id=?`, id, agentID)
	return requireChanged(result, err)
}

// ApplyScheduledWarning atomically checkpoints and queues one expiring banner.
func (store *Store) ApplyScheduledWarning(ctx context.Context, job Schedule, occurrence, eventID string, command instruction.Command, now, expiresAt time.Time) (PendingCommand, error) {
	var record PendingCommand
	scheduleID, agentID := job.ID, job.AgentID
	if eventID == "" || len(eventID) > 128 || !expiresAt.After(now) {
		return record, errorsInvalid("scheduled warning metadata is incomplete")
	}
	if command.Type() != instruction.CommandBanner || command.Validate() != nil {
		return record, errorsInvalid("scheduled warning command is invalid")
	}
	commandJSON, err := encodeStoredCommand(command)
	if err != nil {
		return record, errorsInvalid("scheduled warning command cannot be stored")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return record, err
	}
	defer tx.Rollback()
	if err := checkScheduleSnapshot(ctx, tx, job); err != nil {
		return record, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE schedules SET last_warning_occurrence=? WHERE id=? AND agent_id=? AND enabled=1 AND COALESCE(last_warning_occurrence,'')<>?`, occurrence, scheduleID, agentID, occurrence)
	if err != nil {
		return record, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return record, ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	expiry := expiresAt.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO command_events(event_id,source,created_at,updated_at) VALUES(?,?,?,?)`, eventID, "schedule:"+scheduleID, stamp, stamp); err != nil {
		return record, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO event_targets(event_id,agent_id) VALUES(?,?)`, eventID, agentID); err != nil {
		return record, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO pending_deliveries(event_id,agent_id,command_type,command_json,expires_at,created_at) VALUES(?,?,?,?,?,?)`, eventID, agentID, command.Type(), commandJSON, expiry, stamp); err != nil {
		return record, err
	}
	if err = tx.Commit(); err != nil {
		return record, err
	}
	return PendingCommand{EventID: eventID, AgentID: agentID, Command: command, CreatedAt: now.UTC(), ExpiresAt: expiresAt.UTC()}, nil
}

// ApplyScheduledDisplay queues an expiring HDMI-CEC command with its occurrence checkpoint.
func (store *Store) ApplyScheduledDisplay(ctx context.Context, job Schedule, kind, occurrence, eventID string, display instruction.DisplayOperation, now time.Time) (PendingCommand, error) {
	var record PendingCommand
	scheduleID, agentID := job.ID, job.AgentID
	if !display.Valid() {
		return record, errorsInvalid("scheduled display mode is invalid")
	}
	if kind != "on" && kind != "off" {
		return record, errorsInvalid("schedule occurrence kind is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return record, err
	}
	defer tx.Rollback()
	if err := checkScheduleSnapshot(ctx, tx, job); err != nil {
		return record, err
	}
	var result interface {
		RowsAffected() (int64, error)
	}
	if kind == "on" {
		result, err = tx.ExecContext(ctx, `UPDATE schedules SET last_on_occurrence=? WHERE id=? AND agent_id=? AND enabled=1 AND COALESCE(last_on_occurrence,'')<>?`, occurrence, scheduleID, agentID, occurrence)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE schedules SET last_off_occurrence=? WHERE id=? AND agent_id=? AND enabled=1 AND COALESCE(last_off_occurrence,'')<>?`, occurrence, scheduleID, agentID, occurrence)
	}
	if err != nil {
		return record, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return record, ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO command_events(event_id,source,created_at,updated_at) VALUES(?,?,?,?)`, eventID, "schedule:"+scheduleID, stamp, stamp); err != nil {
		return record, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO event_targets(event_id,agent_id) VALUES(?,?)`, eventID, agentID); err != nil {
		return record, err
	}
	command := instruction.NewCommand(instruction.DisplayCommand{Operation: display})
	commandJSON, err := encodeStoredCommand(command)
	if err != nil {
		return record, err
	}
	// This bounds an unclaimed record; dispatch rejects offline power operations immediately.
	expiresAt := now.UTC().Add(5 * time.Minute)
	if _, err = tx.ExecContext(ctx, `INSERT INTO pending_deliveries(event_id,agent_id,command_type,command_json,expires_at,created_at) VALUES(?,?,?,?,?,?)`, eventID, agentID, command.Type(), commandJSON, expiresAt.Format(time.RFC3339Nano), stamp); err != nil {
		return record, err
	}
	if err = tx.Commit(); err != nil {
		return record, err
	}
	return PendingCommand{EventID: eventID, AgentID: agentID, Command: command, CreatedAt: now.UTC(), ExpiresAt: expiresAt}, nil
}

// querySchedules decodes normalized schedule rows from a fixed query.
func (store *Store) querySchedules(ctx context.Context, query string, arguments ...any) ([]Schedule, error) {
	rows, err := store.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	schedules := make([]Schedule, 0)
	for rows.Next() {
		var schedule Schedule
		var days string
		if err := rows.Scan(&schedule.ID, &schedule.AgentID, &days, &schedule.PowerOn, &schedule.PowerOff, &schedule.Enabled, &schedule.ReminderEnabled, &schedule.LastOnOccurrence, &schedule.LastOffOccurrence, &schedule.LastWarningOccurrence); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(days), &schedule.Days); err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

// requireChanged maps an empty update or delete to ErrNotFound.
func requireChanged(result interface {
	RowsAffected() (int64, error)
}, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// checkScheduleSnapshot rejects work selected before a schedule was disabled or edited.
// The caller holds an immediate transaction through checkpoint and queue insertion.
func checkScheduleSnapshot(ctx context.Context, tx *sql.Tx, job Schedule) error {
	days, err := json.Marshal(job.Days)
	if err != nil {
		return err
	}
	var matches bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schedules WHERE id=? AND agent_id=? AND enabled=1 AND days=? AND power_on=? AND power_off=? AND reminder_enabled=?)`, job.ID, job.AgentID, string(days), job.PowerOn, job.PowerOff, job.ReminderEnabled).Scan(&matches)
	if err != nil {
		return err
	}
	if !matches {
		return ErrConflict
	}
	return nil
}
