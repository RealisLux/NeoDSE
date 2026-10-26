// File purpose: Loads and atomically updates complete controller-owned display state and its proxy policy.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// DesiredRecord combines durable state with reconciliation metadata.
type DesiredRecord struct {
	AgentID    string
	Generation string
	Revision   uint64
	State      instruction.DesiredState
	UpdatedAt  time.Time
}

// DesiredChange describes the portion of a complete state changed by one typed route.
type DesiredChange struct {
	Content *instruction.ContentState
	StartAt *int64
}

// DesiredState loads metadata, playlist, and policy from one committed snapshot.
func (store *Store) DesiredState(ctx context.Context, agentID string) (DesiredRecord, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DesiredRecord{}, mapSQLError(err)
	}
	defer tx.Rollback()
	record, err := loadDesired(ctx, tx, agentID)
	if err != nil {
		return DesiredRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DesiredRecord{}, mapSQLError(err)
	}
	return record, nil
}

// UpdateDesiredStates records an event and applies one typed state change to every target atomically.
func (store *Store) UpdateDesiredStates(ctx context.Context, eventID, source string, targets []string, change DesiredChange, now time.Time) ([]DesiredRecord, error) {
	if len(targets) == 0 {
		return nil, errorsInvalid("desired-state update has no targets")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO command_events(event_id,source,created_at,updated_at) VALUES(?,?,?,?)`, eventID, source, stamp, stamp); err != nil {
		return nil, err
	}
	records := make([]DesiredRecord, 0, len(targets))
	for _, agentID := range targets {
		record, loadErr := loadDesired(ctx, tx, agentID)
		if loadErr != nil {
			return nil, loadErr
		}
		if change.Content != nil {
			record.State.Content = *change.Content
		}
		if change.StartAt != nil {
			if record.State.Content.Mode != instruction.ContentPlaylist {
				return nil, ErrConflict
			}
			record.State.Content.StartAt = *change.StartAt
		}
		if err := record.State.Validate(); err != nil {
			return nil, errorsInvalid(err.Error())
		}
		record.Revision++
		record.UpdatedAt = now.UTC()
		// The target records the revision it delivers so a later acceptance of
		// this or a newer revision can resolve it after reconnection.
		if _, err = tx.ExecContext(ctx, `INSERT INTO event_targets(event_id,agent_id,desired_generation,desired_revision) VALUES(?,?,?,?)`,
			eventID, agentID, record.Generation, record.Revision); err != nil {
			return nil, err
		}
		if err := replaceDesired(ctx, tx, record, change.Content != nil); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

// loadDesired reads a state and its ordered playlist fields using either a DB or transaction.
func loadDesired(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, agentID string) (DesiredRecord, error) {
	var record DesiredRecord
	var updated string
	err := queryer.QueryRowContext(ctx, `SELECT agent_id,generation,revision,content_mode,interval_seconds,start_at,updated_at FROM desired_states WHERE agent_id=?`, agentID).Scan(
		&record.AgentID, &record.Generation, &record.Revision, &record.State.Content.Mode,
		&record.State.Content.Interval, &record.State.Content.StartAt, &updated,
	)
	if err != nil {
		return record, mapSQLError(err)
	}
	record.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return record, fmt.Errorf("decode desired-state timestamp: %w", err)
	}
	record.State.Content.URLs, err = loadOrderedValues(ctx, queryer, `SELECT url FROM desired_playlist_items WHERE agent_id=? ORDER BY position`, agentID)
	if err != nil {
		return record, err
	}
	record.State.Content.ProxyAllow, err = loadOrderedValues(ctx, queryer, `SELECT url FROM desired_proxy_items WHERE agent_id=? ORDER BY position`, agentID)
	if err != nil {
		return record, err
	}
	if err := record.State.Validate(); err != nil {
		return record, fmt.Errorf("stored desired state is invalid: %w", err)
	}
	return record, nil
}

// loadOrderedValues collects one ordered string column from a child table.
func loadOrderedValues(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query string, agentID string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// replaceDesired updates metadata and replaces content grants only for an explicit publication.
func replaceDesired(ctx context.Context, tx *sql.Tx, record DesiredRecord, replaceContent bool) error {
	_, err := tx.ExecContext(ctx, `UPDATE desired_states SET revision=?,content_mode=?,interval_seconds=?,start_at=?,updated_at=? WHERE agent_id=?`,
		record.Revision, record.State.Content.Mode, record.State.Content.Interval, record.State.Content.StartAt,
		record.UpdatedAt.Format(time.RFC3339Nano), record.AgentID)
	if err != nil {
		return err
	}
	// Synchronizing playback must not restore permissions revoked independently
	// of the saved playlist, or rewrite content that has not changed.
	if !replaceContent {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM desired_playlist_items WHERE agent_id=?`, record.AgentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM desired_proxy_items WHERE agent_id=?`, record.AgentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_policies WHERE agent_id=?`, record.AgentID); err != nil {
		return err
	}
	for position, value := range record.State.Content.URLs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO desired_playlist_items(agent_id,position,url) VALUES(?,?,?)`, record.AgentID, position, value); err != nil {
			return err
		}
	}
	for position, value := range record.State.Content.ProxyAllow {
		if _, err := tx.ExecContext(ctx, `INSERT INTO desired_proxy_items(agent_id,position,url) VALUES(?,?,?)`, record.AgentID, position, value); err != nil {
			return err
		}
	}
	targets, err := record.State.Content.ProxyTargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO proxy_policies(agent_id,target) VALUES(?,?)`, record.AgentID, target); err != nil {
			return err
		}
	}
	return nil
}

// errorsInvalid returns a stable invalid-state error without exposing SQL details.
func errorsInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidState, message)
}
