// File purpose: Claims delivery attempts durably before any external side effect.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"time"
)

// Delivery describes a controller-owned outcome independently of agent receipts.
type Delivery struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// RecoverDeliveries rejects hardware operations left unattempted by a previous controller.
func (store *Store) RecoverDeliveries(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE event_targets SET delivery_status='rejected',delivery_reason='controller restarted before delivery' WHERE delivery_status='queued' AND (event_id,agent_id) IN (SELECT event_id,agent_id FROM pending_deliveries)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM pending_deliveries`); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimDelivery consumes the only retryable record and records uncertainty in
// the same transaction. Neither process death nor a failed write can reopen it.
func (store *Store) ClaimDelivery(ctx context.Context, eventID, agentID string, now time.Time) (bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.StmtContext(ctx, store.statements.claimDelivery).ExecContext(ctx, eventID, agentID, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return false, err
	}
	if _, err = tx.StmtContext(ctx, store.statements.removePending).ExecContext(ctx, eventID, agentID); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RejectDelivery records an offline hardware action without leaving a retry.
func (store *Store) RejectDelivery(ctx context.Context, eventID, agentID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE event_targets SET delivery_status='rejected',delivery_reason='agent offline' WHERE event_id=? AND agent_id=? AND delivery_status='queued'`, eventID, agentID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM pending_deliveries WHERE event_id=? AND agent_id=? AND EXISTS(SELECT 1 FROM event_targets t WHERE t.event_id=pending_deliveries.event_id AND t.agent_id=pending_deliveries.agent_id AND t.delivery_status='rejected')`, eventID, agentID); err != nil {
		return err
	}
	return tx.Commit()
}

// ExpireDeliveries retains an explicit outcome after queued payloads expire.
func (store *Store) ExpireDeliveries(ctx context.Context, now time.Time) error {
	return store.expireDeliveries(ctx, now, "")
}

// EventAt refreshes expiration before returning the API's current event outcome.
func (store *Store) EventAt(ctx context.Context, eventID string, now time.Time) (EventState, error) {
	if err := store.expireDeliveries(ctx, now, eventID); err != nil {
		return EventState{}, err
	}
	return store.Event(ctx, eventID)
}

// expireDeliveries scopes expiry writes to one event or the retention sweep.
func (store *Store) expireDeliveries(ctx context.Context, now time.Time, eventID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	// Drive the update from the outbox, not retained history. A reconnect storm
	// must not scan every historical target once per agent.
	if _, err = tx.ExecContext(ctx, `UPDATE event_targets SET delivery_status='expired',delivery_reason='delivery expired' WHERE delivery_status='queued' AND (event_id,agent_id) IN (SELECT event_id,agent_id FROM pending_deliveries WHERE julianday(expires_at)<=julianday(?) AND (?='' OR event_id=?))`, stamp, eventID, eventID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM pending_deliveries WHERE julianday(expires_at)<=julianday(?) AND (?='' OR event_id=?)`, stamp, eventID, eventID); err != nil {
		return err
	}
	return tx.Commit()
}

// Deliveries returns stable, durable per-target outcomes for the event API.
func (store *Store) Deliveries(ctx context.Context, eventID string) ([]Delivery, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT agent_id,delivery_status,delivery_reason FROM event_targets WHERE event_id=? ORDER BY agent_id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Delivery, 0)
	for rows.Next() {
		var item Delivery
		if err := rows.Scan(&item.AgentID, &item.Status, &item.Reason); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
