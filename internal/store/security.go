// File purpose: Persists proxy authorization and performs bounded event cleanup.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Retention defines the event cleanup period.
type Retention struct {
	Events time.Duration
}

const retentionBatchSize = 32

// ProxyAllowed reports whether an exact canonical target is currently authorized.
func (store *Store) ProxyAllowed(ctx context.Context, agentID, target string) (bool, error) {
	var value int
	err := store.db.QueryRowContext(ctx, `SELECT 1 FROM proxy_policies WHERE agent_id=? AND target=?`, agentID, target).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, mapSQLError(err)
}

// RevokeProxyPolicy removes every remote destination authorized for an agent.
func (store *Store) RevokeProxyPolicy(ctx context.Context, agentID string) (bool, error) {
	result, err := store.db.ExecContext(ctx, `DELETE FROM proxy_policies WHERE agent_id=?`, agentID)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

// Cleanup releases the connection between small retention batches so live
// operations can progress even when a stopped controller accumulated history.
func (store *Store) Cleanup(ctx context.Context, now time.Time, retention Retention) error {
	if retention.Events <= 0 {
		return errorsInvalid("retention durations must be positive")
	}
	queries := []struct {
		query  string
		cutoff time.Time
	}{
		{`DELETE FROM command_events WHERE event_id IN (SELECT event_id FROM command_events WHERE created_at<? AND julianday(created_at)<julianday(?) ORDER BY created_at,event_id LIMIT ?)`, now.Add(-retention.Events)},
	}
	for _, item := range queries {
		for {
			// Each statement is an atomic transaction, including foreign-key
			// cascades. A later failure leaves earlier batches safely committed.
			// Keep the indexed range scan, then compare actual times within
			// the cutoff second; RFC3339Nano strings are not lexically ordered.
			upper := item.cutoff.UTC().Truncate(time.Second).Add(time.Second)
			result, err := store.db.ExecContext(ctx, item.query, upper.Format(time.RFC3339), item.cutoff.UTC().Format(time.RFC3339Nano), retentionBatchSize)
			if err != nil {
				return err
			}
			removed, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if removed < retentionBatchSize {
				break
			}
		}
	}
	return store.ExpireDeliveries(ctx, now)
}
