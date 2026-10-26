// File purpose: Owns the fixed prepared statements used by frequent authenticated controller operations.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"database/sql"
	"errors"
)

// preparedStatements caches query plans only; credentials and policy values are
// always read from SQLite. Statements belong to the store and close with it.
type preparedStatements struct {
	agentPSK       *sql.Stmt
	saveStatus     *sql.Stmt
	receiptInsert  *sql.Stmt
	receiptOutcome *sql.Stmt
	removePending  *sql.Stmt
	eventUpdated   *sql.Stmt
	claimDelivery  *sql.Stmt
	all            []*sql.Stmt
}

// prepareStatements prepares the fixed hot paths before any transaction holds
// the store's single connection. Transaction wrappers are owned by database/sql.
func prepareStatements(ctx context.Context, db *sql.DB) (preparedStatements, error) {
	var p preparedStatements
	queries := []struct {
		destination **sql.Stmt
		query       string
	}{
		{&p.agentPSK, `SELECT psk FROM agent_credentials WHERE agent_id=?`},
		{&p.saveStatus, `INSERT INTO agent_status(agent_id,friendly_name,protocol,hostname,version,status,started_at,uptime_seconds,last_event_id,cec_enabled,cec_power_status,cec_output,cec_checked_at,reported_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET friendly_name=excluded.friendly_name,protocol=excluded.protocol,hostname=excluded.hostname,version=excluded.version,status=excluded.status,started_at=excluded.started_at,uptime_seconds=excluded.uptime_seconds,last_event_id=excluded.last_event_id,cec_enabled=excluded.cec_enabled,cec_power_status=excluded.cec_power_status,cec_output=excluded.cec_output,cec_checked_at=excluded.cec_checked_at,reported_at=excluded.reported_at,last_seen=excluded.last_seen`},
		{&p.receiptInsert, `INSERT INTO command_receipts(event_id,agent_id,status,operation,error,details,value,reported_at) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM event_targets WHERE event_id=? AND agent_id=?) AND NOT EXISTS(SELECT 1 FROM command_receipts WHERE event_id=? AND agent_id=? AND status=?)`},
		{&p.receiptOutcome, `UPDATE event_targets SET delivery_status=?,delivery_reason=substr(?,1,128) WHERE event_id=? AND agent_id=? AND delivery_status IN ('queued','uncertain','received','accepted') AND NOT (delivery_status='accepted' AND ?='received')`},
		{&p.removePending, `DELETE FROM pending_deliveries WHERE event_id=? AND agent_id=?`},
		{&p.eventUpdated, `UPDATE command_events SET updated_at=? WHERE event_id=?`},
		{&p.claimDelivery, `UPDATE event_targets SET delivery_status='uncertain',delivery_reason='awaiting authenticated receipt' WHERE event_id=? AND agent_id=? AND delivery_status='queued' AND EXISTS(SELECT 1 FROM pending_deliveries p WHERE p.event_id=event_targets.event_id AND p.agent_id=event_targets.agent_id AND julianday(p.expires_at)>julianday(?))`},
	}
	for _, query := range queries {
		statement, err := db.PrepareContext(ctx, query.query)
		if err != nil {
			return preparedStatements{}, errors.Join(err, p.close())
		}
		*query.destination = statement
		p.all = append(p.all, statement)
	}
	return p, nil
}

// close releases every prepared statement, including a partially prepared set.
func (p *preparedStatements) close() error {
	var result error
	for _, statement := range p.all {
		result = errors.Join(result, statement.Close())
	}
	return result
}
