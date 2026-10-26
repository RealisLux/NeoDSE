// File purpose: Persists provisioned agent credentials and the latest authenticated status reported by each agent.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// AgentStatus is the durable status projection returned after controller restarts.
type AgentStatus struct {
	AgentID       string
	FriendlyName  string
	Protocol      int
	Hostname      string
	Version       string
	Status        string
	StartedAt     string
	UptimeSeconds uint64
	LastEventID   string
	CECEnabled    bool
	CECPower      string
	CECOutput     string
	CECCheckedAt  string
	ReportedAt    string
	LastSeen      time.Time
}

// PutAgent creates an agent and its safe state, or rotates its PSK and tunnel
// address when replace is true. The tunnel address is the WireGuard address
// assigned at enrollment; transport connections must originate from it.
func (store *Store) PutAgent(ctx context.Context, agentID, psk, tunnelAddress string, replace bool, now time.Time) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM agent_credentials WHERE agent_id=?`, agentID).Scan(&exists)
	switch {
	case err == nil && !replace:
		return ErrConflict
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return err
	case err == nil:
		if _, err = tx.ExecContext(ctx, `UPDATE agent_credentials SET psk=?,tunnel_address=?,updated_at=? WHERE agent_id=?`, psk, tunnelAddress, now.UTC().Format(time.RFC3339Nano), agentID); err != nil {
			return err
		}
	case errors.Is(err, sql.ErrNoRows):
		stamp := now.UTC().Format(time.RFC3339Nano)
		if _, err = tx.ExecContext(ctx, `INSERT INTO agent_credentials(agent_id,psk,tunnel_address,created_at,updated_at) VALUES(?,?,?,?,?)`, agentID, psk, tunnelAddress, stamp, stamp); err != nil {
			return err
		}
		generation := make([]byte, 16)
		if _, err = rand.Read(generation); err != nil {
			return err
		}
		state := instruction.DefaultState()
		if _, err = tx.ExecContext(ctx, `INSERT INTO desired_states(agent_id,generation,revision,content_mode,interval_seconds,start_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			agentID, hex.EncodeToString(generation), 1, state.Content.Mode, 0, 0, stamp); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RemoveAgent deletes an agent and all dependent operational records.
func (store *Store) RemoveAgent(ctx context.Context, agentID string) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM agent_credentials WHERE agent_id=?`, agentID)
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

// AgentPSK returns the provisioned pre-shared key for protocol authentication.
func (store *Store) AgentPSK(ctx context.Context, agentID string) (string, error) {
	var psk string
	err := store.statements.agentPSK.QueryRowContext(ctx, agentID).Scan(&psk)
	return psk, mapSQLError(err)
}

// AgentTunnelAddress returns the WireGuard address assigned at enrollment.
func (store *Store) AgentTunnelAddress(ctx context.Context, agentID string) (string, error) {
	var address string
	err := store.db.QueryRowContext(ctx, `SELECT tunnel_address FROM agent_credentials WHERE agent_id=?`, agentID).Scan(&address)
	return address, mapSQLError(err)
}

// AgentExists reports whether an identifier is provisioned without exposing its secret.
func (store *Store) AgentExists(ctx context.Context, agentID string) (bool, error) {
	var value int
	err := store.db.QueryRowContext(ctx, `SELECT 1 FROM agent_credentials WHERE agent_id=?`, agentID).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, mapSQLError(err)
}

// AgentIDs returns every provisioned agent in stable identifier order.
func (store *Store) AgentIDs(ctx context.Context) ([]string, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT agent_id FROM agent_credentials ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identifiers []string
	for rows.Next() {
		var identifier string
		if err := rows.Scan(&identifier); err != nil {
			return nil, err
		}
		identifiers = append(identifiers, identifier)
	}
	return identifiers, rows.Err()
}

// AgentStatuses returns every provisioned agent with an offline durable projection.
func (store *Store) AgentStatuses(ctx context.Context) ([]AgentStatus, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT c.agent_id,COALESCE(st.friendly_name,''),COALESCE(st.protocol,?),COALESCE(st.hostname,''),COALESCE(st.version,''),COALESCE(st.status,'offline'),COALESCE(st.started_at,''),COALESCE(st.uptime_seconds,0),COALESCE(st.last_event_id,''),COALESCE(st.cec_enabled,0),COALESCE(st.cec_power_status,'unknown'),COALESCE(st.cec_output,''),COALESCE(st.cec_checked_at,''),COALESCE(st.reported_at,''),COALESCE(st.last_seen,'') FROM agent_credentials c LEFT JOIN agent_status st ON st.agent_id=c.agent_id ORDER BY c.agent_id`, protocol.Version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AgentStatus
	for rows.Next() {
		var record AgentStatus
		var lastSeen string
		if err := rows.Scan(&record.AgentID, &record.FriendlyName, &record.Protocol, &record.Hostname, &record.Version, &record.Status, &record.StartedAt, &record.UptimeSeconds, &record.LastEventID, &record.CECEnabled, &record.CECPower, &record.CECOutput, &record.CECCheckedAt, &record.ReportedAt, &lastSeen); err != nil {
			return nil, err
		}
		record.Status = "offline"
		record.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		records = append(records, record)
	}
	return records, rows.Err()
}

// SaveStatus replaces the latest authenticated status for one provisioned agent.
func (store *Store) SaveStatus(ctx context.Context, status protocol.Status, seenAt time.Time) error {
	_, err := store.statements.saveStatus.ExecContext(ctx,
		status.AgentID, status.FriendlyName, status.Protocol, status.Hostname, status.Version, status.Status, status.StartedAt, status.UptimeSeconds, status.LastEventID, status.CECEnabled, status.CECPower, status.CECOutput, status.CECCheckedAt, status.Timestamp, seenAt.UTC().Format(time.RFC3339Nano))
	return err
}

// CECStatus returns the latest CEC configuration and power probe reported by an agent.
func (store *Store) CECStatus(ctx context.Context, agentID string) (AgentStatus, error) {
	var record AgentStatus
	err := store.db.QueryRowContext(ctx, `SELECT agent_id,cec_enabled,cec_power_status,cec_output,cec_checked_at FROM agent_status WHERE agent_id=?`, agentID).Scan(&record.AgentID, &record.CECEnabled, &record.CECPower, &record.CECOutput, &record.CECCheckedAt)
	return record, mapSQLError(err)
}
