// File purpose: Persists transient commands, event targets, delivery attempts, and authenticated receipts.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// maxStoredCommandBytes accommodates worst-case JSON escaping of every validated command.
const maxStoredCommandBytes = 32 * 1024

// PendingCommand is a durable transient operation awaiting delivery.
type PendingCommand struct {
	EventID   string
	AgentID   string
	Command   instruction.Command
	CreatedAt time.Time
	ExpiresAt time.Time
}

// EventState is the durable API projection for a dispatched operation.
type EventState struct {
	EventID    string     `json:"event_id"`
	Targets    []string   `json:"targets"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Receipts   []Receipt  `json:"receipts"`
	Deliveries []Delivery `json:"deliveries"`
}

// Receipt is the durable public outcome of one authenticated agent operation.
type Receipt struct {
	AgentID   string    `json:"agent_id"`
	Status    string    `json:"status"`
	Operation string    `json:"operation,omitempty"`
	Error     string    `json:"error,omitempty"`
	Details   string    `json:"details,omitempty"`
	Value     string    `json:"value,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// CreateStateEvent atomically records a reconciliation target and returns the
// exact complete snapshot it describes, before any network delivery.
func (store *Store) CreateStateEvent(ctx context.Context, eventID, source, agentID string, now time.Time) (DesiredRecord, error) {
	if eventID == "" || len(eventID) > 128 || source == "" || len(source) > 128 || agentID == "" || len(agentID) > 128 {
		return DesiredRecord{}, errorsInvalid("desired-state event metadata is incomplete")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DesiredRecord{}, err
	}
	defer tx.Rollback()
	record, err := loadDesired(ctx, tx, agentID)
	if err != nil {
		return DesiredRecord{}, err
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO command_events(event_id,source,created_at,updated_at) VALUES(?,?,?,?)`, eventID, source, stamp, stamp); err != nil {
		return DesiredRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO event_targets(event_id,agent_id,desired_generation,desired_revision) VALUES(?,?,?,?)`,
		eventID, agentID, record.Generation, record.Revision); err != nil {
		return DesiredRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DesiredRecord{}, err
	}
	return record, nil
}

// CreateCommand records one transient command for every target before delivery.
func (store *Store) CreateCommand(ctx context.Context, eventID, source string, targets []string, command instruction.Command, now, expiresAt time.Time) ([]PendingCommand, error) {
	if len(targets) == 0 || eventID == "" || !expiresAt.After(now) {
		return nil, errorsInvalid("command metadata is incomplete")
	}
	if err := command.Validate(); err != nil {
		return nil, errorsInvalid(err.Error())
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	expiry := expiresAt.UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO command_events(event_id,source,created_at,updated_at) VALUES(?,?,?,?)`, eventID, source, stamp, stamp); err != nil {
		return nil, err
	}
	records := make([]PendingCommand, 0, len(targets))
	commandJSON, err := encodeStoredCommand(command)
	if err != nil {
		return nil, errorsInvalid("command payload cannot be stored")
	}
	for _, agentID := range targets {
		if _, err = tx.ExecContext(ctx, `INSERT INTO event_targets(event_id,agent_id) VALUES(?,?)`, eventID, agentID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO pending_deliveries(event_id,agent_id,command_type,command_json,expires_at,created_at) VALUES(?,?,?,?,?,?)`, eventID, agentID, command.Type(), commandJSON, expiry, stamp); err != nil {
			return nil, err
		}
		records = append(records, PendingCommand{EventID: eventID, AgentID: agentID, Command: command, CreatedAt: now.UTC(), ExpiresAt: expiresAt.UTC()})
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return records, nil
}

// PendingCommands returns unexpired operations in stable delivery order.
func (store *Store) PendingCommands(ctx context.Context, agentID string, now time.Time, limit int) ([]PendingCommand, error) {
	if limit < 1 || limit > 128 {
		return nil, errorsInvalid("pending command limit is outside supported bounds")
	}
	if err := store.ExpireDeliveries(ctx, now); err != nil {
		return nil, err
	}
	// RFC3339Nano omits trailing fractional zeros, so lexical comparison can
	// hide a live command within the current second. Match the expiry/claim queries.
	rows, err := store.db.QueryContext(ctx, `SELECT event_id,command_type,command_json,created_at,expires_at FROM pending_deliveries WHERE agent_id=? AND julianday(expires_at)>julianday(?) ORDER BY julianday(created_at),event_id LIMIT ?`, agentID, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []PendingCommand
	for rows.Next() {
		var record PendingCommand
		var commandType, commandJSON string
		var created, expiry string
		record.AgentID = agentID
		if err := rows.Scan(&record.EventID, &commandType, &commandJSON, &created, &expiry); err != nil {
			return nil, err
		}
		record.Command, err = decodeStoredCommand(instruction.CommandType(commandType), commandJSON)
		if err != nil {
			return nil, errorsInvalid("stored command is invalid")
		}
		if err := record.Command.Validate(); err != nil {
			return nil, errorsInvalid("stored command is invalid")
		}
		if record.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
			return nil, err
		}
		if record.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiry); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// encodeStoredCommand creates the single canonical representation used at the SQLite boundary.
func encodeStoredCommand(command instruction.Command) (string, error) {
	payload, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	if len(payload) > maxStoredCommandBytes {
		return "", errorsInvalid("encoded command exceeds storage bound")
	}
	return string(payload), nil
}

// decodeStoredCommand reconstructs a typed command from its bounded SQLite representation.
func decodeStoredCommand(commandType instruction.CommandType, payload string) (instruction.Command, error) {
	if len(payload) < 2 || len(payload) > maxStoredCommandBytes {
		return instruction.Command{}, errorsInvalid("invalid command payload")
	}
	var command instruction.Command
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil || command.Type() != commandType {
		return instruction.Command{}, errorsInvalid("invalid command payload")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return instruction.Command{}, errorsInvalid("invalid command payload")
	}
	return command, nil
}

// SaveReceipt records the first authenticated receipt for each target status.
// The six lifecycle statuses bound history per target. Repeated statuses succeed
// without changing diagnostics or outcomes; the result reports a new committed receipt.
func (store *Store) SaveReceipt(ctx context.Context, eventID string, receipt Receipt) (bool, error) {
	if err := validateReceipt(eventID, receipt); err != nil {
		return false, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.StmtContext(ctx, store.statements.receiptInsert).ExecContext(ctx,
		eventID, receipt.AgentID, receipt.Status, receipt.Operation, receipt.Error, receipt.Details, receipt.Value, receipt.Timestamp.UTC().Format(time.RFC3339Nano), eventID, receipt.AgentID, eventID, receipt.AgentID, receipt.Status)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if count == 0 {
		var targetExists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM event_targets WHERE event_id=? AND agent_id=?)`, eventID, receipt.AgentID).Scan(&targetExists); err != nil {
			return false, err
		}
		if !targetExists {
			return false, ErrNotFound
		}
		return false, tx.Commit()
	}
	// Never regress a terminal outcome when an earlier receipt arrives late.
	if _, err = tx.StmtContext(ctx, store.statements.receiptOutcome).ExecContext(ctx, receipt.Status, receipt.Error, eventID, receipt.AgentID, receipt.Status); err != nil {
		return false, err
	}
	if _, err = tx.StmtContext(ctx, store.statements.removePending).ExecContext(ctx, eventID, receipt.AgentID); err != nil {
		return false, err
	}
	if receipt.Operation == "desired_state" && (receipt.Status == "accepted" || receipt.Status == "completed") {
		if err := resolveEarlierDesiredTargets(ctx, tx, eventID, receipt); err != nil {
			return false, err
		}
	}
	if receipt.Operation == string(instruction.CommandDisplay) && (receipt.Status == "completed" || receipt.Status == "failed") {
		power := receipt.Value
		if power == "" {
			power = "unknown"
		}
		output := receipt.Details
		if output == "" {
			output = receipt.Error
		}
		// The full error remains in receipt history. CEC status has the narrower
		// details bound; copying a longer error must not roll back a valid receipt.
		if len(output) > protocol.ReceiptDetailsMaxBytes {
			output = output[:protocol.ReceiptDetailsMaxBytes]
			for !utf8.ValidString(output) {
				output = output[:len(output)-1]
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE agent_status SET cec_power_status=?,cec_output=?,cec_checked_at=? WHERE agent_id=?`, power, output, receipt.Timestamp.UTC().Format(time.RFC3339Nano), receipt.AgentID); err != nil {
			return false, err
		}
	}
	if _, err = tx.StmtContext(ctx, store.statements.eventUpdated).ExecContext(ctx, receipt.Timestamp.UTC().Format(time.RFC3339Nano), eventID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// resolveEarlierDesiredTargets settles unresolved deliveries of the same or an
// older complete state once an agent applies a revision. A display that was
// offline receives changes through a reconciliation event, so the event returned
// to the operator would otherwise stay queued. Matching revisions were applied;
// older ones were superseded before the display could apply them.
func resolveEarlierDesiredTargets(ctx context.Context, tx *sql.Tx, eventID string, receipt Receipt) error {
	var generation sql.NullString
	var revision sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT desired_generation,desired_revision FROM event_targets WHERE event_id=? AND agent_id=?`, eventID, receipt.AgentID).Scan(&generation, &revision); err != nil {
		return err
	}
	if !generation.Valid || !revision.Valid {
		return nil
	}
	stamp := receipt.Timestamp.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE command_events SET updated_at=? WHERE event_id IN (SELECT event_id FROM event_targets WHERE agent_id=? AND event_id<>? AND desired_generation=? AND desired_revision IS NOT NULL AND desired_revision<=? AND delivery_status IN ('queued','uncertain','received'))`,
		stamp, receipt.AgentID, eventID, generation.String, revision.Int64); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE event_targets SET delivery_status=CASE WHEN desired_revision=? THEN 'accepted' ELSE 'expired' END,delivery_reason=substr(CASE WHEN desired_revision=? THEN 'applied through event ' || ? ELSE 'superseded by revision ' || ? END,1,128) WHERE agent_id=? AND event_id<>? AND desired_generation=? AND desired_revision IS NOT NULL AND desired_revision<=? AND delivery_status IN ('queued','uncertain','received')`,
		revision.Int64, revision.Int64, eventID, revision.Int64, receipt.AgentID, eventID, generation.String, revision.Int64)
	return err
}

// validateReceipt protects the durable boundary from malformed or unbounded agent data.
func validateReceipt(eventID string, receipt Receipt) error {
	if eventID == "" || len(eventID) > 128 || receipt.AgentID == "" || len(receipt.AgentID) > 128 || receipt.Timestamp.IsZero() {
		return errorsInvalid("receipt metadata is incomplete")
	}
	if len(receipt.Error) > protocol.ReceiptErrorMaxBytes || len(receipt.Details) > protocol.ReceiptDetailsMaxBytes || len(receipt.Value) > protocol.ReceiptValueMaxBytes || strings.ContainsRune(receipt.Error, '\x00') || strings.ContainsRune(receipt.Details, '\x00') || strings.ContainsRune(receipt.Value, '\x00') {
		return errorsInvalid("receipt error is outside supported bounds")
	}
	switch receipt.Status {
	case "received", "accepted", "completed", "failed", "expired", "unsupported":
	default:
		return errorsInvalid("receipt status is invalid")
	}
	switch instruction.CommandType(receipt.Operation) {
	case "desired_state", instruction.CommandDisplay, instruction.CommandDisplayVolume, instruction.CommandSound, instruction.CommandSerial, instruction.CommandBanner,
		instruction.CommandReload, instruction.CommandRestart, instruction.CommandReboot, instruction.CommandShutdown:
		return nil
	default:
		return errorsInvalid("receipt operation is invalid")
	}
}

// Event returns targets and receipts for one persisted operation.
func (store *Store) Event(ctx context.Context, eventID string) (EventState, error) {
	var state EventState
	var created, updated string
	err := store.db.QueryRowContext(ctx, `SELECT event_id,created_at,updated_at FROM command_events WHERE event_id=?`, eventID).Scan(&state.EventID, &created, &updated)
	if err != nil {
		return state, mapSQLError(err)
	}
	if state.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return state, err
	}
	if state.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated); err != nil {
		return state, err
	}
	state.Targets, err = store.eventTargets(ctx, eventID)
	if err != nil {
		return state, err
	}
	state.Receipts, err = store.eventReceipts(ctx, eventID)
	if err != nil {
		return state, err
	}
	state.Deliveries, err = store.Deliveries(ctx, eventID)
	return state, err
}

// eventTargets loads an event's authorized agent identifiers.
func (store *Store) eventTargets(ctx context.Context, eventID string) ([]string, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT agent_id FROM event_targets WHERE event_id=? ORDER BY agent_id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// eventReceipts loads authenticated receipt history in insertion order.
func (store *Store) eventReceipts(ctx context.Context, eventID string) ([]Receipt, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT agent_id,status,operation,error,details,value,reported_at FROM command_receipts WHERE event_id=? ORDER BY id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var receipts []Receipt
	for rows.Next() {
		var receipt Receipt
		var reportedAt string
		if err := rows.Scan(&receipt.AgentID, &receipt.Status, &receipt.Operation, &receipt.Error, &receipt.Details, &receipt.Value, &reportedAt); err != nil {
			return nil, err
		}
		var err error
		receipt.Timestamp, err = time.Parse(time.RFC3339Nano, reportedAt)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, rows.Err()
}
