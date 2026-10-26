// File purpose: Authenticates and persists agent status and command receipts.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// handleStatus authenticates, replay-checks, and persists a status before advancing sequence.
func (s *Server) handleStatus(agentID string, payload []byte) bool {
	var message protocol.Status
	if protocol.Decode(payload, &message) != nil || message.AgentID != agentID || message.Protocol != protocol.Version ||
		!identity.ValidFriendlyName(message.FriendlyName) ||
		len(message.Hostname) == 0 || len(message.Hostname) > 255 || len(message.Version) == 0 || len(message.Version) > 128 ||
		message.Status != "online" || len(message.LastEventID) > 128 || len(message.CECPower) > 32 || len(message.CECOutput) > 768 {
		return false
	}
	if message.CECPower != "" && message.CECPower != "on" && message.CECPower != "standby" && message.CECPower != "transitioning" && message.CECPower != "unknown" {
		return false
	}
	if message.CECCheckedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, message.CECCheckedAt); err != nil {
			return false
		}
	}
	if _, err := time.Parse(time.RFC3339, message.StartedAt); err != nil {
		return false
	}
	session := s.sessionFor(agentID)
	if session == nil {
		return false
	}
	session.receiveMu.Lock()
	defer session.receiveMu.Unlock()
	session.mu.Lock()
	if message.SessionID != session.id || message.Sequence != session.lastReceived+1 {
		session.mu.Unlock()
		return false
	}
	expected, signErr := protocol.SignStatus(message, session.keys[keyderivation.TransportStatus])
	ts, err := time.Parse(time.RFC3339Nano, message.Timestamp)
	if signErr != nil || err != nil || !protocol.Verify(message.Signature, expected) || !replay.Fresh(ts, time.Now().UTC(), wire.MaxClockSkew) {
		session.mu.Unlock()
		return false
	}
	session.mu.Unlock()
	if s.store == nil {
		s.resetAgentConnection(agentID, session)
		return false
	}
	storeContext, cancel := boundedStoreContext()
	defer cancel()
	if err := s.store.SaveStatus(storeContext, message, time.Now().UTC()); err != nil {
		s.resetAgentConnection(agentID, session)
		return false
	}
	session.mu.Lock()
	if session.lastReceived+1 != message.Sequence {
		session.mu.Unlock()
		return false
	}
	session.lastReceived = message.Sequence
	session.mu.Unlock()
	return true
}

// handleReceipt authenticates and persists a command receipt before advancing sequence.
func (s *Server) handleReceipt(agentID string, payload []byte) error {
	var receipt protocol.Receipt
	if protocol.Decode(payload, &receipt) != nil {
		return errors.New("malformed receipt message")
	}
	if receipt.AgentID != agentID || receipt.Protocol != protocol.Version || !validReceiptStatus(receipt.Status) ||
		len(receipt.EventID) == 0 || len(receipt.EventID) > 128 || len(receipt.Operation) > 32 || len(receipt.Error) > protocol.ReceiptErrorMaxBytes || len(receipt.Details) > protocol.ReceiptDetailsMaxBytes || len(receipt.Value) > protocol.ReceiptValueMaxBytes {
		return errors.New("invalid receipt identity or field bounds")
	}
	session := s.sessionFor(agentID)
	if session == nil {
		return errors.New("agent session unavailable")
	}
	session.receiveMu.Lock()
	defer session.receiveMu.Unlock()
	session.mu.Lock()
	if receipt.SessionID != session.id {
		session.mu.Unlock()
		return errors.New("receipt session changed")
	}
	if receipt.Sequence != session.lastReceived+1 {
		expected := session.lastReceived + 1
		session.mu.Unlock()
		return fmt.Errorf("nonconsecutive receipt sequence: received=%d expected=%d", receipt.Sequence, expected)
	}
	expected, err := protocol.SignReceipt(receipt, session.keys[keyderivation.TransportReceipt])
	if err != nil || !protocol.Verify(receipt.Signature, expected) {
		session.mu.Unlock()
		return errors.New("receipt authentication failed")
	}
	ts, err := time.Parse(time.RFC3339Nano, receipt.Timestamp)
	if err != nil {
		session.mu.Unlock()
		return errors.New("invalid receipt timestamp")
	}
	if !replay.Fresh(ts, time.Now().UTC(), wire.MaxClockSkew) {
		session.mu.Unlock()
		return errors.New("stale receipt timestamp")
	}
	session.mu.Unlock()
	recorded, err := s.recordCommandReceipt(receipt)
	if err != nil {
		s.resetAgentConnection(agentID, session)
		// Store errors can contain agent-controlled fields. Log only the cause
		// category, never the receipt contents or the underlying error text.
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return errors.New("receipt persistence deadline exceeded")
		case errors.Is(err, context.Canceled):
			return errors.New("receipt persistence cancelled")
		case errors.Is(err, store.ErrNotFound):
			return errors.New("receipt event target unavailable")
		case errors.Is(err, store.ErrInvalidState):
			return errors.New("invalid receipt persistence fields")
		default:
			return errors.New("receipt persistence failed")
		}
	}
	session.mu.Lock()
	if session.lastReceived+1 == receipt.Sequence {
		session.lastReceived = receipt.Sequence
	}
	session.mu.Unlock()
	if recorded && receipt.Operation == "restart" && (receipt.Status == "completed" || receipt.Status == "failed") {
		// The UI socket changes during restart. Reconcile authoritative content
		// after recording the final outcome, while this session remains live.
		if err := s.sendDesiredState(agentID); err != nil {
			s.verbosef("! Restart reconciliation could not be sent agent=%s: %v", agentID, err)
		}
	}
	return nil
}

// validReceiptStatus accepts only the documented finite command lifecycle states.
func validReceiptStatus(value string) bool {
	switch value {
	case "received", "accepted", "completed", "failed", "expired", "unsupported":
		return true
	}
	return false
}

// recordCommandReceipt commits an authenticated receipt through the store.
func (s *Server) recordCommandReceipt(receipt protocol.Receipt) (bool, error) {
	if s.store == nil {
		return false, store.ErrUnavailable
	}
	reportedAt, err := time.Parse(time.RFC3339Nano, receipt.Timestamp)
	if err != nil {
		return false, err
	}
	value := store.Receipt{AgentID: receipt.AgentID, Status: receipt.Status, Operation: receipt.Operation, Error: receipt.Error, Details: receipt.Details, Value: receipt.Value, Timestamp: reportedAt}
	storeContext, cancel := boundedStoreContext()
	defer cancel()
	return s.store.SaveReceipt(storeContext, receipt.EventID, value)
}
