// File purpose: Verifies authenticated inbound persistence and sequencing.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestReceiptFrameRejectionReasons keeps protocol and storage failures
// distinguishable without logging authenticated payloads or credentials.
func TestReceiptFrameRejectionReasons(t *testing.T) {
	var logged bytes.Buffer
	previousLog := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previousLog)
	for _, scenario := range []struct {
		name   string
		change func(*protocol.Receipt)
		raw    []byte
		want   string
	}{
		{name: "malformed", raw: []byte(`{"private-invalid-field":true}`), want: "malformed receipt message"},
		{name: "identity", change: func(m *protocol.Receipt) { m.AgentID = "private-other-agent" }, want: "invalid receipt identity or field bounds"},
		{name: "status", change: func(m *protocol.Receipt) { m.Status = "private-status" }, want: "invalid receipt identity or field bounds"},
		{name: "bounds", change: func(m *protocol.Receipt) { m.Error = strings.Repeat("x", protocol.ReceiptErrorMaxBytes+1) }, want: "invalid receipt identity or field bounds"},
		{name: "session", change: func(m *protocol.Receipt) { m.SessionID = "private-old-session" }, want: "receipt session changed"},
		{name: "sequence gap", change: func(m *protocol.Receipt) { m.Sequence = 2 }, want: "nonconsecutive receipt sequence: received=2 expected=1"},
		{name: "replayed sequence", change: func(m *protocol.Receipt) { m.Sequence = 0 }, want: "nonconsecutive receipt sequence: received=0 expected=1"},
		{name: "signature", change: func(m *protocol.Receipt) { m.Signature = "private-invalid-signature" }, want: "receipt authentication failed"},
		{name: "timestamp", change: func(m *protocol.Receipt) { m.Timestamp = "private-invalid-time" }, want: "invalid receipt timestamp"},
		{name: "stale", change: func(m *protocol.Receipt) {
			m.Timestamp = time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano)
		}, want: "stale receipt timestamp"},
		{name: "unknown event", change: func(m *protocol.Receipt) { m.EventID = "private-unknown-event" }, want: "receipt event target unavailable"},
		{name: "persistence fields", change: func(m *protocol.Receipt) { m.Operation = "private-operation" }, want: "invalid receipt persistence fields"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
			session := s.sessions["display"]
			now := time.Now().UTC()
			if _, err := s.store.CreateStateEvent(context.Background(), "private-event", "test", "display", now); err != nil {
				t.Fatal(err)
			}
			message := protocol.Receipt{Protocol: protocol.Version, AgentID: "display", SessionID: session.id,
				Sequence: 1, EventID: "private-event", Status: "accepted", Operation: "desired_state",
				Error: "private-error", Details: "private-details", Value: "private-value", Timestamp: now.Format(time.RFC3339Nano)}
			if scenario.change != nil {
				scenario.change(&message)
			}
			if message.Signature == "" {
				var err error
				message.Signature, err = protocol.SignReceipt(message, session.keys[keyderivation.TransportReceipt])
				if err != nil {
					t.Fatal(err)
				}
			}
			payload := scenario.raw
			if payload == nil {
				payload = mustJSON(t, message)
			}
			logged.Reset()
			s.handleAgentFrame("display", session.connectionID, mustJSON(t, protocol.Frame{Type: "receipt", Payload: payload}))
			if !strings.Contains(logged.String(), "invalid authenticated receipt: "+scenario.want) {
				t.Fatalf("missing rejection detail: %q", logged.String())
			}
			for _, secret := range []string{"private-", session.id, message.Signature, fmt.Sprintf("%x", session.keys[keyderivation.TransportReceipt])} {
				if strings.Contains(logged.String(), secret) {
					t.Fatal("receipt rejection log exposed authenticated message contents")
				}
			}
			if session.lastReceived != 0 || s.sessionFor("display") != nil {
				t.Fatal("rejected receipt advanced sequence or retained authority")
			}
			event, err := s.store.Event(context.Background(), "private-event")
			if err != nil || len(event.Receipts) != 0 {
				t.Fatalf("rejected receipt changed history: receipts=%d error=%v", len(event.Receipts), err)
			}
		})
	}
}

// TestRepeatedAuthenticatedReceiptStateDoesNotGrowHistory checks that fresh
// sequence numbers cannot turn one event into an unbounded diagnostic history.
func TestRepeatedAuthenticatedReceiptStateDoesNotGrowHistory(t *testing.T) {
	for _, operation := range []string{"desired_state", "restart"} {
		t.Run(operation, func(t *testing.T) {
			const agentID = "display-a"
			s := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
			session := s.sessions[agentID]
			now := time.Now().UTC()
			status := "accepted"
			if operation == "restart" {
				status = "completed"
				if _, err := s.store.CreateCommand(context.Background(), "evt-repeat", "test", []string{agentID}, instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.store.CreateStateEvent(context.Background(), "evt-repeat", "test", agentID, now); err != nil {
				t.Fatal(err)
			}
			reconciliations := 0
			s.sendOverride = func(string, protocol.Frame) error { reconciliations++; return nil }
			for sequence := uint64(1); sequence <= 128; sequence++ {
				receipt := protocol.Receipt{
					Protocol: protocol.Version, SessionID: session.id, Sequence: sequence,
					EventID: "evt-repeat", AgentID: agentID, Status: status, Operation: operation,
					Details: strings.Repeat("x", protocol.ReceiptDetailsMaxBytes), Timestamp: now.Format(time.RFC3339Nano),
				}
				var err error
				receipt.Signature, err = protocol.SignReceipt(receipt, session.keys[keyderivation.TransportReceipt])
				if err != nil {
					t.Fatal(err)
				}
				if err := s.handleReceipt(agentID, mustJSON(t, receipt)); err != nil {
					t.Fatalf("idempotent receipt at sequence %d revoked the agent: %v", sequence, err)
				}
			}
			event, err := s.store.Event(context.Background(), "evt-repeat")
			if err != nil || len(event.Receipts) != 1 || event.Deliveries[0].Status != status || session.lastReceived != 128 {
				t.Fatalf("unbounded receipt history: rows=%d sequence=%d error=%v", len(event.Receipts), session.lastReceived, err)
			}
			wantReconciliations := 0
			if operation == "restart" {
				wantReconciliations = 1
			}
			if reconciliations != wantReconciliations {
				t.Fatalf("duplicate receipts generated %d reconciliation events, want %d", reconciliations, wantReconciliations)
			}
		})
	}
}

// TestStatusRequiresSessionSignature rejects a status signed with another key
// or carrying a malformed tag, without persisting it or advancing the sequence.
func TestStatusRequiresSessionSignature(t *testing.T) {
	const agentID = "display-a"
	s := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	session := s.sessions[agentID]
	now := time.Now().UTC()
	status := protocol.Status{
		Protocol: protocol.Version, SessionID: session.id, Sequence: 1,
		AgentID: agentID, Hostname: "display-a.local", Version: "1.0.0", Status: "online",
		StartedAt: now.Add(-time.Hour).Format(time.RFC3339), Timestamp: now.Format(time.RFC3339Nano),
	}
	forged, err := protocol.SignStatus(status, session.keys[keyderivation.TransportReceipt])
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range []string{forged, "", strings.Repeat("z", len(forged))} {
		status.Signature = signature
		if s.handleStatus(agentID, mustJSON(t, status)) || session.lastReceived != 0 {
			t.Fatalf("accepted status signature %q; sequence = %d", signature, session.lastReceived)
		}
	}
	if statuses, err := s.store.AgentStatuses(context.Background()); err != nil || len(statuses) != 1 || statuses[0].Hostname != "" {
		t.Fatalf("rejected status was stored: %#v error=%v", statuses, err)
	}
	status.Signature, err = protocol.SignStatus(status, session.keys[keyderivation.TransportStatus])
	if err != nil {
		t.Fatal(err)
	}
	if !s.handleStatus(agentID, mustJSON(t, status)) || session.lastReceived != 1 {
		t.Fatalf("authentic status rejected; sequence = %d", session.lastReceived)
	}
}

// TestAuthenticatedInboundMessagesPersistBeforeSequenceAdvances verifies authenticated inbound messages persist before sequence advances.
func TestAuthenticatedInboundMessagesPersistBeforeSequenceAdvances(t *testing.T) {
	const agentID = "display-a"
	s := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	session := s.sessions[agentID]
	now := time.Now().UTC()

	status := protocol.Status{
		Protocol: protocol.Version, SessionID: session.id, Sequence: 1,
		AgentID: agentID, Hostname: "display-a.local", Version: "1.0.0", Status: "online",
		StartedAt: now.Add(-time.Hour).Format(time.RFC3339), Timestamp: now.Format(time.RFC3339Nano),
	}
	status.Signature, _ = protocol.SignStatus(status, session.keys[keyderivation.TransportStatus])
	s.handleStatus(agentID, mustJSON(t, status))
	if session.lastReceived != 1 {
		t.Fatalf("status sequence = %d, want 1", session.lastReceived)
	}
	if s.handleStatus(agentID, mustJSON(t, status)) {
		t.Fatal("replayed status was accepted")
	}
	statuses, err := s.store.AgentStatuses(context.Background())
	if err != nil || len(statuses) != 1 || statuses[0].Hostname != status.Hostname {
		t.Fatalf("stored statuses=%#v error=%v", statuses, err)
	}

	if _, err := s.store.CreateCommand(context.Background(), "evt-receipt", "test", []string{agentID}, instruction.NewCommand(instruction.RestartCommand{}), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var reconciliation []protocol.Frame
	s.sendOverride = func(deliveredAgent string, frame protocol.Frame) error {
		if deliveredAgent != agentID {
			t.Fatalf("reconciliation delivered to %q", deliveredAgent)
		}
		reconciliation = append(reconciliation, frame)
		return nil
	}
	receipt := protocol.Receipt{
		Protocol: protocol.Version, SessionID: session.id, Sequence: 2,
		EventID: "evt-receipt", AgentID: agentID, Status: "completed", Operation: "restart",
		Timestamp: now.Add(time.Nanosecond).Format(time.RFC3339Nano),
	}
	receipt.Signature, _ = protocol.SignReceipt(receipt, session.keys[keyderivation.TransportReceipt])
	if err := s.handleReceipt(agentID, mustJSON(t, receipt)); err != nil {
		t.Fatal(err)
	}
	if session.lastReceived != 2 {
		t.Fatalf("receipt sequence = %d, want 2", session.lastReceived)
	}
	if err := s.handleReceipt(agentID, mustJSON(t, receipt)); err == nil {
		t.Fatal("replayed receipt was accepted")
	}
	event, err := s.store.Event(context.Background(), receipt.EventID)
	if err != nil || len(event.Receipts) != 1 {
		t.Fatalf("stored event=%#v error=%v", event, err)
	}
	if event.Deliveries[0].Status != "completed" || len(reconciliation) != 1 || reconciliation[0].Type != "desired_state" {
		t.Fatalf("restart outcome=%#v reconciliation=%#v", event.Deliveries, reconciliation)
	}
}

// TestInboundBoundsRejectBeforeSequenceAdvance verifies inbound bounds reject before sequence advance.
func TestInboundBoundsRejectBeforeSequenceAdvance(t *testing.T) {
	const agentID = "display-a"
	s := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	session := s.sessions[agentID]
	receipt := protocol.Receipt{
		Protocol: protocol.Version, SessionID: session.id, Sequence: 1,
		EventID: "evt", AgentID: agentID, Status: "failed", Error: strings.Repeat("x", 1025),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	receipt.Signature, _ = protocol.SignReceipt(receipt, session.keys[keyderivation.TransportReceipt])
	s.handleReceipt(agentID, mustJSON(t, receipt))
	if session.lastReceived != 0 {
		t.Fatalf("oversized receipt advanced sequence to %d", session.lastReceived)
	}
}

// TestInvalidInboundFrameRevokesSession verifies invalid inbound frame revokes session.
func TestInvalidInboundFrameRevokesSession(t *testing.T) {
	const agentID = "display-a"
	s := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	session := s.sessions[agentID]
	receipt := protocol.Receipt{
		Protocol: protocol.Version, SessionID: session.id, Sequence: 1,
		EventID: "evt", AgentID: agentID, Status: "failed", Error: strings.Repeat("x", 1025),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	receipt.Signature, _ = protocol.SignReceipt(receipt, session.keys[keyderivation.TransportReceipt])
	frame := protocol.Frame{Type: "receipt", Payload: mustJSON(t, receipt)}
	s.handleAgentFrame(agentID, "", mustJSON(t, frame))
	if s.sessionFor(agentID) != nil {
		t.Fatal("invalid authenticated frame retained session authority")
	}
}

// mustJSON encodes a protocol fixture or terminates its test.
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
