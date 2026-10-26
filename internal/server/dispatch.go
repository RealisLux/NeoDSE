// File purpose: Signs and delivers records only after the concrete store commits their authoritative effects.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
)

var errAgentOffline = errors.New("agent has no authenticated session")

// publishDesiredState signs and sends one complete durable state for the active session.
func (s *Server) publishDesiredState(record store.DesiredRecord, eventID string) error {
	return s.publishDesiredStateWithApply(record, eventID, "")
}

// publishDesiredStateWithApply optionally narrows how an already-running renderer applies the state.
func (s *Server) publishDesiredStateWithApply(record store.DesiredRecord, eventID, apply string) error {
	session := s.sessionFor(record.AgentID)
	if session == nil {
		return fmt.Errorf("%w: %s", errAgentOffline, record.AgentID)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if s.sessionFor(record.AgentID) != session {
		return errAgentOffline
	}
	ctx, cancel := boundedStoreContext()
	defer cancel()
	latest, err := s.store.DesiredState(ctx, record.AgentID)
	if err != nil {
		return err
	}
	// A newer commit may replace content while this dispatch waits for the
	// session lock. Its full state must not inherit an older timing-only hint.
	if latest.Generation != record.Generation || latest.Revision != record.Revision {
		apply = ""
		// Keep the original publication bound to its requested revision. The
		// latest state gets its own event so acceptance can expire superseded
		// publications and accept the revision that the display actually applied.
		eventID, err = generateEventID()
		if err != nil {
			return err
		}
		latest, err = s.store.CreateStateEvent(ctx, eventID, "reconciliation", record.AgentID, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	record = latest
	// Policy stays on the controller; only renderer content crosses this boundary.
	record.State.Content.ProxyAllow = nil
	session.nextSend++
	message := protocol.DesiredState{
		Protocol: protocol.Version, SessionID: session.id, Sequence: session.nextSend,
		EventID: eventID, AgentID: record.AgentID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Generation: record.Generation, Revision: record.Revision, Apply: apply, State: record.State,
	}
	signature, err := protocol.SignDesiredState(message, session.keys[keyderivation.TransportCommand])
	if err != nil {
		return err
	}
	message.Signature = signature
	if err := s.sendFrame(record.AgentID, session.connectionID, "desired_state", message); err != nil {
		s.clearSession(record.AgentID, session)
		return err
	}
	s.verbosef("| Desired state sent agent=%s event_id=%s revision=%d", record.AgentID, eventID, record.Revision)
	return nil
}

// deliverCommand records offline rejection or makes one durable delivery attempt.
// Transient commands need an online agent; they are never queued for later delivery.
func (s *Server) deliverCommand(record store.PendingCommand) {
	ctx, cancel := boundedStoreContext()
	defer cancel()
	if s.sessionFor(record.AgentID) == nil {
		if err := s.store.RejectDelivery(ctx, record.EventID, record.AgentID); err != nil {
			log.Printf("! Offline rejection could not be recorded agent=%s event_id=%s", record.AgentID, record.EventID)
		}
		return
	}
	if err := s.publishCommand(record); err != nil {
		log.Printf("! Delivery did not complete agent=%s event_id=%s", record.AgentID, record.EventID)
	}
}

// publishCommand signs and sends one transient command for the active session.
func (s *Server) publishCommand(record store.PendingCommand) error {
	session := s.sessionFor(record.AgentID)
	if session == nil {
		return fmt.Errorf("%w: %s", errAgentOffline, record.AgentID)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if s.sessionFor(record.AgentID) != session {
		return errAgentOffline
	}
	ctx, cancel := boundedStoreContext()
	defer cancel()
	claimed, err := s.store.ClaimDelivery(ctx, record.EventID, record.AgentID, s.now().UTC())
	if err != nil {
		return err
	}
	if !claimed {
		return store.ErrConflict
	}
	session.nextSend++
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: session.id, Sequence: session.nextSend,
		EventID: record.EventID, AgentID: record.AgentID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: record.ExpiresAt.UTC().Format(time.RFC3339Nano), Command: record.Command,
	}
	signature, err := protocol.SignCommand(message, session.keys[keyderivation.TransportCommand])
	if err != nil {
		return err
	}
	message.Signature = signature
	if err := s.sendFrame(record.AgentID, session.connectionID, "command", message); err != nil {
		s.clearSession(record.AgentID, session)
		return err
	}
	s.verbosef("| Command sent agent=%s event_id=%s type=%s", record.AgentID, record.EventID, record.Command.Type())
	return nil
}

// rejectPendingDeliveries settles commands still undelivered when an agent
// authenticates. Transient actions are never replayed after an outage, so each
// unexpired record is rejected instead of sent.
func (s *Server) rejectPendingDeliveries(agentID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	records, err := s.store.PendingCommands(ctx, agentID, time.Now().UTC(), 128)
	if err != nil {
		log.Printf("! Pending delivery query failed agent=%s", agentID)
		return
	}
	for _, record := range records {
		if err := s.store.RejectDelivery(ctx, record.EventID, record.AgentID); err != nil {
			return
		}
	}
}
