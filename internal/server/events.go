// File purpose: Serves durable event status and resolves scoped broadcast targets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"errors"
	"net/http"

	"github.com/RealisLux/NeoDSE/internal/store"
)

// writeQueuedEvent returns the stable accepted response for committed operations.
func writeQueuedEvent(w http.ResponseWriter, eventID string) {
	writeJSON(w, http.StatusAccepted, map[string]string{"event_id": eventID, "status": "queued"})
}

// eventStateHandler returns one event only when the principal can see every target.
func (s *Server) eventStateHandler(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("eventId")
	if !validEventID(eventID) {
		writeAPIError(w, http.StatusNotFound, "event not found")
		return
	}
	state, err := s.store.EventAt(r.Context(), eventID, s.now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "event not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		}
		return
	}
	principal, _ := principalFor(r)
	if len(state.Targets) == 0 || !allowsEveryAgent(principal, state.Targets) {
		writeAPIError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, newEventStateResponse(state))
}

// validEventID accepts bounded opaque identifiers, including scheduler occurrences.
func validEventID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

type eventStateResponse struct {
	EventID    string            `json:"event_id"`
	Targets    []string          `json:"targets"`
	CreatedAt  string            `json:"created_at"`
	UpdatedAt  string            `json:"updated_at"`
	Receipts   []receiptResponse `json:"receipts"`
	Deliveries []store.Delivery  `json:"deliveries"`
}

type receiptResponse struct {
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
	Operation string `json:"operation,omitempty"`
	Error     string `json:"error,omitempty"`
	Details   string `json:"details,omitempty"`
	Value     string `json:"value,omitempty"`
	Timestamp string `json:"timestamp"`
}

// newEventStateResponse converts durable event and receipt times for public output.
func newEventStateResponse(state store.EventState) eventStateResponse {
	response := eventStateResponse{
		EventID: state.EventID, Targets: state.Targets, Deliveries: state.Deliveries,
		CreatedAt: formatAPITimestamp(state.CreatedAt), UpdatedAt: formatAPITimestamp(state.UpdatedAt),
		Receipts: make([]receiptResponse, 0, len(state.Receipts)),
	}
	for _, receipt := range state.Receipts {
		response.Receipts = append(response.Receipts, receiptResponse{
			AgentID: receipt.AgentID, Status: receipt.Status, Operation: receipt.Operation,
			Error: receipt.Error, Details: receipt.Details, Value: receipt.Value, Timestamp: formatAPITimestamp(receipt.Timestamp),
		})
	}
	return response
}

// authorizedBroadcastTargets intersects provisioned agents with principal scope.
func (s *Server) authorizedBroadcastTargets(r *http.Request) ([]string, error) {
	principal, ok := principalFor(r)
	if !ok {
		return nil, errors.New("principal unavailable")
	}
	available, err := s.store.AgentIDs(r.Context())
	if err != nil {
		return nil, err
	}
	if principal.AllAgents {
		return available, nil
	}
	targets := make([]string, 0, len(principal.AgentIDs))
	for _, identifier := range available {
		if principal.AgentIDs[identifier] {
			targets = append(targets, identifier)
		}
	}
	return targets, nil
}

// allowsEveryAgent reports whether a principal may observe all event targets.
func allowsEveryAgent(principal Principal, targets []string) bool {
	for _, identifier := range targets {
		if !principal.allowsAgent(identifier) {
			return false
		}
	}
	return true
}
