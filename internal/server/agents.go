// File purpose: Projects durable and live agent status through small HTTP handlers.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/store"
)

// sessionRoute returns the authenticated account identity and its assigned roles.
func (s *Server) sessionRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFor(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	roles := make([]string, 0, len(principal.Roles))
	for role := range principal.Roles {
		roles = append(roles, string(role))
	}
	sort.Strings(roles)
	writeJSON(w, http.StatusOK, map[string]any{"service_account_id": principal.ServiceAccountID, "roles": roles})
}

// healthz reports process liveness without exposing dependency or configuration details.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// listAgents returns durable agents filtered by the authenticated account scope.
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFor(r)
	out, err := s.loadAgentStates(r.Context(), p)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	response := make([]agentResponse, 0, len(out))
	for _, state := range out {
		response = append(response, newAgentResponse(state))
	}
	writeJSON(w, http.StatusOK, response)
}

// agentResponse is the normalized public projection of internal live agent state.
type agentResponse struct {
	Protocol        int    `json:"protocol"`
	AgentID         string `json:"agent_id"`
	FriendlyName    string `json:"friendly_name,omitempty"`
	Hostname        string `json:"hostname"`
	Version         string `json:"version"`
	Status          string `json:"status"`
	StartedAt       string `json:"started_at"`
	UptimeSeconds   uint64 `json:"uptime_seconds"`
	LastEventID     string `json:"last_event_id"`
	LastSeen        string `json:"last_seen"`
	IsAuthenticated bool   `json:"is_authenticated"`
	Timestamp       string `json:"timestamp"`
}

// newAgentResponse converts all agent timestamps at the HTTP response boundary.
func newAgentResponse(state AgentState) agentResponse {
	return agentResponse{
		Protocol: state.Protocol, AgentID: state.AgentID, FriendlyName: state.FriendlyName, Hostname: state.Hostname, Version: state.Version,
		Status: state.Status, StartedAt: formatAPIStoredTimestamp(state.StartedAt), UptimeSeconds: state.UptimeSeconds,
		LastEventID: state.LastEventID, LastSeen: formatAPITimestamp(state.LastSeen), IsAuthenticated: state.IsAuthenticated,
		Timestamp: formatAPIStoredTimestamp(state.Timestamp),
	}
}

// loadAgentStates projects durable status and derives current authentication from volatile sessions.
func (s *Server) loadAgentStates(ctx context.Context, p Principal) ([]AgentState, error) {
	ctx, cancel := context.WithTimeout(ctx, storeOperationTimeout)
	defer cancel()
	records, err := s.store.AgentStatuses(ctx)
	if err != nil {
		return nil, err
	}
	out := []AgentState{}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !p.allowsAgent(record.AgentID) {
			continue
		}
		state := AgentState{
			AgentID: record.AgentID, FriendlyName: record.FriendlyName, Protocol: record.Protocol, Hostname: record.Hostname,
			Version: record.Version, StartedAt: record.StartedAt, UptimeSeconds: record.UptimeSeconds,
			LastEventID: record.LastEventID, Timestamp: record.ReportedAt, LastSeen: record.LastSeen,
		}
		state.Status = "offline"
		connected := s.authenticatedSession(ctx, state.AgentID) != nil
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		statusAge := time.Since(state.LastSeen)
		if connected && !state.LastSeen.IsZero() && statusAge >= 0 && statusAge <= 30*time.Second {
			state.Status = "online"
			state.IsAuthenticated = true
		}
		out = append(out, state)
	}
	return out, nil
}

// getAgent returns one scoped agent projection or a stable not-found response.
func (s *Server) getAgent(w http.ResponseWriter, r *http.Request, id string) {
	p, _ := principalFor(r)
	agents, err := s.loadAgentStates(r.Context(), p)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var agent AgentState
	found := false
	for _, candidate := range agents {
		if candidate.AgentID == id {
			agent, found = candidate, true
			break
		}
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, newAgentResponse(agent))
}

// getAgentRoute returns the agent selected by the explicit route variable.
func (s *Server) getAgentRoute(w http.ResponseWriter, r *http.Request) {
	s.getAgent(w, r, r.PathValue("agentId"))
}

// getAgentStateRoute returns the durable desired state for one agent.
func (s *Server) getAgentStateRoute(w http.ResponseWriter, r *http.Request) {
	s.getAgentDesiredState(w, r, r.PathValue("agentId"))
}

// getDisplayStatusRoute returns the last CEC observation reported by the selected agent.
func (s *Server) getDisplayStatusRoute(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.CECStatus(r.Context(), r.PathValue("agentId"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{"agent_id": r.PathValue("agentId"), "enabled": false, "power_status": "unknown", "output": "", "checked_at": ""})
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": status.AgentID, "enabled": status.CECEnabled, "power_status": status.CECPower, "output": status.CECOutput, "checked_at": formatAPIStoredTimestamp(status.CECCheckedAt)})
}

// revokeWebRoute invalidates the durable proxy policy for one agent.
func (s *Server) revokeWebRoute(w http.ResponseWriter, r *http.Request) {
	revoked, err := s.revokeProxyPolicy(r.Context(), r.PathValue("agentId"))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not persist proxy policy revocation")
		return
	}
	if !revoked {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// apiErrorCodes are the machine-readable codes of the public error statuses.
var apiErrorCodes = map[int]string{
	http.StatusBadRequest:            "bad_request",
	http.StatusUnauthorized:          "unauthorized",
	http.StatusForbidden:             "forbidden",
	http.StatusNotFound:              "not_found",
	http.StatusConflict:              "conflict",
	http.StatusRequestEntityTooLarge: "request_too_large",
	http.StatusUnsupportedMediaType:  "unsupported_media_type",
	http.StatusMethodNotAllowed:      "method_not_allowed",
	http.StatusTooManyRequests:       "rate_limited",
	http.StatusInternalServerError:   "internal_error",
	http.StatusServiceUnavailable:    "service_unavailable",
}

// writeAPIError emits the standard public error shape without internal details.
func writeAPIError(w http.ResponseWriter, status int, message string) {
	code := apiErrorCodes[status]
	if code == "" {
		code = "request_failed"
	}
	writeAPIErrorCode(w, status, code, message)
}

// writeAPIErrorCode exposes a stable machine-readable operation failure.
func writeAPIErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message, "request_id": responseRequestID(w)})
}

// writeJSON emits one JSON value with a stable content type and explicit status.
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// writeMethodNotAllowed emits a JSON error and the complete deterministic Allow header.
func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
}
