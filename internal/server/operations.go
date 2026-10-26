// File purpose: Serves desired state, readiness, security logging, and request identity support.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/store"
)

type requestIDContextKey struct{}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

type responseRequestIDWriter interface {
	Header() http.Header
}

// requestIDMiddleware validates or creates one request identifier and echoes it on the response.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !requestIDPattern.MatchString(id) {
			value := make([]byte, 16)
			if _, err := rand.Read(value); err == nil {
				id = hex.EncodeToString(value)
			} else {
				id = strconv.FormatInt(time.Now().UnixNano(), 10)
			}
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id)))
	})
}

// responseRequestID returns the identifier that requestIDMiddleware set on the
// response before the handler ran, so error writers need no request.
func responseRequestID(w responseRequestIDWriter) string {
	return w.Header().Get("X-Request-ID")
}

// getAgentDesiredState returns the complete SQLite-authoritative state projection.
func (s *Server) getAgentDesiredState(w http.ResponseWriter, r *http.Request, agentID string) {
	record, err := s.store.DesiredState(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "desired state not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		}
		return
	}
	response := struct {
		AgentID    string                   `json:"agent_id"`
		Generation string                   `json:"generation"`
		Revision   uint64                   `json:"revision"`
		UpdatedAt  string                   `json:"updated_at"`
		Content    instruction.ContentState `json:"content"`
	}{
		AgentID: record.AgentID, Generation: record.Generation, Revision: record.Revision,
		UpdatedAt: formatAPITimestamp(record.UpdatedAt), Content: record.State.Content,
	}
	writeJSON(w, http.StatusOK, response)
}

// systemStatusHandler reports authenticated database and transport readiness.
func (s *Server) systemStatusHandler(w http.ResponseWriter, r *http.Request) {
	databaseReady := s.store != nil && s.store.Ping(r.Context()) == nil
	transportReady := s.link != nil && s.link.connected()
	status := "ready"
	if !databaseReady || !transportReady {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "database": databaseReady, "transport": transportReady})
}

// Requests without a valid token are audited at most once per source address
// per interval. The next record reports how many were suppressed, so a client
// without credentials cannot flood the journal while denials stay visible.
// Expired windows are evicted only when the table is full, so a pending count
// survives requests from other sources.
const (
	unauthenticatedAuditInterval = time.Minute
	unauthenticatedAuditSources  = 1024
)

// auditWindow counts unauthenticated requests from one source since its last record.
type auditWindow struct {
	logged     time.Time
	suppressed int
}

// logUnauthenticatedOutcome audits a request without a valid token, subject to
// the per-source rate limit.
func (s *Server) logUnauthenticatedOutcome(r *http.Request, status int) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := s.now()
	s.auditMu.Lock()
	window, tracked := s.authFailures[host]
	if tracked && now.Sub(window.logged) < unauthenticatedAuditInterval {
		window.suppressed++
		s.authFailures[host] = window
		s.auditMu.Unlock()
		return
	}
	if !tracked && len(s.authFailures) >= unauthenticatedAuditSources {
		for source, previous := range s.authFailures {
			if now.Sub(previous.logged) >= unauthenticatedAuditInterval {
				delete(s.authFailures, source)
			}
		}
		if len(s.authFailures) >= unauthenticatedAuditSources {
			s.auditMu.Unlock()
			return
		}
	}
	if s.authFailures == nil {
		s.authFailures = make(map[string]auditWindow)
	}
	s.authFailures[host] = auditWindow{logged: now}
	s.auditMu.Unlock()
	s.logAPIOutcome(r, "unauthenticated", status, "suppressed", window.suppressed)
}

// logAPIOutcome emits one redacted security-relevant API outcome through the shared service logger.
// Successful mutations and denied reads or writes remain visible at the default level.
func (s *Server) logAPIOutcome(r *http.Request, actorID string, status int, extra ...any) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	result := auditResult(status)
	requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
	agentID := r.PathValue("agentId")
	if !identity.ValidAgentID(agentID) {
		agentID = ""
	}
	attributes := []any{"actor_id", actorID, "operation", r.Method, "target", r.Pattern, "agent_id", agentID, "result", result, "source_address", host, "request_id", requestID, "status", status}
	slog.Info("API audit", append(attributes, extra...)...)
}

// auditResult maps an HTTP status to the stable security audit outcome vocabulary.
func auditResult(status int) string {
	if status >= 500 {
		return "failed"
	}
	if status >= 400 {
		return "denied"
	}
	return "success"
}
