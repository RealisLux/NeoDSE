// File purpose: Authenticates service accounts and enforces role and agent scope authorization.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/store"
)

// Role identifies one coarse-grained service-account authorization role.
type Role string

const (
	RoleViewer         Role = "viewer"
	RoleContentManager Role = "content_manager"
	RoleAlertIO        Role = "alert_io_operator"
	RoleCECManager     Role = "cec_manager"
	RoleSystemOperator Role = "system_operator"
	RoleAdministrator  Role = "administrator"
)

type capability string

const (
	capView     capability = "view"
	capContent  capability = "content"
	capAlertIO  capability = "alert_io"
	capCEC      capability = "cec"
	capSystem   capability = "system"
	capAccounts capability = "accounts"
)

// Principal is the authenticated service-account identity installed by middleware.
type Principal struct {
	ServiceAccountID string
	Roles            map[Role]bool
	AllAgents        bool
	AgentIDs         map[string]bool
}

// has reports whether assigned roles grant one coarse API capability.
func (p Principal) has(c capability) bool {
	if p.Roles[RoleAdministrator] {
		return true
	}
	switch c {
	case capView:
		return len(p.Roles) > 0
	case capContent:
		return p.Roles[RoleContentManager]
	case capAlertIO:
		return p.Roles[RoleAlertIO]
	case capCEC:
		return p.Roles[RoleCECManager]
	case capSystem:
		return p.Roles[RoleSystemOperator]
	}
	return false
}

// allowsAgent reports whether the principal scope contains one agent.
func (p Principal) allowsAgent(id string) bool {
	return p.AllAgents || p.AgentIDs[id]
}

// principalFor retrieves the authenticated identity installed in request context.
func principalFor(r *http.Request) (Principal, bool) {
	v := r.Context().Value(authorizationContextKey{})
	p, ok := v.(Principal)
	return p, ok
}

// authMiddleware authenticates bearer tokens and logs every mutating request.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			s.logUnauthenticatedOutcome(r, http.StatusUnauthorized)
			return
		}
		p, err := s.authenticateToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			if errors.Is(err, store.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) {
				writeAPIError(w, http.StatusServiceUnavailable, "authentication storage unavailable")
				s.logUnauthenticatedOutcome(r, http.StatusServiceUnavailable)
				return
			}
			writeAPIError(w, http.StatusUnauthorized, "unauthorized")
			s.logUnauthenticatedOutcome(r, http.StatusUnauthorized)
			return
		}
		authorized := r.WithContext(context.WithValue(r.Context(), authorizationContextKey{}, p))
		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next(tracked, authorized)
		if tracked.status >= 400 || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
			s.logAPIOutcome(authorized, p.ServiceAccountID, tracked.status)
		}
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader records only the first response status for security-outcome logging.
func (w *statusWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Write records an implicit success status before forwarding response bytes.
func (w *statusWriter) Write(value []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

// Unwrap preserves HTTP streaming and deadline support through the audit wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// authenticateToken validates token shape before constant-time database authentication.
func (s *Server) authenticateToken(ctx context.Context, token string) (Principal, error) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 || parts[0] != "nds" || !validHexBytes(parts[1], 16) || !validHexBytes(parts[2], 32) {
		return Principal{}, store.ErrNotFound
	}
	authentication, err := s.store.AuthenticateAccount(ctx, parts[1], token, time.Now().UTC())
	if err != nil {
		return Principal{}, err
	}
	principal := Principal{
		ServiceAccountID: authentication.AccountID,
		AllAgents:        authentication.AllAgents,
		Roles:            make(map[Role]bool, len(authentication.Roles)),
		AgentIDs:         make(map[string]bool, len(authentication.Agents)),
	}
	for _, role := range authentication.Roles {
		principal.Roles[Role(role)] = true
	}
	for _, agentID := range authentication.Agents {
		principal.AgentIDs[agentID] = true
	}
	return principal, nil
}

// requireCapability enforces both role capability and per-agent scope before a handler runs.
func requireCapability(w http.ResponseWriter, r *http.Request, c capability, agentID string, broadcast bool) bool {
	p, ok := principalFor(r)
	if !ok || !p.has(c) || (!broadcast && agentID != "" && !p.allowsAgent(agentID)) {
		writeAPIError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}
