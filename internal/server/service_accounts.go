// File purpose: Validates service-account API input and delegates all persistence to the concrete store.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/store"
)

var validRoles = map[Role]bool{RoleViewer: true, RoleContentManager: true, RoleAlertIO: true, RoleCECManager: true, RoleSystemOperator: true, RoleAdministrator: true}
var errInvalidAccount = errors.New("invalid service account")
var errBootstrapExists = errors.New("service accounts already exist")

type serviceAccount struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Roles       []Role   `json:"roles"`
	AllAgents   bool     `json:"all_agents"`
	Agents      []string `json:"agents"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
	Disabled    bool     `json:"disabled"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	LastUsedAt  *string  `json:"last_used_at,omitempty"`
}

type serviceAccountInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Roles       []Role     `json:"roles"`
	AllAgents   bool       `json:"all_agents"`
	Agents      []string   `json:"agents"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Disabled    bool       `json:"disabled"`
}

// validateServiceAccountInput enforces role and agent-scope invariants before storage.
func (s *Server) validateServiceAccountInput(ctx context.Context, input serviceAccountInput) error {
	name := strings.TrimSpace(input.Name)
	description := strings.TrimSpace(input.Description)
	if name == "" || len(name) > 128 || strings.ContainsRune(name, '\x00') || len(description) > 1024 || !utf8.ValidString(name) || !utf8.ValidString(description) ||
		len(input.Roles) == 0 || len(input.Roles) > len(validRoles) || len(input.Agents) > 256 ||
		(input.AllAgents && len(input.Agents) > 0) || (input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC())) {
		return errInvalidAccount
	}
	seenRoles := make(map[Role]bool, len(input.Roles))
	for _, role := range input.Roles {
		if !validRoles[role] || seenRoles[role] {
			return errInvalidAccount
		}
		seenRoles[role] = true
	}
	if seenRoles[RoleAdministrator] && len(seenRoles) != 1 {
		return errInvalidAccount
	}
	seenAgents := make(map[string]bool, len(input.Agents))
	for _, agentID := range input.Agents {
		if !identity.ValidAgentID(agentID) || seenAgents[agentID] {
			return errInvalidAccount
		}
		seenAgents[agentID] = true
		if exists, err := s.store.AgentExists(ctx, agentID); err != nil || !exists {
			return errInvalidAccount
		}
	}
	return nil
}

// createServiceAccount validates input and returns the one-time token from the store.
func (s *Server) createServiceAccount(ctx context.Context, input serviceAccountInput, requireEmpty bool) (serviceAccount, string, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if err := s.validateServiceAccountInput(ctx, input); err != nil {
		return serviceAccount{}, "", err
	}
	account, token, err := s.store.CreateAccount(ctx, storeAccountInput(input), requireEmpty, time.Now().UTC())
	if requireEmpty && errors.Is(err, store.ErrConflict) {
		return serviceAccount{}, "", errBootstrapExists
	}
	return serverAccount(account), token, err
}

// rotateAccountHandler rotates token material without changing account scopes.
func (s *Server) rotateAccountHandler(w http.ResponseWriter, r *http.Request, id string) {
	token, err := s.store.RotateAccountToken(r.Context(), id, time.Now().UTC())
	if err != nil {
		writeAccountError(w, err, "rotate")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// listAccountsRoute returns service accounts without exposing token material.
func (s *Server) listAccountsRoute(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.listServiceAccounts(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

// createAccountRoute creates an account and returns its token exactly once.
func (s *Server) createAccountRoute(w http.ResponseWriter, r *http.Request) {
	var input serviceAccountInput
	if !decodeJSONBody(w, r, &input) {
		return
	}
	account, token, err := s.createServiceAccount(r.Context(), input, false)
	if err != nil {
		writeAccountError(w, err, "create")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"service_account": account, "token": token})
}

// getAccountRoute returns the service account selected by the route.
func (s *Server) getAccountRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("accountId")
	if !validHexBytes(id, 16) {
		writeAPIError(w, http.StatusNotFound, "service account not found")
		return
	}
	account, err := s.getServiceAccount(r.Context(), id)
	if err != nil {
		writeAccountError(w, err, "get")
		return
	}
	writeJSON(w, http.StatusOK, account)
}

// replaceAccountRoute replaces service-account metadata and scopes.
func (s *Server) replaceAccountRoute(w http.ResponseWriter, r *http.Request) {
	if !validHexBytes(r.PathValue("accountId"), 16) {
		writeAPIError(w, http.StatusNotFound, "service account not found")
		return
	}
	s.replaceAccountHandler(w, r, r.PathValue("accountId"))
}

// deleteAccountRoute removes the selected service account.
func (s *Server) deleteAccountRoute(w http.ResponseWriter, r *http.Request) {
	if !validHexBytes(r.PathValue("accountId"), 16) {
		writeAPIError(w, http.StatusNotFound, "service account not found")
		return
	}
	s.deleteAccountHandler(w, r, r.PathValue("accountId"))
}

// rotateAccountRoute rotates the selected account token without changing scopes.
func (s *Server) rotateAccountRoute(w http.ResponseWriter, r *http.Request) {
	if !validHexBytes(r.PathValue("accountId"), 16) {
		writeAPIError(w, http.StatusNotFound, "service account not found")
		return
	}
	s.rotateAccountHandler(w, r, r.PathValue("accountId"))
}

// replaceAccountHandler protects the active administrator and replaces validated scopes.
func (s *Server) replaceAccountHandler(w http.ResponseWriter, r *http.Request, id string) {
	var input serviceAccountInput
	if !decodeJSONBody(w, r, &input) {
		return
	}
	principal, _ := principalFor(r)
	// An expiry removes access later just as surely as disabling does now.
	// Another administrator may set one; recover-admin restores lost access.
	if principal.ServiceAccountID == id && (input.Disabled || input.ExpiresAt != nil || !containsRole(input.Roles, RoleAdministrator)) {
		writeAPIError(w, http.StatusConflict, "cannot remove access from the active administrator")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if err := s.validateServiceAccountInput(r.Context(), input); err != nil {
		writeAccountError(w, err, "update")
		return
	}
	account, err := s.store.ReplaceAccount(r.Context(), id, storeAccountInput(input), time.Now().UTC())
	if err != nil {
		writeAccountError(w, err, "update")
		return
	}
	writeJSON(w, http.StatusOK, serverAccount(account))
}

// deleteAccountHandler prevents an administrator from deleting its own identity.
func (s *Server) deleteAccountHandler(w http.ResponseWriter, r *http.Request, id string) {
	principal, _ := principalFor(r)
	if principal.ServiceAccountID == id {
		writeAPIError(w, http.StatusConflict, "cannot delete the active administrator")
		return
	}
	if err := s.store.DeleteAccount(r.Context(), id); err != nil {
		writeAccountError(w, err, "delete")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// containsRole reports whether a request includes one exact role.
func containsRole(roles []Role, want Role) bool {
	return slices.Contains(roles, want)
}

// listServiceAccounts converts store records into API role types.
func (s *Server) listServiceAccounts(ctx context.Context) ([]serviceAccount, error) {
	accounts, err := s.store.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]serviceAccount, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, serverAccount(account))
	}
	return result, nil
}

// getServiceAccount loads and converts one store record.
func (s *Server) getServiceAccount(ctx context.Context, id string) (serviceAccount, error) {
	account, err := s.store.Account(ctx, id)
	return serverAccount(account), err
}

// storeAccountInput converts API role types into dependency-free store values.
func storeAccountInput(input serviceAccountInput) store.AccountInput {
	roles := make([]string, len(input.Roles))
	for index, role := range input.Roles {
		roles[index] = string(role)
	}
	return store.AccountInput{Name: input.Name, Description: input.Description, Roles: roles, AllAgents: input.AllAgents, Agents: append([]string(nil), input.Agents...), ExpiresAt: input.ExpiresAt, Disabled: input.Disabled}
}

// serverAccount converts a dependency-free store account into its API projection.
func serverAccount(account store.Account) serviceAccount {
	roles := make([]Role, len(account.Roles))
	for index, role := range account.Roles {
		roles[index] = Role(role)
	}
	// The API contract requires an array, so an account without assigned
	// agents (for example an all_agents administrator) reports [] instead of null.
	agents := append(make([]string, 0, len(account.Agents)), account.Agents...)
	return serviceAccount{
		ID: account.ID, Name: account.Name, Description: account.Description, Roles: roles,
		AllAgents: account.AllAgents, Agents: agents, ExpiresAt: formatAPIOptionalTimestamp(account.ExpiresAt),
		Disabled: account.Disabled, CreatedAt: formatAPITimestamp(account.CreatedAt), UpdatedAt: formatAPITimestamp(account.UpdatedAt),
		LastUsedAt: formatAPIOptionalTimestamp(account.LastUsedAt),
	}
}

// writeAccountError maps stable store and validation outcomes to public responses.
func writeAccountError(w http.ResponseWriter, err error, operation string) {
	switch {
	case errors.Is(err, errInvalidAccount):
		writeAPIError(w, http.StatusBadRequest, "invalid service account")
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "service account not found")
	case errors.Is(err, store.ErrConflict):
		writeAPIError(w, http.StatusConflict, "service account conflicts with current state")
	default:
		writeAPIError(w, http.StatusInternalServerError, "could not "+operation+" service account")
	}
}
