// File purpose: Verifies account token handling, scope replacement, authentication, and transaction rollback.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestAccountProjectionFailuresRollbackMutations injects decoding failures at the
// durable boundary so a failed response cannot consume bootstrap or replace scopes.
func TestAccountProjectionFailuresRollbackMutations(t *testing.T) {
	for _, operation := range []string{"create", "replace"} {
		t.Run(operation, func(t *testing.T) {
			store := openTestStore(t)
			ctx := context.Background()
			input := AccountInput{Name: "administrator", Roles: []string{"administrator"}, AllAgents: true}
			now := time.Now().UTC()
			var previous Account
			var token string
			var err error
			trigger := `CREATE TRIGGER invalid_projection AFTER INSERT ON service_accounts BEGIN UPDATE service_accounts SET updated_at='invalid' WHERE id=NEW.id; END`
			if operation == "replace" {
				previous, token, err = store.CreateAccount(ctx, input, true, now)
				if err != nil {
					t.Fatal(err)
				}
				trigger = `CREATE TRIGGER invalid_projection AFTER UPDATE ON service_accounts BEGIN UPDATE service_accounts SET updated_at='invalid' WHERE id=NEW.id; END`
			}
			if _, err := store.db.ExecContext(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			if operation == "create" {
				_, returnedToken, err := store.CreateAccount(ctx, input, true, now)
				if err == nil || returnedToken != "" {
					t.Fatal("failed account projection returned a token or success")
				}
				var count int
				if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_accounts`).Scan(&count); err != nil || count != 0 {
					t.Fatalf("failed bootstrap consumed the empty database: count=%d error=%v", count, err)
				}
			} else {
				input.Name, input.Roles = "replacement", []string{"viewer"}
				if _, err := store.ReplaceAccount(ctx, previous.ID, input, now.Add(time.Minute)); err == nil {
					t.Fatal("invalid replacement projection succeeded")
				}
				restored, err := store.Account(ctx, previous.ID)
				if err != nil || !reflect.DeepEqual(restored, previous) {
					t.Fatalf("failed replacement changed account or scopes: %#v error=%v", restored, err)
				}
			}
			if _, err := store.db.ExecContext(ctx, `DROP TRIGGER invalid_projection`); err != nil {
				t.Fatal(err)
			}
			if operation == "create" {
				previous, token, err = store.CreateAccount(ctx, input, true, now)
				if err != nil {
					t.Fatalf("bootstrap could not be retried: %v", err)
				}
			}
			parts := strings.Split(token, "_")
			if authentication, err := store.AuthenticateAccount(ctx, parts[1], token, now); err != nil || authentication.AccountID != previous.ID {
				t.Fatalf("original token lost authority: %#v error=%v", authentication, err)
			}
		})
	}
}

// TestAccountAuthenticationAndRotation verifies account authentication and rotation.
func TestAccountAuthenticationAndRotation(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 15, 0, 0, 0, time.UTC)
	input := AccountInput{Name: "operator", Roles: []string{"viewer"}, Agents: []string{"display-01"}}
	account, token, err := store.CreateAccount(ctx, input, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateAccount(ctx, AccountInput{Name: "second", Roles: []string{"viewer"}, AllAgents: true}, true, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("second bootstrap account error=%v", err)
	}
	parts := strings.Split(token, "_")
	authentication, err := store.AuthenticateAccount(ctx, parts[1], token, now)
	if err != nil || authentication.AccountID != account.ID || len(authentication.Agents) != 1 {
		t.Fatalf("AuthenticateAccount() auth=%#v error=%v", authentication, err)
	}
	if _, err := store.AuthenticateAccount(ctx, parts[1], token+"00", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("incorrect token error = %v, want not found", err)
	}
	rotated, err := store.RotateAccountToken(ctx, account.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateAccount(ctx, parts[1], token, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token error = %v, want not found", err)
	}
	rotatedParts := strings.Split(rotated, "_")
	if _, err := store.AuthenticateAccount(ctx, rotatedParts[1], rotated, now.Add(time.Minute)); err != nil {
		t.Fatalf("rotated token authentication error = %v", err)
	}
}

// TestRestoreAdministratorRecoversLockedOutAuthority verifies host recovery
// re-enables a named administrator, or creates it, and replaces its token.
func TestRestoreAdministratorRecoversLockedOutAuthority(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 15, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Minute)
	original, oldToken, err := store.CreateAccount(ctx, AccountInput{Name: "admin", Roles: []string{"viewer"}, Agents: []string{"display-01"}, ExpiresAt: &expiry, Disabled: true}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	restored, token, err := store.RestoreAdministrator(ctx, "admin", later)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != original.ID || !reflect.DeepEqual(restored.Roles, []string{"administrator"}) || !restored.AllAgents ||
		len(restored.Agents) != 0 || restored.Disabled || restored.ExpiresAt != nil {
		t.Fatalf("restored account = %#v", restored)
	}
	if _, err := store.AuthenticateAccount(ctx, strings.Split(oldToken, "_")[1], oldToken, later); !errors.Is(err, ErrNotFound) {
		t.Fatalf("previous token error = %v, want not found", err)
	}
	authentication, err := store.AuthenticateAccount(ctx, strings.Split(token, "_")[1], token, later)
	if err != nil || authentication.AccountID != original.ID || !authentication.AllAgents {
		t.Fatalf("restored token authentication=%#v error=%v", authentication, err)
	}
	created, createdToken, err := store.RestoreAdministrator(ctx, "recovery-admin", later)
	if err != nil || created.ID == original.ID || created.Name != "recovery-admin" {
		t.Fatalf("created recovery account=%#v error=%v", created, err)
	}
	if _, err := store.AuthenticateAccount(ctx, strings.Split(createdToken, "_")[1], createdToken, later); err != nil {
		t.Fatalf("created recovery token error = %v", err)
	}
}

// TestReplaceAccountRollsBackInvalidScopes verifies replace account rolls back invalid scopes.
func TestReplaceAccountRollsBackInvalidScopes(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	now := time.Now().UTC()
	account, _, err := store.CreateAccount(context.Background(), AccountInput{Name: "operator", Roles: []string{"viewer"}, Agents: []string{"display-01"}}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ReplaceAccount(context.Background(), account.ID, AccountInput{Name: "changed", Roles: []string{"viewer", "viewer"}, Agents: []string{"display-01"}}, now.Add(time.Minute))
	if err == nil {
		t.Fatal("duplicate scope was accepted")
	}
	restored, err := store.Account(context.Background(), account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Name != "operator" || len(restored.Roles) != 1 {
		t.Fatalf("partial account update escaped rollback: %#v", restored)
	}
}

// TestAccountListingReplacementExpiryAndDeletion verifies account listing replacement expiry and deletion.
func TestAccountListingReplacementExpiryAndDeletion(t *testing.T) {
	store := openTestStore(t)
	putTestAgent(t, store, "display-01")
	ctx := context.Background()
	now := time.Now().UTC()
	account, token, err := store.CreateAccount(ctx, AccountInput{Name: "viewer", Description: "initial", Roles: []string{"viewer"}, AllAgents: true}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := store.Accounts(ctx)
	if err != nil || len(accounts) != 1 || accounts[0].ID != account.ID {
		t.Fatalf("Accounts()=%#v error=%v", accounts, err)
	}
	expires := now.Add(time.Hour)
	replaced, err := store.ReplaceAccount(ctx, account.ID, AccountInput{Name: "viewer", Description: "updated", Roles: []string{"viewer"}, Agents: []string{"display-01"}, ExpiresAt: &expires}, now.Add(time.Minute))
	if err != nil || replaced.Description != "updated" || replaced.ExpiresAt == nil {
		t.Fatalf("ReplaceAccount()=%#v error=%v", replaced, err)
	}
	parts := strings.Split(token, "_")
	if _, err := store.AuthenticateAccount(ctx, parts[1], token, expires.Add(time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token error=%v", err)
	}
	if err := store.DeleteAccount(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAccount(ctx, account.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete error=%v", err)
	}
}

// TestAccountMissingOperationsReturnTypedErrors verifies account missing operations return typed errors.
func TestAccountMissingOperationsReturnTypedErrors(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := AccountInput{Name: "missing", Roles: []string{"viewer"}, AllAgents: true}
	if _, err := store.ReplaceAccount(ctx, "missing", input, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace missing error=%v", err)
	}
	if _, err := store.RotateAccountToken(ctx, "missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate missing error=%v", err)
	}
	if _, err := store.Account(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load missing error=%v", err)
	}
}

// TestAccountNameConflictsPreserveExistingAuthority verifies duplicate names fail
// predictably without returning a token or changing existing account scopes.
func TestAccountNameConflictsPreserveExistingAuthority(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := AccountInput{Name: "operator", Roles: []string{"viewer"}, AllAgents: true}
	first, firstToken, err := store.CreateAccount(ctx, input, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, token, err := store.CreateAccount(ctx, input, false, now); !errors.Is(err, ErrConflict) || token != "" {
		t.Fatalf("duplicate create token=%q error=%v", token, err)
	}
	input.Name = "second operator"
	second, secondToken, err := store.CreateAccount(ctx, input, false, now)
	if err != nil {
		t.Fatal(err)
	}
	input.Name, input.Roles, input.Disabled = first.Name, []string{"administrator"}, true
	if _, err := store.ReplaceAccount(ctx, second.ID, input, now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate replace error=%v", err)
	}
	restored, err := store.Account(ctx, second.ID)
	if err != nil || !reflect.DeepEqual(restored, second) {
		t.Fatalf("conflicting replacement changed account: %#v error=%v", restored, err)
	}
	for _, token := range []string{firstToken, secondToken} {
		parts := strings.Split(token, "_")
		if _, err := store.AuthenticateAccount(ctx, parts[1], token, now); err != nil {
			t.Fatalf("conflict revoked existing token: %v", err)
		}
	}
	accounts, err := store.Accounts(ctx)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("conflict changed account count: count=%d error=%v", len(accounts), err)
	}
}
