// File purpose: Persists service accounts, scopes, token rotation, and constant-time authentication data.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Account is the durable public projection of a service account without its token.
type Account struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Roles       []string   `json:"roles"`
	AllAgents   bool       `json:"all_agents"`
	Agents      []string   `json:"agents"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// AccountInput contains validated account attributes supplied by the server API.
type AccountInput struct {
	Name        string
	Description string
	Roles       []string
	AllAgents   bool
	Agents      []string
	ExpiresAt   *time.Time
	Disabled    bool
}

// Authentication is the scoped identity returned after token verification.
type Authentication struct {
	AccountID string
	Roles     []string
	AllAgents bool
	Agents    []string
}

// CreateAccount atomically creates an account and returns its token exactly once.
func (store *Store) CreateAccount(ctx context.Context, input AccountInput, requireEmpty bool, now time.Time) (Account, string, error) {
	identifier, tokenID, secret, err := accountSecrets()
	if err != nil {
		return Account{}, "", err
	}
	token := "nds_" + tokenID + "_" + secret
	digest := sha256.Sum256([]byte(token))
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, "", err
	}
	defer tx.Rollback()
	if requireEmpty {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_accounts`).Scan(&count); err != nil {
			return Account{}, "", err
		}
		if count != 0 {
			return Account{}, "", ErrConflict
		}
	}
	stamp := now.UTC().Format(time.RFC3339)
	var expiry any
	if input.ExpiresAt != nil {
		expiry = input.ExpiresAt.UTC().Format(time.RFC3339)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO service_accounts(id,name,description,all_agents,token_id,token_hash,expires_at,disabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		identifier, input.Name, input.Description, input.AllAgents, tokenID, digest[:], expiry, input.Disabled, stamp, stamp)
	if err != nil {
		return Account{}, "", mapSQLError(err)
	}
	if err := replaceAccountScopes(ctx, tx, identifier, input.Roles, input.Agents); err != nil {
		return Account{}, "", err
	}
	// Resolve the response before committing. A failed projection must not leave
	// a bootstrap account whose one-time token can no longer be retrieved.
	account, err := loadAccount(ctx, tx, identifier)
	if err != nil {
		return Account{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, "", err
	}
	return account, token, nil
}

// ReplaceAccount updates mutable account attributes and replaces all scopes atomically.
func (store *Store) ReplaceAccount(ctx context.Context, id string, input AccountInput, now time.Time) (Account, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	var expiry any
	if input.ExpiresAt != nil {
		expiry = input.ExpiresAt.UTC().Format(time.RFC3339)
	}
	result, err := tx.ExecContext(ctx, `UPDATE service_accounts SET name=?,description=?,all_agents=?,expires_at=?,disabled=?,updated_at=? WHERE id=?`,
		input.Name, input.Description, input.AllAgents, expiry, input.Disabled, now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return Account{}, mapSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Account{}, err
	}
	if count == 0 {
		return Account{}, ErrNotFound
	}
	if err := replaceAccountScopes(ctx, tx, id, input.Roles, input.Agents); err != nil {
		return Account{}, err
	}
	account, err := loadAccount(ctx, tx, id)
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return account, nil
}

// RotateAccountToken replaces token material and returns the new token exactly once.
func (store *Store) RotateAccountToken(ctx context.Context, id string, now time.Time) (string, error) {
	_, tokenID, secret, err := accountSecrets()
	if err != nil {
		return "", err
	}
	token := "nds_" + tokenID + "_" + secret
	digest := sha256.Sum256([]byte(token))
	result, err := store.db.ExecContext(ctx, `UPDATE service_accounts SET token_id=?,token_hash=?,updated_at=? WHERE id=?`, tokenID, digest[:], now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return "", err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", ErrNotFound
	}
	return token, nil
}

// RestoreAdministrator creates the named account, or restores it, as an
// enabled, non-expiring administrator for all agents and returns its new token
// exactly once. Host-local recovery uses it when every administrator token has
// been lost, disabled or has expired.
func (store *Store) RestoreAdministrator(ctx context.Context, name string, now time.Time) (Account, string, error) {
	identifier, tokenID, secret, err := accountSecrets()
	if err != nil {
		return Account{}, "", err
	}
	token := "nds_" + tokenID + "_" + secret
	digest := sha256.Sum256([]byte(token))
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, "", mapSQLError(err)
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339)
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id FROM service_accounts WHERE name=?`, name).Scan(&existing)
	switch {
	case err == nil:
		identifier = existing
		_, err = tx.ExecContext(ctx, `UPDATE service_accounts SET all_agents=1,token_id=?,token_hash=?,expires_at=NULL,disabled=0,updated_at=? WHERE id=?`,
			tokenID, digest[:], stamp, identifier)
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO service_accounts(id,name,description,all_agents,token_id,token_hash,expires_at,disabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			identifier, name, "Restored on the controller host", true, tokenID, digest[:], nil, false, stamp, stamp)
	}
	if err != nil {
		return Account{}, "", mapSQLError(err)
	}
	if err := replaceAccountScopes(ctx, tx, identifier, []string{"administrator"}, nil); err != nil {
		return Account{}, "", mapSQLError(err)
	}
	account, err := loadAccount(ctx, tx, identifier)
	if err != nil {
		return Account{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, "", mapSQLError(err)
	}
	return account, token, nil
}

// DeleteAccount removes an account and its scopes.
func (store *Store) DeleteAccount(ctx context.Context, id string) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM service_accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// Accounts lists public account projections in stable name order.
func (store *Store) Accounts(ctx context.Context) ([]Account, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM service_accounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identifiers []string
	for rows.Next() {
		var identifier string
		if err := rows.Scan(&identifier); err != nil {
			return nil, err
		}
		identifiers = append(identifiers, identifier)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	accounts := make([]Account, 0, len(identifiers))
	for _, identifier := range identifiers {
		account, err := loadAccount(ctx, tx, identifier)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, mapSQLError(tx.Commit())
}

// Account returns one public account projection with sorted roles and agents.
func (store *Store) Account(ctx context.Context, id string) (Account, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, mapSQLError(err)
	}
	defer tx.Rollback()
	account, err := loadAccount(ctx, tx, id)
	if err != nil {
		return Account{}, err
	}
	return account, mapSQLError(tx.Commit())
}

// loadAccount reads metadata and scopes from the caller's committed or pending snapshot.
func loadAccount(ctx context.Context, tx *sql.Tx, id string) (Account, error) {
	var account Account
	var expiry, lastUsed sql.NullString
	var allAgents, disabled int
	var created, updated string
	err := tx.QueryRowContext(ctx, `SELECT id,name,description,all_agents,expires_at,disabled,created_at,updated_at,last_used_at FROM service_accounts WHERE id=?`, id).Scan(
		&account.ID, &account.Name, &account.Description, &allAgents, &expiry, &disabled, &created, &updated, &lastUsed)
	if err != nil {
		return account, mapSQLError(err)
	}
	account.AllAgents = allAgents != 0
	account.Disabled = disabled != 0
	if account.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return account, err
	}
	if account.UpdatedAt, err = time.Parse(time.RFC3339, updated); err != nil {
		return account, err
	}
	if account.ExpiresAt, err = parseNullableTime(expiry); err != nil {
		return account, err
	}
	if account.LastUsedAt, err = parseNullableTime(lastUsed); err != nil {
		return account, err
	}
	account.Roles, err = databaseValues(ctx, tx, `SELECT role FROM service_account_roles WHERE service_account_id=? ORDER BY role`, id)
	if err != nil {
		return account, err
	}
	account.Agents, err = databaseValues(ctx, tx, `SELECT agent_id FROM service_account_agents WHERE service_account_id=? ORDER BY agent_id`, id)
	return account, err
}

// AuthenticateAccount verifies token material and loads account scopes in one transaction.
func (store *Store) AuthenticateAccount(ctx context.Context, tokenID, token string, now time.Time) (Authentication, error) {
	return store.AuthenticateAccountDigest(ctx, tokenID, sha256.Sum256([]byte(token)), now)
}

// AuthenticateAccountDigest revalidates a live capability without retaining its bearer secret.
func (store *Store) AuthenticateAccountDigest(ctx context.Context, tokenID string, want [sha256.Size]byte, now time.Time) (Authentication, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Authentication{}, mapSQLError(err)
	}
	defer tx.Rollback()
	var authentication Authentication
	var digest []byte
	var disabled, allAgents int
	var expiry sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,token_hash,disabled,all_agents,expires_at FROM service_accounts WHERE token_id=?`, tokenID).Scan(
		&authentication.AccountID, &digest, &disabled, &allAgents, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return Authentication{}, ErrNotFound
	}
	if err != nil {
		return Authentication{}, fmt.Errorf("%w: authenticate account: %v", ErrUnavailable, err)
	}
	if disabled != 0 || !hmac.Equal(digest, want[:]) {
		return Authentication{}, ErrNotFound
	}
	if expiry.Valid {
		deadline, parseErr := time.Parse(time.RFC3339, expiry.String)
		if parseErr != nil || !deadline.After(now) {
			return Authentication{}, ErrNotFound
		}
	}
	authentication.AllAgents = allAgents != 0
	authentication.Roles, err = databaseValues(ctx, tx, `SELECT role FROM service_account_roles WHERE service_account_id=?`, authentication.AccountID)
	if err != nil {
		return Authentication{}, mapSQLError(err)
	}
	if len(authentication.Roles) == 0 {
		return Authentication{}, ErrNotFound
	}
	authentication.Agents, err = databaseValues(ctx, tx, `SELECT agent_id FROM service_account_agents WHERE service_account_id=?`, authentication.AccountID)
	if err != nil {
		return Authentication{}, mapSQLError(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE service_accounts SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at<?)`,
		now.UTC().Format(time.RFC3339), authentication.AccountID, now.Add(-5*time.Minute).UTC().Format(time.RFC3339))
	if err != nil {
		return Authentication{}, mapSQLError(err)
	}
	return authentication, mapSQLError(tx.Commit())
}

// replaceAccountScopes replaces role and agent join rows inside the caller's transaction.
func replaceAccountScopes(ctx context.Context, tx *sql.Tx, id string, roles, agents []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_account_roles WHERE service_account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_account_agents WHERE service_account_id=?`, id); err != nil {
		return err
	}
	sort.Strings(roles)
	sort.Strings(agents)
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, `INSERT INTO service_account_roles(service_account_id,role) VALUES(?,?)`, id, role); err != nil {
			return err
		}
	}
	for _, agent := range agents {
		if _, err := tx.ExecContext(ctx, `INSERT INTO service_account_agents(service_account_id,agent_id) VALUES(?,?)`, id, agent); err != nil {
			return err
		}
	}
	return nil
}

// databaseValues scans a single string column from a concrete queryer.
func databaseValues(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query, id string) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// accountSecrets generates independent account, token, and secret identifiers.
func accountSecrets() (string, string, string, error) {
	values := make([]string, 3)
	for index, size := range []int{16, 16, 32} {
		buffer := make([]byte, size)
		if _, err := rand.Read(buffer); err != nil {
			return "", "", "", err
		}
		values[index] = hex.EncodeToString(buffer)
	}
	return values[0], values[1], values[2], nil
}

// parseNullableTime decodes an optional RFC3339 database timestamp.
func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value.String)
	return &parsed, err
}
