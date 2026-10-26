// File purpose: Opens the encrypted authoritative SQLite database and defines the concrete store shared by controller services.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package store owns NeoDSE's SQLite schema, queries, row decoding, and
// transactions. Callers work with domain records and never issue SQL.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

var (
	// ErrNotFound reports a missing record.
	ErrNotFound = errors.New("record not found")
	// ErrConflict reports a write that conflicts with an existing record.
	ErrConflict = errors.New("record conflicts with current state")
	// ErrUnavailable reports that the database could not complete an operation.
	ErrUnavailable = errors.New("store unavailable")
	// ErrInvalidState reports stored or supplied values outside the schema contract.
	ErrInvalidState = errors.New("invalid store state")
	// ErrKeyMismatch reports a key that cannot decrypt the database file.
	ErrKeyMismatch = errors.New("database key does not decrypt this database")
)

// KeySize is the length of the AES-256-XTS key that encrypts every database page.
const KeySize = 64

// migrationFiles contains the ordered schema applied transactionally.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// Store is the concrete owner of one SQLite connection pool.
type Store struct {
	db         *sql.DB
	statements preparedStatements
}

// Open decrypts, migrates, and verifies an existing authoritative database.
func Open(ctx context.Context, path string, key []byte) (*Store, error) {
	return open(ctx, path, key, false)
}

// Create initializes a new encrypted database and refuses to replace any file.
func Create(ctx context.Context, path string, key []byte) (*Store, error) {
	return open(ctx, path, key, true)
}

// open prepares the connection pool, then migrates and prepares statements.
func open(ctx context.Context, path string, key []byte, create bool) (store *Store, err error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("database key must be %d bytes", KeySize)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if create {
		if err = createEmptyFile(absolute); err != nil {
			return nil, fmt.Errorf("create database: %w", err)
		}
		// Only a file created by this call may be discarded when initialization fails.
		defer func() {
			if err != nil {
				removeDatabaseFiles(absolute)
			}
		}()
		if err = syncDatabaseDirectory(absolute); err != nil {
			return nil, fmt.Errorf("synchronize new database directory: %w", err)
		}
	}
	db, err := openDatabase(ctx, absolute, key)
	if err != nil {
		return nil, err
	}
	if err = migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	statements, err := prepareStatements(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, statements: statements}, nil
}

// CheckCreatePath refuses an existing database or SQLite sidecar. Orphaned
// sidecars can contain recoverable state and must never be consumed or removed
// while creating a different database at the same path.
func CheckCreatePath(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		candidate := path + suffix
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("%s: %w", candidate, os.ErrExist)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s: %w", candidate, err)
		}
	}
	return nil
}

// createEmptyFile reserves a new private database file after refusing orphaned
// sidecars. An empty file is a valid empty database, and O_EXCL keeps any
// existing database intact if another creator wins the race.
func createEmptyFile(path string) error {
	if err := CheckCreatePath(path); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

// removeDatabaseFiles discards a database that Create could not initialize.
func removeDatabaseFiles(path string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suffix)
	}
}

// openDatabase opens one existing AES-256-XTS encrypted SQLite file at an
// absolute path. The XTS VFS also encrypts the WAL and rollback journal with
// the same key; temporary tables stay in memory. The key is set before any page
// is read on each connection and is never part of the file name. The
// unencrypted -shm file holds only the WAL index, never row data.
func openDatabase(ctx context.Context, absolute string, key []byte) (*sql.DB, error) {
	uri := url.URL{Scheme: "file", Path: absolute}
	uri.RawQuery = url.Values{"vfs": {databaseVFS}, "mode": {"rw"}, "_txlock": {"immediate"}}.Encode()
	keyPragma := "PRAGMA hexkey='" + hex.EncodeToString(key) + "'"
	db, err := driver.Open(uri.String(), func(connection *sqlite3.Conn) error {
		if err := connection.Exec(keyPragma); err != nil {
			return err
		}
		return connection.Exec(`PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY`)
	})
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// The first statement reads the database header and so verifies the key.
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		if errors.Is(err, sqlite3.NOTADB) {
			return nil, ErrKeyMismatch
		}
		return nil, err
	}
	shareOwnership(absolute)
	return db, nil
}

// shareOwnership gives the WAL and shared-memory files the owner and group of
// the database. SQLite's unix VFS did this when it created them; this VFS
// creates them as the calling user, so a root command that is killed would
// leave files the service account cannot open. Lchown does not follow
// symlinks, and a failure keeps the caller's ownership.
func shareOwnership(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Lchown(path+suffix, int(owner.Uid), int(owner.Gid))
	}
}

// Close releases database resources after controller shutdown.
func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	return errors.Join(store.statements.close(), store.db.Close())
}

// Ping verifies that SQLite can execute work for readiness reporting.
func (store *Store) Ping(ctx context.Context) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("%w: database is not open", ErrUnavailable)
	}
	return mapSQLError(store.db.PingContext(ctx))
}

// migrate applies every embedded migration and records each version atomically.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)`); err != nil {
		return fail(err)
	}
	version, err := schemaVersion(ctx, tx)
	if err != nil {
		return fail(err)
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fail(fmt.Errorf("read embedded migrations: %w", err))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if version > len(entries) {
		return fail(fmt.Errorf("database schema version %d is newer than this binary", version))
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		migrationVersion, parseErr := strconv.Atoi(prefix)
		if !ok || parseErr != nil || migrationVersion < 1 {
			return fail(fmt.Errorf("invalid migration filename %q", entry.Name()))
		}
		if migrationVersion <= version {
			continue
		}
		if migrationVersion != version+1 {
			return fail(fmt.Errorf("missing database migration version %d", version+1))
		}
		contents, readErr := migrationFiles.ReadFile("migrations/" + entry.Name())
		if readErr != nil {
			return fail(fmt.Errorf("read migration %q: %w", entry.Name(), readErr))
		}
		if _, err = tx.ExecContext(ctx, string(contents)); err != nil {
			return fail(fmt.Errorf("apply migration %q: %w", entry.Name(), err))
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, migrationVersion, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fail(err)
		}
		version = migrationVersion
	}
	return tx.Commit()
}

// schemaVersion verifies that applied migrations form a contiguous sequence.
func schemaVersion(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	version := 0
	for rows.Next() {
		var applied int
		if err := rows.Scan(&applied); err != nil {
			return 0, err
		}
		if applied != version+1 {
			return 0, fmt.Errorf("database migration history is not contiguous at version %d", version+1)
		}
		version = applied
	}
	return version, rows.Err()
}

// mapSQLError converts SQLite outcomes into stable errors without exposing driver details to callers.
func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if errors.Is(err, sqlite3.CONSTRAINT_UNIQUE) || errors.Is(err, sqlite3.CONSTRAINT_PRIMARYKEY) {
		return ErrConflict
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidState) || errors.Is(err, ErrKeyMismatch) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
