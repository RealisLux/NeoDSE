// File purpose: Verifies that maintenance database opens cannot follow symbolic links into unrelated files.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/vfs"
)

// TestOpenRefusesSymlinks preserves both existing authorities and empty files
// that a privileged maintenance command would otherwise initialize as a database.
func TestOpenRefusesSymlinks(t *testing.T) {
	for _, existingDatabase := range []bool{false, true} {
		name := "empty-file"
		if existingDatabase {
			name = "database"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			victim := filepath.Join(directory, "victim")
			if existingDatabase {
				database, err := Create(context.Background(), victim, testKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := database.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(victim, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			before := fileDigest(t, victim)
			for _, parentLink := range []bool{false, true} {
				path := filepath.Join(directory, "controller.db")
				target := victim
				if parentLink {
					path = filepath.Join(directory, "linked-directory")
					target = directory
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				if parentLink {
					path = filepath.Join(path, "victim")
				}
				if database, err := Open(context.Background(), path, testKey); err == nil {
					_ = database.Close()
					t.Fatal("opened a database through a symbolic link")
				}
				if after := fileDigest(t, victim); after != before {
					t.Fatal("rejected database open changed the symlink target")
				}
			}
		})
	}
}

// TestJournalDirectorySyncPrecedesWrites verifies real encrypted SQLite writes
// fail when a new journal cannot be durably published, instead of acknowledging
// a transaction whose journal name could disappear after power loss.
func TestJournalDirectorySyncPrecedesWrites(t *testing.T) {
	for _, failSync := range []bool{false, true} {
		name := "success"
		if failSync {
			name = "sync-failure"
		}
		t.Run(name, func(t *testing.T) {
			const filesystemName = "neodse-journal-sync-test"
			attempts := 0
			syncFailure := errors.New("injected journal directory sync failure")
			vfs.Register(filesystemName, noSymlinkVFS{
				VFS: vfs.Find("xts"),
				syncDirectory: func(path string) error {
					// The callback must run after the actual journal is created.
					if _, err := os.Stat(path); err != nil {
						t.Errorf("journal absent before directory synchronization: %v", err)
						return err
					}
					if strings.HasSuffix(path, "-wal") {
						attempts++
						if failSync {
							return syncFailure
						}
					}
					return syncDatabaseDirectory(path)
				},
			})
			defer vfs.Unregister(filesystemName)
			path := filepath.Join(t.TempDir(), "controller.db")
			connection, err := sqlite3.Open("file:" + path + "?vfs=" + filesystemName)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			err = connection.Exec("PRAGMA hexkey='" + hex.EncodeToString(testKey) + "'; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE durable(value TEXT); INSERT INTO durable VALUES('committed')")
			if attempts == 0 {
				t.Fatal("SQLite wrote without synchronizing the WAL directory")
			}
			if failSync && err == nil {
				t.Fatal("SQLite acknowledged writes after directory synchronization failed")
			}
			if !failSync && err != nil {
				t.Fatalf("write with a synchronized journal: %v", err)
			}
		})
	}
}
