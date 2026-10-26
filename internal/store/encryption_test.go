// File purpose: Verifies that database files are encrypted at rest and open only with their key.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"golang.org/x/crypto/xts"
)

// TestDatabaseFilesContainNoPlaintext checks the main file and the live WAL
// for row data and for the plaintext SQLite header.
func TestDatabaseFilesContainNoPlaintext(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	psk := strings.Repeat("5e", 32)
	if err := database.PutAgent(ctx, "plaintext-probe-agent", psk, "10.99.0.2", false, now); err != nil {
		t.Fatal(err)
	}
	content := instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: []string{"https://plaintext-probe.example/secret-path"}}
	if _, err := database.UpdateDesiredStates(ctx, "content", "test", []string{"plaintext-probe-agent"}, DesiredChange{Content: &content}, now); err != nil {
		t.Fatal(err)
	}
	markers := [][]byte{[]byte(psk), []byte("plaintext-probe-agent"), []byte("plaintext-probe.example"), []byte("SQLite format 3")}
	inspect := func(stage string) {
		t.Helper()
		files, err := filepath.Glob(path + "*")
		if err != nil {
			t.Fatal(err)
		}
		inspected := 0
		for _, file := range files {
			if strings.HasSuffix(file, "-shm") {
				continue // The WAL index holds page numbers and checksums only.
			}
			contents, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if len(contents) == 0 {
				continue
			}
			inspected++
			for _, marker := range markers {
				if bytes.Contains(contents, marker) {
					t.Fatalf("%s: %s contains plaintext %q", stage, filepath.Base(file), marker)
				}
			}
		}
		if inspected == 0 {
			t.Fatalf("%s: no database file was inspected", stage)
		}
	}
	if wal, err := os.Stat(path + "-wal"); err != nil || wal.Size() == 0 {
		t.Fatalf("expected live WAL contents: %v", err)
	}
	inspect("open")
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	inspect("closed")
}

// TestOpenRejectsWrongKeyWithoutChangingFile verifies key mismatch detection.
func TestOpenRejectsWrongKeyWithoutChangingFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	before := fileDigest(t, path)
	wrong := bytes.Repeat([]byte{0x43}, KeySize)
	if opened, err := Open(ctx, path, wrong); !errors.Is(err, ErrKeyMismatch) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("wrong key error = %v, want key mismatch", err)
	}
	if after := fileDigest(t, path); after != before {
		t.Fatal("opening with a wrong key changed the database file")
	}
	reopened, err := Open(ctx, path, testKey)
	if err != nil {
		t.Fatalf("correct key after a rejected key: %v", err)
	}
	_ = reopened.Close()
}

// TestOpenRequiresExistingDatabase keeps service start from creating an empty authority.
func TestOpenRequiresExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	if opened, err := Open(context.Background(), path, testKey); err == nil {
		_ = opened.Close()
		t.Fatal("missing database was opened")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open created a database file: %v", err)
	}
}

// TestCreateRefusesExistingFile keeps bootstrap from replacing an authority.
func TestCreateRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if created, err := Create(context.Background(), path, testKey); !errors.Is(err, os.ErrExist) {
		if created != nil {
			_ = created.Close()
		}
		t.Fatalf("create over existing file error = %v", err)
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != "existing" {
		t.Fatalf("existing file changed: %q %v", contents, err)
	}
}

// TestCreatePreservesOrphanedSidecars prevents a new authority from consuming
// recoverable journals or deleting names that belong to an earlier database.
func TestCreatePreservesOrphanedSidecars(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		for _, symlink := range []bool{false, true} {
			name := suffix
			if symlink {
				name += "-dangling-symlink"
			}
			t.Run(name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "controller.db")
				sidecar := path + suffix
				if symlink {
					if err := os.Symlink("recoverable-state", sidecar); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(sidecar, []byte("recoverable state"), 0o600); err != nil {
					t.Fatal(err)
				}
				if created, err := Create(context.Background(), path, testKey); !errors.Is(err, os.ErrExist) {
					if created != nil {
						_ = created.Close()
					}
					t.Fatalf("create with existing sidecar error = %v, want already exists", err)
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refused creation left a database: %v", err)
				}
				if symlink {
					if target, err := os.Readlink(sidecar); err != nil || target != "recoverable-state" {
						t.Fatalf("orphaned symlink changed: %q, %v", target, err)
					}
				} else if contents, err := os.ReadFile(sidecar); err != nil || string(contents) != "recoverable state" {
					t.Fatalf("orphaned sidecar changed: %q, %v", contents, err)
				}
			})
		}
	}
}

// TestFailedCreateKeepsExistingDatabase keeps a rejected Create from discarding
// a database that it did not create.
func TestFailedCreateKeepsExistingDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	before := fileDigest(t, path)
	if created, err := Create(ctx, path, make([]byte, KeySize-1)); err == nil {
		_ = created.Close()
		t.Fatal("create with a malformed key succeeded")
	}
	if after := fileDigest(t, path); after != before {
		t.Fatal("a failed create changed the existing database")
	}
	reopened, err := Open(ctx, path, testKey)
	if err != nil {
		t.Fatalf("existing database no longer opens: %v", err)
	}
	_ = reopened.Close()
}

// serviceID stands for the unprivileged account that owns the database; it
// need not exist.
const serviceID = 65534

// fileOwner returns the numeric owner of a file without following symlinks.
func fileOwner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file ownership is unavailable")
	}
	return owner.Uid, owner.Gid
}

// serviceOwner hands path to the service account where the caller may assign
// owners, which takes root, and otherwise leaves it alone. It returns the owner
// that the database files must then share. The ownership tests never skip: as
// root they check a real transfer, and for any other user that nothing moves.
func serviceOwner(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	_ = os.Chown(path, serviceID, serviceID)
	return fileOwner(t, path)
}

// TestOpenSharesDatabaseOwnership checks that the WAL files created by a
// command belong to the database owner, so the service can reuse them if a root
// command dies before it cleans up.
func TestOpenSharesDatabaseOwnership(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	created, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID := serviceOwner(t, path)
	opened, err := Open(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if uid, gid := fileOwner(t, path+suffix); uid != wantUID || gid != wantGID {
			t.Fatalf("%s owner = %d:%d, want %d:%d", suffix, uid, gid, wantUID, wantGID)
		}
	}
}

// TestShareOwnershipDoesNotFollowSymlinks keeps root from re-owning a file that
// the owner of the state directory points a WAL name at.
func TestShareOwnershipDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	database, victim := filepath.Join(dir, "controller.db"), filepath.Join(dir, "victim")
	for _, path := range []string{database, victim} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	serviceOwner(t, database)
	if err := os.Symlink(victim, database+"-wal"); err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID := fileOwner(t, victim)
	shareOwnership(database)
	if uid, gid := fileOwner(t, victim); uid != wantUID || gid != wantGID {
		t.Fatalf("symlink target owner = %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
	}
}

// TestCreatedDatabaseIsPrivate checks the mode of a new database file.
func TestCreatedDatabaseIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.db")
	created, err := Create(context.Background(), path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", info.Mode().Perm())
	}
}

// TestOpenRejectsInvalidKeyLength refuses truncated or oversized keys.
func TestOpenRejectsInvalidKeyLength(t *testing.T) {
	for _, length := range []int{0, 32, KeySize - 1, KeySize + 1} {
		path := filepath.Join(t.TempDir(), "controller.db")
		if created, err := Create(context.Background(), path, make([]byte, length)); err == nil {
			_ = created.Close()
			t.Fatalf("key length %d was accepted", length)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected key length %d left a database file: %v", length, err)
		}
	}
}

// TestDatabaseFormatIsAES256XTS decrypts a closed database without the driver.
// Deployed databases depend on this format: AES-256-XTS over 512-byte sectors
// with the sector index as tweak. A driver update that changes it must fail here.
func TestDatabaseFormatIsAES256XTS(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := Create(ctx, path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutAgent(ctx, "format-probe-agent", strings.Repeat("ab", 32), "10.99.0.2", false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const sector = 512
	if len(ciphertext) == 0 || len(ciphertext)%sector != 0 {
		t.Fatalf("database size %d is not a whole number of %d-byte sectors", len(ciphertext), sector)
	}
	cipher, err := xts.NewCipher(aes.NewCipher, testKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += sector {
		cipher.Decrypt(plaintext[offset:offset+sector], ciphertext[offset:offset+sector], uint64(offset/sector))
	}
	if !bytes.HasPrefix(plaintext, []byte("SQLite format 3\x00")) {
		t.Fatalf("decrypted header = %q", plaintext[:16])
	}
	if !bytes.Contains(plaintext, []byte("format-probe-agent")) {
		t.Fatal("decrypted database lacks the inserted row")
	}
}

// fileDigest returns the SHA-256 digest of a file for change detection.
func fileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(contents)
}
