// File purpose: Verifies the locked controller start, root-only unlock, passphrase change and maintenance access.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/provisioning"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/storekey"
)

const testPassphrase = "correct horse battery staple"

// fastKeyslotParams keeps controller tests quick; production uses storekey.DefaultParams.
var fastKeyslotParams = storekey.Params{Time: 1, MemoryKiB: 1024, Threads: 1}

// lockedTestController creates an encrypted database and keyslot for one locked controller.
func lockedTestController(t *testing.T) (*Server, string) {
	t.Helper()
	directory := t.TempDir()
	cfg := Config{}
	cfg.Server.Database = filepath.Join(directory, "controller.db")
	database, err := store.Create(context.Background(), cfg.Server.Database, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PutAgent(context.Background(), "display", strings.Repeat("ab", 32), "10.99.0.2", false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	writeTestKeyslot(t, cfg.Server.Database, testDatabaseKey, testPassphrase)
	// Unix socket paths are limited to 108 bytes, so avoid long test-named directories.
	socketDirectory, err := os.MkdirTemp("", "neodse-unlock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
	return newServer(cfg, "test"), filepath.Join(socketDirectory, "unlock.sock")
}

// writeTestKeyslot seals key under passphrase next to the database.
func writeTestKeyslot(t *testing.T, databasePath string, key []byte, passphrase string) {
	t.Helper()
	sealed, err := storekey.SealWith(key, []byte(passphrase), fastKeyslotParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storekey.Path(databasePath), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
}

// passphraseInput returns a pipe that supplies text as non-terminal input.
func passphraseInput(t *testing.T, text string) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if _, err := io.WriteString(writer, text); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return reader
}

// startLocked runs waitForUnlock in the background and waits for its socket.
func startLocked(t *testing.T, controller *Server, socketPath string, uid uint32) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.waitForUnlock(ctx, socketPath, uid) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case err := <-result:
			cancel()
			t.Fatalf("controller stopped before listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("unlock socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		if controller.store != nil {
			_ = controller.store.Close()
		}
	})
	return cancel, result
}

// TestLockedControllerUnlocksWithPassphrase keeps the database closed until the right passphrase arrives.
func TestLockedControllerUnlocksWithPassphrase(t *testing.T) {
	controller, socketPath := lockedTestController(t)
	_, result := startLocked(t, controller, socketPath, uint32(os.Getuid()))
	var output bytes.Buffer
	err := requestUnlock(context.Background(), socketPath, passphraseInput(t, "wrong passphrase value\n"), &output)
	if err == nil || !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	select {
	case err := <-result:
		t.Fatalf("controller left the locked state after a wrong passphrase: %v", err)
	default:
	}
	if controller.store != nil {
		t.Fatal("database opened after a wrong passphrase")
	}
	if err := requestUnlock(context.Background(), socketPath, passphraseInput(t, testPassphrase+"\n"), &output); err != nil {
		t.Fatalf("correct passphrase: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("unlock result: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller did not finish unlocking")
	}
	if controller.store == nil {
		t.Fatal("database is not open after unlock")
	}
	if exists, err := controller.store.AgentExists(context.Background(), "display"); err != nil || !exists {
		t.Fatalf("unlocked database lost state: exists=%t error=%v", exists, err)
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlock socket remains after unlock: %v", err)
	}
	if !strings.Contains(output.String(), "unlocked") {
		t.Fatalf("client output = %q", output.String())
	}
	if err := requestUnlock(context.Background(), socketPath, passphraseInput(t, testPassphrase+"\n"), &output); !errors.Is(err, errControllerNotLocked) {
		t.Fatalf("second unlock error = %v", err)
	}
}

// TestLockedControllerRejectsOtherUsers accepts unlock requests only from the allowed UID.
func TestLockedControllerRejectsOtherUsers(t *testing.T) {
	controller, socketPath := lockedTestController(t)
	cancel, result := startLocked(t, controller, socketPath, uint32(os.Getuid())+1)
	err := requestUnlock(context.Background(), socketPath, passphraseInput(t, testPassphrase+"\n"), io.Discard)
	if err == nil {
		t.Fatal("unlock from another UID succeeded")
	}
	if controller.store != nil {
		t.Fatal("database opened for another UID")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stop while locked returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("locked controller did not stop")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlock socket remains after stop: %v", err)
	}
}

// TestUnlockWithMismatchedKeyslotFailsStartup exits when the passphrase opens a keyslot for another database.
func TestUnlockWithMismatchedKeyslotFailsStartup(t *testing.T) {
	controller, socketPath := lockedTestController(t)
	writeTestKeyslot(t, controller.config.Server.Database, bytes.Repeat([]byte{0x99}, store.KeySize), testPassphrase)
	_, result := startLocked(t, controller, socketPath, uint32(os.Getuid()))
	err := requestUnlock(context.Background(), socketPath, passphraseInput(t, testPassphrase+"\n"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "controller startup failed") {
		t.Fatalf("client error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, store.ErrKeyMismatch) {
			t.Fatalf("startup error = %v, want key mismatch", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller kept waiting after a failed startup")
	}
	if controller.store != nil {
		t.Fatal("store left open after failed startup")
	}
}

// TestLockedControllerRequiresKeyslotAndDatabase fails before listening when either file is missing.
func TestLockedControllerRequiresKeyslotAndDatabase(t *testing.T) {
	for name, remove := range map[string]func(string) string{
		"keyslot":  storekey.Path,
		"database": func(database string) string { return database },
	} {
		t.Run(name, func(t *testing.T) {
			controller, socketPath := lockedTestController(t)
			if err := os.Remove(remove(controller.config.Server.Database)); err != nil {
				t.Fatal(err)
			}
			err := controller.waitForUnlock(context.Background(), socketPath, uint32(os.Getuid()))
			if err == nil {
				t.Fatal("locked controller started without its " + name)
			}
			if _, statErr := os.Lstat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("socket created despite missing %s: %v", name, statErr)
			}
		})
	}
}

// TestUnlockSocketReplacesOnlyStaleSockets refuses to delete a regular file at the socket path.
func TestUnlockSocketReplacesOnlyStaleSockets(t *testing.T) {
	controller, socketPath := lockedTestController(t)
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controller.waitForUnlock(context.Background(), socketPath, uint32(os.Getuid())); err == nil {
		t.Fatal("regular file at the socket path was accepted")
	}
	if contents, err := os.ReadFile(socketPath); err != nil || string(contents) != "not a socket" {
		t.Fatalf("regular file was changed: %q %v", contents, err)
	}
	stale, err := listenUnlockSocket(filepath.Join(filepath.Dir(socketPath), "stale.sock"))
	if err != nil {
		t.Fatal(err)
	}
	stalePath := stale.Addr().String()
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	replacement, err := listenUnlockSocket(stalePath)
	if err != nil {
		t.Fatalf("stale socket was not replaced: %v", err)
	}
	info, err := os.Lstat(stalePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v", info, err)
	}
	_ = replacement.Close()
}

// TestRequestUnlockWithoutLockedController fails before reading the passphrase.
func TestRequestUnlockWithoutLockedController(t *testing.T) {
	input := passphraseInput(t, testPassphrase+"\n")
	err := requestUnlock(context.Background(), filepath.Join(t.TempDir(), "absent.sock"), input, io.Discard)
	if !errors.Is(err, errControllerNotLocked) {
		t.Fatalf("error = %v", err)
	}
	remaining, readErr := io.ReadAll(input)
	if readErr != nil || string(remaining) != testPassphrase+"\n" {
		t.Fatalf("passphrase was consumed: %q %v", remaining, readErr)
	}
}

// TestReadUnlockRequestBounds accepts one bounded line and rejects anything else.
func TestReadUnlockRequestBounds(t *testing.T) {
	longest := strings.Repeat("a", storekey.MaxPassphraseBytes)
	for name, test := range map[string]struct {
		request string
		want    string
		valid   bool
	}{
		"one line":            {"secret value\n", "secret value", true},
		"ignores later bytes": {"secret value\nextra", "secret value", true},
		"longest passphrase":  {longest + "\n", longest, true},
		"empty line":          {"\n", "", false},
		"missing newline":     {"secret value", "", false},
		"over the limit":      {longest + "a\n", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readUnlockRequest(strings.NewReader(test.request))
			if (err == nil) != test.valid || string(got) != test.want {
				t.Fatalf("readUnlockRequest = %q, %v; want %q, valid=%t", got, err, test.want, test.valid)
			}
		})
	}
}

// TestRewrapKeyslotChangesPassphrase keeps the database key and replaces only the passphrase.
func TestRewrapKeyslotChangesPassphrase(t *testing.T) {
	controller, _ := lockedTestController(t)
	databasePath := controller.config.Server.Database
	write := func(path string, contents []byte) error { return provisioning.AtomicWrite(path, contents, 0o600) }
	before, err := os.ReadFile(storekey.Path(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"wrong current": "not the passphrase\nanother long passphrase\n",
		"short new":     testPassphrase + "\nshort\n",
		"missing new":   testPassphrase + "\n",
	} {
		if err := rewrapKeyslot(context.Background(), databasePath, passphraseInput(t, input), io.Discard, write); err == nil {
			t.Fatalf("%s: passphrase change succeeded", name)
		}
		if after, _ := os.ReadFile(storekey.Path(databasePath)); !bytes.Equal(after, before) {
			t.Fatalf("%s: rejected change modified the keyslot", name)
		}
	}
	const next = "a different and long passphrase"
	if err := rewrapKeyslot(context.Background(), databasePath, passphraseInput(t, testPassphrase+"\n"+next+"\n"), io.Discard, write); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(storekey.Path(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storekey.Unseal(sealed, []byte(testPassphrase)); !errors.Is(err, storekey.ErrIncorrectPassphrase) {
		t.Fatalf("old passphrase still opens the keyslot: %v", err)
	}
	key, err := storekey.Unseal(sealed, []byte(next))
	if err != nil || !bytes.Equal(key, testDatabaseKey) {
		t.Fatalf("new passphrase: key changed=%t error=%v", !bytes.Equal(key, testDatabaseKey), err)
	}
}

// TestOpenMaintenanceDatabaseRequiresPassphrase opens the database for root commands only with its passphrase.
func TestOpenMaintenanceDatabaseRequiresPassphrase(t *testing.T) {
	controller, _ := lockedTestController(t)
	if err := controller.openMaintenanceDatabase(context.Background(), passphraseInput(t, "not the passphrase\n"), io.Discard); !errors.Is(err, storekey.ErrIncorrectPassphrase) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	if controller.store != nil {
		t.Fatal("database opened with a wrong passphrase")
	}
	input := passphraseInput(t, testPassphrase+"\nNEODSE_PROVISIONING_VERSION=1\n")
	if err := controller.openMaintenanceDatabase(context.Background(), input, io.Discard); err != nil {
		t.Fatal(err)
	}
	defer controller.store.Close()
	if exists, err := controller.store.AgentExists(context.Background(), "display"); err != nil || !exists {
		t.Fatalf("maintenance database: exists=%t error=%v", exists, err)
	}
	remaining, err := io.ReadAll(input)
	if err != nil || string(remaining) != "NEODSE_PROVISIONING_VERSION=1\n" {
		t.Fatalf("input after the passphrase = %q, %v", remaining, err)
	}
}
