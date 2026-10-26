// File purpose: Verifies provisioning command allowlists and atomic file behavior.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestReadWireGuardConfigRejectsSpecialFiles ensures enrollment cannot block on a FIFO.
func TestReadWireGuardConfigRejectsSpecialFiles(t *testing.T) {
	directory := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(directory, "fifo.conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"fifo.conf", "."} {
		if _, err := readWireGuardConfig(root, name); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("read %s: got %v, want regular-file rejection", name, err)
		}
	}
}

// TestReadWireGuardConfigBoundsAndConfinement verifies ordinary files remain readable without path escapes.
func TestReadWireGuardConfigBoundsAndConfinement(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "valid.conf"), []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "large.conf"), []byte(strings.Repeat("x", 1<<20+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(directory, "escape.conf")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	contents, err := readWireGuardConfig(root, "valid.conf")
	if err != nil || string(contents) != "[Interface]\n" {
		t.Fatalf("read valid configuration: contents=%q err=%v", contents, err)
	}
	for _, name := range []string{"large.conf", "escape.conf"} {
		if _, err := readWireGuardConfig(root, name); err == nil {
			t.Fatalf("read %s: invalid configuration was accepted", name)
		}
	}
}

// TestRunRejectsUnlistedExecutable verifies callers cannot select an arbitrary process.
func TestRunRejectsUnlistedExecutable(t *testing.T) {
	if _, err := Run("", "sh", "-c", "true"); err == nil {
		t.Fatal("unlisted executable was accepted")
	}
}

// TestFileSnapshotRestoresExistingAndMissingTargets verifies file snapshot restores existing and missing targets.
func TestFileSnapshotRestoresExistingAndMissingTargets(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	missing := filepath.Join(directory, "missing")
	if err := os.WriteFile(existing, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	existingSnapshot, err := SnapshotFile(existing, 64)
	if err != nil || !existingSnapshot.Exists() {
		t.Fatalf("snapshot existing: exists=%v err=%v", existingSnapshot.Exists(), err)
	}
	missingSnapshot, err := SnapshotFile(missing, 64)
	if err != nil || missingSnapshot.Exists() {
		t.Fatalf("snapshot missing: exists=%v err=%v", missingSnapshot.Exists(), err)
	}
	if err := AtomicWrite(existing, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(missing, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := existingSnapshot.Restore(); err != nil {
		t.Fatal(err)
	}
	if err := missingSnapshot.Restore(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil || string(contents) != "original" {
		t.Fatalf("restored contents=%q err=%v", contents, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("created target remains: %v", err)
	}
}

// TestSnapshotFileRejectsSymlink verifies snapshot file rejects symlink.
func TestSnapshotFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotFile(link, 64); err == nil {
		t.Fatal("symbolic link was accepted")
	}
}
