// File purpose: Verifies provisioning exclusion and lock release without host configuration changes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirectoryLockSurvivesConfigurationReplacement prevents concurrent stale snapshots.
func TestDirectoryLockSurvivesConfigurationReplacement(t *testing.T) {
	directory := t.TempDir()
	first, err := LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	path := filepath.Join(directory, "neodse.conf")
	for _, value := range []string{"first", "replacement"} {
		if err := AtomicWrite(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if second, err := LockDirectory(directory); err == nil {
			second.Close()
			t.Fatal("concurrent provisioning was admitted")
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockDirectory(directory)
	if err != nil {
		t.Fatalf("closed lock blocked the next change: %v", err)
	}
	defer second.Close()
}

// TestDirectoryLockRejectsSymlink refuses a redirected configuration boundary.
func TestDirectoryLockRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(t.TempDir(), "configuration")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if lock, err := LockDirectory(link); err == nil {
		lock.Close()
		t.Fatal("symlink directory accepted")
	}
}
