// File purpose: Verifies atomic file publication and bounded helper output.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestAtomicPublicationPreservesOwnerAndRejectsSymlinks checks the replacement boundary.
func TestAtomicPublicationPreservesOwnerAndRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := AtomicWrite(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o640 || int(owner.Uid) != os.Geteuid() || int(owner.Gid) != os.Getegid() {
		t.Fatal("replacement metadata changed")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(link, []byte("bad"), 0o600); err == nil {
		t.Fatal("symlink accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "new" {
		t.Fatal("rejected write modified target")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("temporary files leaked")
	}
}

// TestAtomicCreateOwnedPreservesExistingNames keeps exclusive publication from
// replacing regular files, directories, or either kind of symbolic link.
func TestAtomicCreateOwnedPreservesExistingNames(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "keyslot")
			victim := filepath.Join(directory, "victim")
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("existing keyslot"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink", "dangling-symlink":
				if kind == "symlink" {
					if err := os.WriteFile(victim, []byte("existing keyslot"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := AtomicCreateOwned(path, []byte("replacement"), 0o640, os.Geteuid(), os.Getegid()); !errors.Is(err, os.ErrExist) {
				t.Fatalf("create error = %v, want already exists", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
				t.Fatalf("existing name changed: %v", err)
			}
			if kind == "file" || kind == "symlink" {
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != "existing keyslot" {
					t.Fatalf("existing contents changed: %q, %v", contents, err)
				}
			}
		})
	}
}

// TestAtomicCreateOwnedConcurrentPublishers verifies that exactly one complete,
// privately owned file wins when multiple writers start with the same new name.
func TestAtomicCreateOwnedConcurrentPublishers(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "keyslot")
	type result struct {
		contents []byte
		err      error
	}
	const writers = 8
	start := make(chan struct{})
	results := make(chan result, writers)
	for i := range writers {
		go func() {
			contents := bytes.Repeat([]byte{byte(i + 1)}, 128<<10)
			<-start
			results <- result{contents, AtomicCreateOwned(path, contents, 0o600, os.Geteuid(), os.Getegid())}
		}()
	}
	close(start)
	var winner []byte
	wins := 0
	for range writers {
		result := <-results
		if result.err == nil {
			wins++
			winner = result.contents
		} else if !errors.Is(result.err, os.ErrExist) {
			t.Errorf("concurrent create: %v", result.err)
		}
	}
	if wins != 1 {
		t.Fatalf("successful publishers = %d, want one", wins)
	}
	contents, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(contents, winner) {
		t.Fatalf("winning contents were incomplete or replaced: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o600 || int(owner.Uid) != os.Geteuid() || int(owner.Gid) != os.Getegid() {
		t.Fatal("published metadata differs from the requested private owner and mode")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v", err)
	}
}

// TestHelperOutputCancelsAtLimit ensures repeated output cannot grow memory after cancellation.
func TestHelperOutputCancelsAtLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &boundedOutput{cancel: cancel}
	block := bytes.Repeat([]byte("x"), maxHelperOutput)
	_, _ = output.Write(block)
	if ctx.Err() != nil {
		t.Fatal("exact bound rejected")
	}
	for range 3 {
		_, _ = output.Write(block)
	}
	if ctx.Err() == nil || !output.overflow || output.buffer.Len() != maxHelperOutput {
		t.Fatal("unbounded helper output")
	}
}

func TestBoundedProvisioningReadRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBoundedFile(path, 1024); err == nil {
		t.Fatal("FIFO accepted as configuration")
	}
}

// TestAtomicWriteRollbackAfterPublication keeps a reported synchronization
// failure from changing durable configuration while callers retain old state.
func TestAtomicWriteRollbackAfterPublication(t *testing.T) {
	for _, restoreFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("restore-fails=%t", restoreFails), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "neodse.conf")
			current, next := []byte("prior WireGuard peers"), []byte("replacement WireGuard peers")
			if err := AtomicWrite(path, current, 0o600); err != nil {
				t.Fatal(err)
			}
			writeFailure := errors.New("simulated directory synchronization failure")
			restoreFailure := errors.New("simulated restoration failure")
			calls := 0
			write := func(path string, contents []byte, mode os.FileMode) error {
				calls++
				if calls == 2 && restoreFails {
					return restoreFailure
				}
				if err := AtomicWrite(path, contents, mode); err != nil {
					return err
				}
				if calls == 1 {
					return writeFailure
				}
				return nil
			}
			err := atomicWriteWithRollback(path, current, next, 0o600, write)
			if calls != 2 || !errors.Is(err, writeFailure) || errors.Is(err, restoreFailure) != restoreFails {
				t.Fatalf("write calls=%d error=%v", calls, err)
			}
			if !restoreFails {
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != string(current) {
					t.Fatalf("prior WireGuard file not restored: %q, %v", contents, err)
				}
			}
		})
	}
}
