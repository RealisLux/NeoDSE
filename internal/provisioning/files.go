// File purpose: Installs durable configuration with ownership set before publication.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// AtomicWrite preserves existing ownership when replacing a configuration file.
func AtomicWrite(path string, contents []byte, mode os.FileMode) error {
	uid, gid := os.Geteuid(), os.Getegid()
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("configuration target is not a regular file")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("configuration ownership unavailable")
		}
		uid, gid = int(stat.Uid), int(stat.Gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return AtomicWriteOwned(path, contents, mode, uid, gid)
}

// AtomicWriteWithRollback replaces an existing configuration and restores the
// supplied prior contents if writing fails, including after publication. Both
// writes use mode; callers must hold the directory lock from reading current
// until this operation ends. A failed restoration is returned with the write error.
func AtomicWriteWithRollback(path string, current, next []byte, mode os.FileMode) error {
	return atomicWriteWithRollback(path, current, next, mode, AtomicWrite)
}

// atomicWriteWithRollback permits fault injection after publication in tests.
func atomicWriteWithRollback(path string, current, next []byte, mode os.FileMode, write func(string, []byte, os.FileMode) error) error {
	if err := write(path, next, mode); err != nil {
		if restoreErr := write(path, current, mode); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore prior configuration: %w", restoreErr))
		}
		return err
	}
	return nil
}

// WriteServiceFile resolves trusted installation accounts before publishing secrets.
func WriteServiceFile(path string, contents []byte, mode os.FileMode, owner, group string) error {
	return publishServiceFile(path, contents, mode, owner, group, true)
}

// CreateServiceFile publishes a complete service-owned file without replacing
// any existing file, including one another process creates during the write.
func CreateServiceFile(path string, contents []byte, mode os.FileMode, owner, group string) error {
	return publishServiceFile(path, contents, mode, owner, group, false)
}

// publishServiceFile resolves installation accounts before publishing secrets.
func publishServiceFile(path string, contents []byte, mode os.FileMode, owner, group string, replace bool) error {
	account, err := user.Lookup(owner)
	if err != nil {
		return err
	}
	membership, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(membership.Gid)
	if err != nil {
		return err
	}
	if replace {
		return AtomicWriteOwned(path, contents, mode, uid, gid)
	}
	return AtomicCreateOwned(path, contents, mode, uid, gid)
}

// AtomicWriteOwned confines all file operations to one opened parent directory.
// A reported fsync failure means the final state must be inspected before retry.
func AtomicWriteOwned(path string, contents []byte, mode os.FileMode, uid, gid int) error {
	return publishOwnedFile(path, contents, mode, uid, gid, true)
}

// AtomicCreateOwned sets ownership and synchronizes complete contents before
// exclusively publishing a new file. Existing names are always preserved.
func AtomicCreateOwned(path string, contents []byte, mode os.FileMode, uid, gid int) error {
	return publishOwnedFile(path, contents, mode, uid, gid, false)
}

// publishOwnedFile keeps temporary files and publication in one opened parent.
func publishOwnedFile(path string, contents []byte, mode os.FileMode, uid, gid int, replace bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if info, err := root.Lstat(name); err == nil {
		if !replace {
			return fmt.Errorf("configuration %q: %w", path, os.ErrExist)
		}
		if !info.Mode().IsRegular() {
			return errors.New("configuration target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	suffix, err := RandomPSK()
	if err != nil {
		return err
	}
	temporary := ".neodse-" + suffix
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	// Owner and mode become visible together with the completed contents.
	if err = file.Chown(uid, gid); err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		_, err = file.Write(contents)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		if err = root.Rename(temporary, name); err != nil {
			return err
		}
	} else {
		// Linking the completed file publishes it atomically and fails if the
		// destination appeared after the initial check. Rename would replace it.
		if err = root.Link(temporary, name); err != nil {
			return err
		}
		if err = root.Remove(temporary); err != nil {
			return fmt.Errorf("configuration %q was published but removing its temporary link failed; check final state before retrying: %w", path, err)
		}
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("configuration %q was published but opening its directory for synchronization failed; check final state before retrying: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("configuration %q was published but synchronizing its directory failed; check final state before retrying: %w", path, err)
	}
	return nil
}
