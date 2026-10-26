// File purpose: Preserves no-follow encrypted database opens and durable publication of SQLite journals.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package store

import (
	"os"
	"path/filepath"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
	_ "github.com/ncruces/go-sqlite3/vfs/xts"
)

const databaseVFS = "neodse-xts"

// init keeps the driver's encrypted file implementation and its no-follow
// opens, but prevents path canonicalization from first resolving a symlink.
func init() {
	vfs.Register(databaseVFS, noSymlinkVFS{VFS: vfs.Find("xts")})
}

type noSymlinkVFS struct {
	vfs.VFS
	// Tests inject directory-sync failure to verify that writes cannot proceed.
	syncDirectory func(string) error
}

// FullPathname rejects symbolic links in the absolute path supplied by open.
// The state directory's ancestors must remain outside service-account control.
func (filesystem noSymlinkVFS) FullPathname(name string) (string, error) {
	full, err := filesystem.VFS.FullPathname(name)
	if full != "" && full != name {
		return "", sqlite3.CANTOPEN_SYMLINK
	}
	return full, err
}

// OpenFilename preserves encryption and makes new journal names durable before
// SQLite can acknowledge a transaction. The pinned driver's file Sync opens
// the parent directory but mistakenly synchronizes the file again instead.
func (filesystem noSymlinkVFS) OpenFilename(name *vfs.Filename, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	file, flags, err := vfsutil.WrapOpenFilename(filesystem.VFS, name, flags)
	if err == nil && name != nil && flags&vfs.OPEN_CREATE != 0 &&
		flags&(vfs.OPEN_WAL|vfs.OPEN_MAIN_JOURNAL|vfs.OPEN_SUPER_JOURNAL) != 0 {
		synchronize := filesystem.syncDirectory
		if synchronize == nil {
			synchronize = syncDatabaseDirectory
		}
		if err := synchronize(name.String()); err != nil {
			_ = file.Close()
			return nil, flags, err
		}
	}
	return file, flags, err
}

// syncDatabaseDirectory persists a newly created database or journal name.
// SQLite's FULL synchronization separately persists subsequent file contents.
func syncDatabaseDirectory(path string) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
