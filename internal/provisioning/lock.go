// File purpose: Serializes read-modify-write provisioning operations across CLI processes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"fmt"
	"os"
	"syscall"
)

// LockDirectory locks a stable configuration directory until the returned file
// is closed. Locking the directory survives atomic replacement of its files and
// leaves no lock file that another process could unlink and recreate.
func LockDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open provisioning directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock provisioning directory (another configuration change may be running): %w", err)
	}
	return file, nil
}
