// File purpose: Provides random secrets, fixed external commands, and atomic writes for provisioning.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
)

// RandomPSK returns a cryptographically random application pre-shared key.
func RandomPSK() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Run executes one allowlisted fixed-path provisioning command with bounded input and output.
func Run(input string, name string, args ...string) (string, error) {
	paths := map[string]string{
		"wg":        "/usr/bin/wg",
		"wg-quick":  "/usr/bin/wg-quick",
		"systemctl": "/usr/bin/systemctl",
		"chown":     "/usr/bin/chown",
	}
	path, ok := paths[name]
	if !ok {
		return "", fmt.Errorf("executable %q is not permitted", name)
	}
	if len(input) > 1<<20 {
		return "", errors.New("helper input exceeds 1 MiB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- EXC-PROVISIONING-COMMAND: path is selected from the fixed allowlist above.
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output := &boundedOutput{cancel: cancel}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if output.overflow {
		return "", errors.New("helper output exceeds 1 MiB")
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return strings.TrimSpace(output.buffer.String()), nil
}

// ReadBoundedFile opens an operator-selected file without following its final
// symlink and caps memory use. Provisioning callers validate the decoded data
// before using it.
func ReadBoundedFile(path string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("invalid file size limit")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, errors.New("input exceeds size limit")
	}
	return contents, nil
}

// ReadWireGuardConfig reads one bounded configuration from the fixed
// WireGuard directory. os.Root prevents symlink or traversal escapes.
func ReadWireGuardConfig(instance string) ([]byte, error) {
	if !config.ValidInterfaceName(instance) {
		return nil, fmt.Errorf("invalid WireGuard interface name %q", instance)
	}
	root, err := os.OpenRoot("/etc/wireguard")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readWireGuardConfig(root, instance+".conf")
}

// readWireGuardConfig rejects special files before consuming bounded contents.
// Nonblocking open prevents a FIFO from hanging provisioning before Stat.
func readWireGuardConfig(root *os.Root, name string) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("WireGuard configuration is not a regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > 1<<20 {
		return nil, errors.New("WireGuard configuration exceeds 1 MiB")
	}
	return contents, nil
}

// FileSnapshot captures one bounded regular file so a multi-file provisioning
// operation can restore its starting point after a later step fails.
type FileSnapshot struct {
	path     string
	contents []byte
	mode     os.FileMode
	uid      int
	gid      int
	exists   bool
}

// SnapshotFile refuses symbolic links and non-regular files. A missing file is
// a valid snapshot and is removed by Restore if the operation created it.
func SnapshotFile(path string, maximum int64) (FileSnapshot, error) {
	snapshot := FileSnapshot{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() {
		return snapshot, errors.New("provisioning target is not a regular file")
	}
	contents, err := ReadBoundedFile(path, maximum)
	if err != nil {
		return snapshot, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return snapshot, errors.New("provisioning target ownership is unavailable")
	}
	snapshot.contents = contents
	snapshot.mode = info.Mode().Perm()
	snapshot.uid = int(stat.Uid)
	snapshot.gid = int(stat.Gid)
	snapshot.exists = true
	return snapshot, nil
}

// Exists reports whether the target existed when the snapshot was captured.
func (s FileSnapshot) Exists() bool {
	return s.exists
}

// Restore atomically restores an existing file, or removes a file created by
// the failed operation when the target did not initially exist.
func (s FileSnapshot) Restore() error {
	if !s.exists {
		if err := os.Remove(s.path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		directory, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	return AtomicWriteOwned(s.path, s.contents, s.mode, s.uid, s.gid)
}
