// File purpose: Keeps service and maintenance secrets out of process dumps.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cli

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DisableProcessDumping disables core dumps and unprivileged access to process
// memory before credentials are loaded. The core limit also applies to child
// helpers. PR_SET_DUMPABLE is needed because piped core collectors can ignore
// RLIMIT_CORE. This does not prevent privileged access or swapping.
func DisableProcessDumping() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable process dumping: %w", err)
	}
	return nil
}
