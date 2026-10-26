// File purpose: Provides consistent version flag behavior for all NeoDSE executables.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package cli contains the small command-line contracts shared by NeoDSE
// executables.
package cli

import (
	"fmt"
	"io"
)

// WriteVersion handles the single, side-effect-free --version command.
func WriteVersion(output io.Writer, name, version string, arguments []string) bool {
	if len(arguments) != 1 || arguments[0] != "--version" {
		return false
	}
	_, _ = fmt.Fprintf(output, "%s %s\n", name, version)
	return true
}
