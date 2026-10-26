// File purpose: Verifies stable version flag output for packaged executables.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cli

import (
	"bytes"
	"testing"
)

// TestWriteVersion verifies write version.
func TestWriteVersion(t *testing.T) {
	var output bytes.Buffer
	if !WriteVersion(&output, "neodse-server", "1.0.0", []string{"--version"}) {
		t.Fatal("version argument was not handled")
	}
	if got := output.String(); got != "neodse-server 1.0.0\n" {
		t.Fatalf("version output = %q", got)
	}
	if WriteVersion(&output, "neodse-server", "1.0.0", []string{"--help"}) {
		t.Fatal("unrelated argument was handled")
	}
}
