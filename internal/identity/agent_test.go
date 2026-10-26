// File purpose: Verifies the canonical agent identifier syntax at boundary values.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package identity

import (
	"strings"
	"testing"
)

// TestValidAgentID verifies accepted and rejected identity boundary values.
func TestValidAgentID(t *testing.T) {
	valid := []string{"a", "Display-01", "display_01", "Broadcast", "broadcast-01", strings.Repeat("a", 32)}
	invalid := []string{"", "-display", "display.example", "display/01", strings.Repeat("a", 33), "display🙂", "broadcast"}
	for _, value := range valid {
		if !ValidAgentID(value) {
			t.Errorf("ValidAgentID(%q) = false", value)
		}
	}
	for _, value := range invalid {
		if ValidAgentID(value) {
			t.Errorf("ValidAgentID(%q) = true", value)
		}
	}
}

// TestValidFriendlyName checks byte encoding, character count, and the C-string boundary.
func TestValidFriendlyName(t *testing.T) {
	for _, value := range []string{"", "Lobby display", strings.Repeat("🙂", 32)} {
		if !ValidFriendlyName(value) {
			t.Errorf("valid friendly name rejected: %q", value)
		}
	}
	for _, value := range []string{"Lobby\x00hidden", "\xff", strings.Repeat("🙂", 33)} {
		if ValidFriendlyName(value) {
			t.Errorf("invalid friendly name accepted: %q", value)
		}
	}
}
