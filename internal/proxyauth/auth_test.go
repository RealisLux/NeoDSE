// File purpose: Verifies the internal proxy credential rejects malformed keys.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxyauth

import (
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
)

// TestInternalTokenRejectsInvalidPSK verifies internal token rejects invalid psk.
func TestInternalTokenRejectsInvalidPSK(t *testing.T) {
	if _, err := InternalToken("invalid"); err == nil {
		t.Fatal("invalid internal PSK was accepted")
	}
	token, err := InternalToken(strings.Repeat("ab", keyderivation.PSKBytes))
	if err != nil || len(token) != keyderivation.KeyBytes*2 {
		t.Fatalf("InternalToken() = %q, %v", token, err)
	}
}
