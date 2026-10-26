// File purpose: Provides bounded identifier and hexadecimal validation shared by server boundaries.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import "encoding/hex"

// validHexBytes accepts only the canonical fixed-width representation used by
// protocol identifiers, nonces, digests, and token components.
func validHexBytes(value string, size int) bool {
	if size < 1 || len(value) != size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size
}
