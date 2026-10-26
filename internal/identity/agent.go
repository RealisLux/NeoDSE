// File purpose: Defines the canonical syntax shared by every agent identity boundary.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package identity defines identifiers exchanged across NeoDSE trust boundaries.
package identity

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

// ValidAgentID reports whether value is a canonical NeoDSE agent identifier.
// The broadcast identifier is reserved for fleet API routes.
func ValidAgentID(value string) bool {
	return value != "broadcast" && agentIDPattern.MatchString(value)
}

// ValidFriendlyName accepts optional labels that survive both C strings and SQLite storage.
func ValidFriendlyName(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 32 && !strings.ContainsRune(value, '\x00')
}
