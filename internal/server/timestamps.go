// File purpose: Normalizes public API timestamps without changing internal precision.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import "time"

// formatAPITimestamp emits the canonical whole-second UTC representation used by public responses.
func formatAPITimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

// formatAPIStoredTimestamp normalizes an already validated RFC3339 timestamp.
// Empty values represent agents that have not reported status yet and remain empty.
func formatAPIStoredTimestamp(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return formatAPITimestamp(parsed)
}

// formatAPIOptionalTimestamp preserves nil optional fields while normalizing present values.
func formatAPIOptionalTimestamp(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := formatAPITimestamp(*value)
	return &formatted
}
