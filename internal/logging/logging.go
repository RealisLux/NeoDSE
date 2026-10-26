// File purpose: Installs concise process-wide logging that redacts recognizable secret material.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package logging configures human-readable, secret-safe application logs.
package logging

import (
	"io"
	"log"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// Configure restores standard timestamped journal output behind a redacting writer.
func Configure() {
	writer := redactingWriter{destination: os.Stderr}
	slog.SetDefault(slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})))
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("")
	log.SetOutput(writer)
}

type redactingWriter struct {
	destination io.Writer
}

var secretField = regexp.MustCompile(`(?i)\b(token|psk|signature|nonce|authorization)(=|:[[:space:]]*)("[^"]*"|'[^']*'|(?:Bearer|Basic)[[:space:]]+\S+|\S+)`)

// Write emits one bounded redacted line without wrapping it in a JSON envelope.
func (writer redactingWriter) Write(value []byte) (int, error) {
	message := sanitizeLogMessage(value)
	if message != "" {
		if _, err := io.WriteString(writer.destination, message+"\n"); err != nil {
			return 0, err
		}
	}
	return len(value), nil
}

// sanitizeLogMessage replaces credential-like values without retaining the original bytes.
func sanitizeLogMessage(value []byte) string {
	message := strings.ToValidUTF8(strings.TrimSpace(string(value)), "�")
	// Rejected protocol fields and peripheral diagnostics can still contain
	// terminal escapes or bidirectional overrides. Keep every entry inert and
	// on one line without changing the direction of surrounding log fields.
	message = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.Is(unicode.Bidi_Control, character) ||
			character == '\u2028' || character == '\u2029' {
			return ' '
		}
		return character
	}, message)
	message = secretField.ReplaceAllString(message, "$1=[redacted]")
	if len(message) > 4096 {
		message = strings.ToValidUTF8(message[:4096], "")
	}
	return message
}

var _ io.Writer = redactingWriter{}
