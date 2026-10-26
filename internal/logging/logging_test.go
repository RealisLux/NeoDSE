// File purpose: Verifies that log output removes credentials and preserves safe diagnostics.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package logging

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRedactingWriterProducesPlainText verifies redacting writer produces plain text.
func TestRedactingWriterProducesPlainText(t *testing.T) {
	var output bytes.Buffer
	writer := redactingWriter{destination: &output}
	input := []byte("configuration failed token=secret\ninjected")
	if count, err := writer.Write(input); err != nil || count != len(input) {
		t.Fatalf("Write() count=%d error=%v", count, err)
	}
	if got := output.String(); got != "configuration failed token=[redacted] injected\n" {
		t.Fatalf("plain log output = %q", got)
	}
	if strings.Contains(output.String(), "application event") || strings.HasPrefix(output.String(), "{") {
		t.Fatalf("log output retained structured wrapper: %q", output.String())
	}
}

// TestSanitizeLogMessageRedactsSecrets verifies sanitize log message redacts secrets.
func TestSanitizeLogMessageRedactsSecrets(t *testing.T) {
	t.Parallel()

	input := []byte(`token=abc psk: "def ghi" signature='jkl' nonce: mno Authorization: Bearer-secret safe=value`)
	got := sanitizeLogMessage(input)
	for _, secret := range []string{"abc", "def ghi", "jkl", "mno", "Bearer-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q remained in sanitized message %q", secret, got)
		}
	}
	if !strings.Contains(got, "safe=value") {
		t.Fatalf("non-secret field was removed: %q", got)
	}
}

// TestRedactingWriterRemovesAuthorizationCredentials covers HTTP authentication
// values whose scheme and credential are separated by whitespace.
func TestRedactingWriterRemovesAuthorizationCredentials(t *testing.T) {
	t.Parallel()
	for _, header := range []string{
		"Authorization: Bearer sensitive-credential",
		"authorization=Bearer sensitive-credential",
		"Proxy-Authorization: Basic sensitive-credential",
		"AUTHORIZATION: bearer\tsensitive-credential",
		`authorization="Bearer sensitive-credential"`,
	} {
		t.Run(header, func(t *testing.T) {
			var output bytes.Buffer
			writer := redactingWriter{destination: &output}
			if _, err := writer.Write([]byte(header + " status=denied")); err != nil {
				t.Fatal(err)
			}
			got := output.String()
			if strings.Contains(got, "sensitive-credential") || !strings.Contains(got, "[redacted] status=denied") {
				t.Fatalf("authorization was not safely redacted: %q", got)
			}
		})
	}
}

// TestSanitizeLogMessageBoundsAndRepairsUTF8 verifies sanitize log message bounds and repairs utf 8.
func TestSanitizeLogMessageBoundsAndRepairsUTF8(t *testing.T) {
	t.Parallel()

	input := append([]byte(strings.Repeat("x", 5000)), 0xff)
	got := sanitizeLogMessage(input)
	if len(got) > 4096 {
		t.Fatalf("sanitized message length = %d, want at most 4096", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("sanitized message is not valid UTF-8")
	}
}

// TestRedactingWriterNeutralizesTerminalControls covers hostile identifiers
// logged before authentication and diagnostic strings returned by peripherals.
func TestRedactingWriterNeutralizesTerminalControls(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	writer := redactingWriter{destination: &output}
	input := []byte("rejected event_id=\x1b[2J\bspoofed\x00\x7f\u009b31m\u2028next\u2029line\u202Espoofed\u202C\u2066isolated\u2069 العربية token=secret")
	if count, err := writer.Write(input); err != nil || count != len(input) {
		t.Fatalf("Write() count=%d error=%v", count, err)
	}
	if got, want := output.String(), "rejected event_id= [2J spoofed   31m next line spoofed  isolated  العربية token=[redacted]\n"; got != want {
		t.Fatalf("terminal-safe log output = %q, want %q", got, want)
	}
}
