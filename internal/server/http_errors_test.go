// File purpose: Verifies bounded TLS trust diagnostics without suppressing unrelated server errors.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestHTTPServerErrorWriterRateLimitsCertificateRejectionsByHost verifies http server error writer rate limits certificate rejections by host.
func TestHTTPServerErrorWriterRateLimitsCertificateRejectionsByHost(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 34, 0, 0, time.UTC)
	var messages []string
	writer := &httpServerErrorWriter{
		warned: make(map[string]time.Time),
		now:    func() time.Time { return now },
		output: func(format string, values ...any) { messages = append(messages, fmt.Sprintf(format, values...)) },
	}
	for _, port := range []string{"57566", "57493", "51229"} {
		line := "http: TLS handshake error from 10.4.10.250:" + port + ": remote error: tls: unknown certificate\n"
		if _, err := writer.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if len(messages) != 1 || !strings.Contains(messages[0], "source=10.4.10.250") {
		t.Fatalf("rate-limited messages = %#v", messages)
	}
	now = now.Add(certificateWarningInterval)
	_, _ = writer.Write([]byte("http: TLS handshake error from 10.4.10.250:60000: remote error: tls: unknown certificate\n"))
	if len(messages) != 2 {
		t.Fatalf("warning was not emitted after interval: %#v", messages)
	}
}

// TestHTTPServerErrorWriterPreservesOtherErrors verifies http server error writer preserves other errors.
func TestHTTPServerErrorWriterPreservesOtherErrors(t *testing.T) {
	var message string
	writer := &httpServerErrorWriter{
		warned: make(map[string]time.Time), now: time.Now,
		output: func(format string, values ...any) { message = fmt.Sprintf(format, values...) },
	}
	_, _ = writer.Write([]byte("http: Accept error: resource temporarily unavailable\n"))
	if message != "! HTTPS http: Accept error: resource temporarily unavailable" {
		t.Fatalf("server error = %q", message)
	}
}

// TestCertificateRejectionSourceRejectsUntrustedShapes verifies certificate rejection source rejects untrusted shapes.
func TestCertificateRejectionSourceRejectsUntrustedShapes(t *testing.T) {
	for _, message := range []string{
		"http: TLS handshake error from hostname:443: remote error: tls: unknown certificate",
		"http: TLS handshake error from 10.4.10.250:443: tls: bad certificate",
		"attacker\nhttp: TLS handshake error from 10.4.10.250:443: remote error: tls: unknown certificate",
	} {
		if source, ok := certificateRejectionSource(message); ok {
			t.Fatalf("untrusted diagnostic produced source %q", source)
		}
	}
}
