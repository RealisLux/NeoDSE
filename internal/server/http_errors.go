// File purpose: Converts HTTP server diagnostics into concise, bounded, operator-readable log events.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	certificateWarningInterval = 5 * time.Minute
	certificateWarningLimit    = 1024
)

type httpServerErrorWriter struct {
	mu     sync.Mutex
	warned map[string]time.Time
	now    func() time.Time
	output func(string, ...any)
}

// newHTTPServerErrorLogger builds the logger used exclusively by net/http server diagnostics.
func newHTTPServerErrorLogger() *log.Logger {
	writer := &httpServerErrorWriter{warned: make(map[string]time.Time), now: time.Now, output: log.Printf}
	return log.New(writer, "", 0)
}

// Write preserves actionable server errors and rate-limits expected browser trust rejections.
func (writer *httpServerErrorWriter) Write(value []byte) (int, error) {
	message := strings.ToValidUTF8(strings.TrimSpace(string(value)), "�")
	message = strings.NewReplacer("\r", " ", "\n", " ").Replace(message)
	if source, ok := certificateRejectionSource(message); ok {
		if writer.shouldReportCertificateRejection(source) {
			writer.output("| HTTPS client does not trust the controller certificate source=%s", source)
		}
		return len(value), nil
	}
	writer.output("! HTTPS %s", message)
	return len(value), nil
}

// shouldReportCertificateRejection bounds warning frequency and retained source addresses.
func (writer *httpServerErrorWriter) shouldReportCertificateRejection(source string) bool {
	now := writer.now()
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for candidate, reported := range writer.warned {
		if now.Sub(reported) >= certificateWarningInterval {
			delete(writer.warned, candidate)
		}
	}
	if reported, exists := writer.warned[source]; exists && now.Sub(reported) < certificateWarningInterval {
		return false
	}
	if len(writer.warned) >= certificateWarningLimit {
		return false
	}
	writer.warned[source] = now
	return true
}

// certificateRejectionSource extracts the host from Go's exact client trust-rejection diagnostic.
func certificateRejectionSource(message string) (string, bool) {
	const prefix = "http: TLS handshake error from "
	const suffix = ": remote error: tls: unknown certificate"
	if !strings.HasPrefix(message, prefix) || !strings.HasSuffix(message, suffix) {
		return "", false
	}
	address := strings.TrimSuffix(strings.TrimPrefix(message, prefix), suffix)
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || ip.To4() == nil {
		return "", false
	}
	return host, true
}
