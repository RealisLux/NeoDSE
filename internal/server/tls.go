// File purpose: Loads the explicitly configured controller TLS certificate and reports its expiry.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// certificateRenewalWarning is how long before expiry the controller starts
// daily warnings. The proxy rejects an expired controller certificate, which
// stops all display content until the certificate is renewed.
const certificateRenewalWarning = 30 * 24 * time.Hour

// prepareServerCertificate validates configured paths and loads one matching TLS key pair.
func prepareServerCertificate(certPath, keyPath, configPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("TLS certificate and key must be configured in %s", configPath)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load configured TLS certificate and key: %w", err)
	}
	if certificate.Leaf == nil {
		if certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0]); err != nil {
			return nil, fmt.Errorf("parse configured TLS certificate: %w", err)
		}
	}
	return &certificate, nil
}

// certificateExpiryWarning returns the journal warning for a certificate that
// has expired or expires within the renewal window, or an empty string.
func certificateExpiryWarning(notAfter, now time.Time) string {
	remaining := notAfter.Sub(now)
	expiry := notAfter.UTC().Format(time.DateOnly)
	switch {
	case remaining <= 0:
		return fmt.Sprintf("! HTTPS certificate expired on %s; displays cannot load web content until it is renewed with neodse-server renew-certificate", expiry)
	case remaining <= certificateRenewalWarning:
		return fmt.Sprintf("! HTTPS certificate expires on %s (%d days); renew it with neodse-server renew-certificate", expiry, int(remaining.Hours()/24))
	default:
		return ""
	}
}

// reportCertificateExpiry logs the certificate lifetime at startup and checks
// it daily, because a controller can run for longer than the renewal window.
func reportCertificateExpiry(ctx context.Context, notAfter time.Time, now func() time.Time, report func(string, ...any)) {
	report("| HTTPS certificate valid until %s", notAfter.UTC().Format(time.DateOnly))
	check := func() {
		if warning := certificateExpiryWarning(notAfter, now()); warning != "" {
			report("%s", warning)
		}
	}
	check()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}
