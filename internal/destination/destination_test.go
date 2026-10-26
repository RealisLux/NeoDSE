// File purpose: Tests canonical origin identity across request and policy inputs.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package destination

import (
	"net/url"
	"testing"
)

// TestCanonicalOrigins equates alternate spellings of one approved destination.
func TestCanonicalOrigins(t *testing.T) {
	for _, raw := range []string{"https://EXAMPLE.com.:0443/path", "https://example.com/path"} {
		got, err := FromURL(raw)
		if err != nil || got != "https://example.com:443" {
			t.Fatalf("%s => %s %v", raw, got, err)
		}
	}
	for _, raw := range []string{"https://[::1]/", "https://user:pass@example.com/", "file:///etc/passwd", "https://bad_host/"} {
		if _, err := FromURL(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

// TestCanonicalIPv4Literal verifies origin authorization does not require DNS.
func TestCanonicalIPv4Literal(t *testing.T) {
	got, err := FromURL("http://10.20.1.5:8080/status")
	if err != nil || got != "http://10.20.1.5:8080" {
		t.Fatalf("FromURL() = %q, %v", got, err)
	}
}

// TestURLPortUsesSchemeDefaults keeps proxy policy and dialing on the same port.
func TestURLPortUsesSchemeDefaults(t *testing.T) {
	for raw, want := range map[string]string{
		"http://example.com/":       "80",
		"https://example.com/":      "443",
		"https://example.com:8443/": "8443",
		"http://192.0.2.1:8080":     "8080",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := URLPort(parsed); got != want {
			t.Errorf("URLPort(%s) = %q, want %q", raw, got, want)
		}
	}
}
