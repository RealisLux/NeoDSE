// File purpose: Verifies the fail-closed pam_exec helper contract.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package main

import (
	"strings"
	"testing"
)

// TestRunAuthenticatesOnlyExpectedPAMContext verifies exact context matching and token forwarding.
func TestRunAuthenticatesOnlyExpectedPAMContext(t *testing.T) {
	environment := map[string]string{"PAM_SERVICE": allowedService, "PAM_USER": allowedUser, "PAM_TYPE": "auth"}
	called := false
	result := run(func(key string) string { return environment[key] }, strings.NewReader(strings.Repeat("a", 43)), func(token []byte) bool {
		called = true
		return string(token) == strings.Repeat("a", 43)
	})
	if result != 0 || !called {
		t.Fatalf("valid authentication result = %d, called = %v", result, called)
	}
	for key, value := range map[string]string{"PAM_SERVICE": "other", "PAM_USER": "root", "PAM_TYPE": "open_session"} {
		modified := map[string]string{"PAM_SERVICE": allowedService, "PAM_USER": allowedUser, "PAM_TYPE": "auth"}
		modified[key] = value
		if run(func(name string) string { return modified[name] }, strings.NewReader(strings.Repeat("a", 43)), func([]byte) bool { return true }) == 0 {
			t.Fatalf("accepted invalid %s", key)
		}
	}
}

// TestRunRejectsInvalidTokensAndAllowsBoundedAccountCheck covers size and account-phase policy.
func TestRunRejectsInvalidTokensAndAllowsBoundedAccountCheck(t *testing.T) {
	environment := map[string]string{"PAM_SERVICE": allowedService, "PAM_USER": allowedUser, "PAM_TYPE": "auth"}
	getenv := func(key string) string { return environment[key] }
	for _, token := range []string{"short", strings.Repeat("a", maxTokenBytes+1)} {
		if run(getenv, strings.NewReader(token), func([]byte) bool { return true }) == 0 {
			t.Fatalf("accepted token length %d", len(token))
		}
	}
	environment["PAM_TYPE"] = "account"
	if run(getenv, strings.NewReader(""), func([]byte) bool { return false }) != 0 {
		t.Fatal("rejected valid account phase")
	}
}
