// File purpose: Verifies key separation, session binding, and invalid secret rejection.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package keyderivation

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestDerivationUsesNegotiatedVersion checks the complete HKDF context against an independent construction.
func TestDerivationUsesNegotiatedVersion(t *testing.T) {
	psk := bytes.Repeat([]byte{0xab}, PSKBytes)
	client, server := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	for _, session := range []bool{false, true} {
		var actual, salt []byte
		var err error
		kind := "agent"
		if session {
			kind, salt = "session", append(append([]byte(nil), client...), server...)
			actual, err = DeriveSession(psk, "display", hex.EncodeToString(client), hex.EncodeToString(server), TransportCommand)
		} else {
			actual, err = Derive(psk, "display", TransportCommand)
		}
		if err != nil {
			t.Fatal(err)
		}
		info := fmt.Sprintf("neodse/v1\x00%s\x00display\x00%s", kind, TransportCommand)
		expected, err := hkdf.Key(sha256.New, psk, salt, info, KeyBytes)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("%s derivation differs from negotiated protocol domain: %v", kind, err)
		}
	}
}

// TestDeriveSeparatesAgentAndPurpose verifies derive separates agent and purpose.
func TestDeriveSeparatesAgentAndPurpose(t *testing.T) {
	psk, err := ParsePSK(strings.Repeat("ab", PSKBytes))
	if err != nil {
		t.Fatal(err)
	}

	command, err := Derive(psk, "display-001", TransportCommand)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := Derive(psk, "display-001", TransportStatus)
	otherAgent, _ := Derive(psk, "display-002", TransportCommand)

	if bytes.Equal(command, status) {
		t.Fatal("different purposes derived the same key")
	}
	if bytes.Equal(command, otherAgent) {
		t.Fatal("different agents derived the same key")
	}
}

// TestParsePSKRejectsInvalidValues verifies parse psk rejects invalid values.
func TestParsePSKRejectsInvalidValues(t *testing.T) {
	valid := strings.Repeat("ab", PSKBytes)
	for _, value := range []string{"", "abcd", strings.Repeat("zz", PSKBytes), strings.Repeat("ab", PSKBytes+1), " " + valid, valid + " ", "\t" + valid + "\n", valid[:32] + " " + valid[32:]} {
		if _, err := ParsePSK(value); err == nil {
			t.Fatalf("ParsePSK(%q) unexpectedly succeeded", value)
		}
	}
}

// TestSessionKeysSeparateConnectionsAndPurposes verifies session keys separate
// agents, secrets, both handshake nonces and purposes. The proxy credential is
// the ProxyClient session key, so it cannot be reused in another handshake.
func TestSessionKeysSeparateConnectionsAndPurposes(t *testing.T) {
	psk, _ := ParsePSK(strings.Repeat("ab", PSKBytes))
	otherPSK, _ := ParsePSK(strings.Repeat("cd", PSKBytes))
	client := strings.Repeat("11", 32)
	serverA := strings.Repeat("22", 32)
	proxyKey, err := DeriveSession(psk, "display-001", client, serverA, ProxyClient)
	if err != nil {
		t.Fatal(err)
	}
	if same, _ := DeriveSession(psk, "display-001", client, serverA, ProxyClient); !bytes.Equal(proxyKey, same) || len(same) != KeyBytes {
		t.Fatal("session key was not stable")
	}
	for name, input := range map[string]struct {
		psk            []byte
		agent          string
		client, server string
		purpose        Purpose
	}{
		"agent":        {psk, "display-002", client, serverA, ProxyClient},
		"secret":       {otherPSK, "display-001", client, serverA, ProxyClient},
		"client nonce": {psk, "display-001", strings.Repeat("33", 32), serverA, ProxyClient},
		"server nonce": {psk, "display-001", client, strings.Repeat("44", 32), ProxyClient},
		"purpose":      {psk, "display-001", client, serverA, TransportStatus},
	} {
		other, err := DeriveSession(input.psk, input.agent, input.client, input.server, input.purpose)
		if err != nil || bytes.Equal(proxyKey, other) {
			t.Fatalf("distinct %s derived the same session key", name)
		}
	}
}

// TestDeriveSessionKeysCoversSessionPurposes keeps the agent and controller key
// sets identical: every session purpose, each equal to DeriveSession, and no
// long-term handshake key.
func TestDeriveSessionKeysCoversSessionPurposes(t *testing.T) {
	psk, _ := ParsePSK(strings.Repeat("ab", PSKBytes))
	client, server := strings.Repeat("11", 32), strings.Repeat("22", 32)
	keys, err := DeriveSessionKeys(psk, "display-001", client, server)
	if err != nil {
		t.Fatal(err)
	}
	purposes := []Purpose{TransportCommand, TransportStatus, TransportReceipt, TransportDisplay, ProxyClient}
	if len(keys) != len(purposes) {
		t.Fatalf("derived %d session keys, want %d", len(keys), len(purposes))
	}
	for _, purpose := range purposes {
		want, err := DeriveSession(psk, "display-001", client, server, purpose)
		if err != nil || !bytes.Equal(keys[purpose], want) {
			t.Fatalf("%s session key differs from DeriveSession", purpose)
		}
	}
	if _, exists := keys[TransportHandshake]; exists {
		t.Fatal("session keys include the long-term handshake key")
	}
	if _, err := DeriveSessionKeys(psk, "display-001", "short", server); err == nil {
		t.Fatal("accepted an invalid client nonce")
	}
}

// TestDerivationRejectsIncompleteContext verifies derivation rejects incomplete context.
func TestDerivationRejectsIncompleteContext(t *testing.T) {
	psk, _ := ParsePSK(strings.Repeat("ab", PSKBytes))
	nonce := strings.Repeat("11", 32)
	for name, candidate := range map[string]struct {
		psk     []byte
		agentID string
		purpose Purpose
	}{
		"PSK":     {psk: []byte("short"), agentID: "display", purpose: TransportCommand},
		"agent":   {psk: psk, agentID: " ", purpose: TransportCommand},
		"purpose": {psk: psk, agentID: "display"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Derive(candidate.psk, candidate.agentID, candidate.purpose); err == nil {
				t.Fatal("incomplete derivation context was accepted")
			}
		})
	}
	for name, candidate := range map[string]struct{ client, server string }{
		"client encoding": {client: strings.Repeat("gg", 32), server: nonce},
		"client length":   {client: "11", server: nonce},
		"server encoding": {client: nonce, server: strings.Repeat("gg", 32)},
		"server length":   {client: nonce, server: "22"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveSession(psk, "display", candidate.client, candidate.server, TransportCommand); err == nil {
				t.Fatal("invalid session nonce was accepted")
			}
		})
	}
	if _, err := DeriveSession([]byte("short"), "display", nonce, nonce, TransportCommand); err == nil {
		t.Fatal("invalid session PSK was accepted")
	}
	if _, err := DeriveSession(psk, "", nonce, nonce, TransportCommand); err == nil {
		t.Fatal("empty session identity was accepted")
	}
	derived, err := DeriveHex(psk, "display", ProxyClient)
	if err != nil || len(derived) != KeyBytes*2 {
		t.Fatalf("DeriveHex() = %q, %v", derived, err)
	}
	if _, err := DeriveHex([]byte("short"), "display", ProxyClient); err == nil {
		t.Fatal("DeriveHex accepted an invalid PSK")
	}
}
