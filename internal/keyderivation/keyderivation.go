// File purpose: Derives purpose- and session-separated keys from provisioned agent secrets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package keyderivation turns one per-agent PSK into purpose-specific keys.
package keyderivation

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

// Sizes of a per-agent PSK and of every key derived from it.
const (
	PSKBytes = 32
	KeyBytes = 32
)

// Purpose identifies a cryptographically separated use of agent key material.
type Purpose string

// Key purposes. TransportHandshake and ProxyInternal are long-term; the other
// keys belong to one authenticated session.
const (
	TransportHandshake Purpose = "transport-handshake"
	TransportCommand   Purpose = "transport-command"
	TransportStatus    Purpose = "transport-status"
	TransportReceipt   Purpose = "transport-receipt"
	TransportDisplay   Purpose = "transport-display"
	ProxyClient        Purpose = "proxy-client"
	ProxyInternal      Purpose = "proxy-internal"
)

// ParsePSK decodes the canonical 64-character hexadecimal PSK representation.
func ParsePSK(value string) ([]byte, error) {
	if len(value) != PSKBytes*2 {
		return nil, fmt.Errorf("PSK must be exactly %d bytes encoded as %d hexadecimal characters", PSKBytes, PSKBytes*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode PSK: %w", err)
	}
	return decoded, nil
}

// DeriveSession derives a connection-specific key. Both nonces are generated
// independently during the authenticated handshake, so captured application
// frames cannot be replayed in a later connection.
func DeriveSession(psk []byte, agentID, clientNonce, serverNonce string, purpose Purpose) ([]byte, error) {
	if len(psk) != PSKBytes {
		return nil, fmt.Errorf("PSK must be exactly %d bytes", PSKBytes)
	}
	if strings.TrimSpace(agentID) == "" || purpose == "" {
		return nil, errors.New("agent ID and key purpose are required")
	}
	client, err := hex.DecodeString(clientNonce)
	if err != nil || len(client) != 32 {
		return nil, errors.New("client nonce must be 32 bytes encoded as hexadecimal")
	}
	server, err := hex.DecodeString(serverNonce)
	if err != nil || len(server) != 32 {
		return nil, errors.New("server nonce must be 32 bytes encoded as hexadecimal")
	}
	salt := append(append(make([]byte, 0, len(client)+len(server)), client...), server...)
	info := strings.Join([]string{fmt.Sprintf("neodse/v%d", wire.ProtocolVersion), "session", agentID, string(purpose)}, "\x00")
	return hkdf.Key(sha256.New, psk, salt, info, KeyBytes)
}

// sessionPurposes are the keys of one authenticated agent session. The
// handshake key is long-term and derived separately with Derive.
var sessionPurposes = []Purpose{TransportCommand, TransportStatus, TransportReceipt, TransportDisplay, ProxyClient}

// DeriveSessionKeys derives every key of one authenticated agent session, so
// the agent and the controller always hold the same set.
func DeriveSessionKeys(psk []byte, agentID, clientNonce, serverNonce string) (map[Purpose][]byte, error) {
	keys := make(map[Purpose][]byte, len(sessionPurposes))
	for _, purpose := range sessionPurposes {
		key, err := DeriveSession(psk, agentID, clientNonce, serverNonce, purpose)
		if err != nil {
			return nil, err
		}
		keys[purpose] = key
	}
	return keys, nil
}

// Derive uses HKDF-SHA-256 to bind a key to the protocol, agent, and purpose.
func Derive(psk []byte, agentID string, purpose Purpose) ([]byte, error) {
	if len(psk) != PSKBytes {
		return nil, fmt.Errorf("PSK must be exactly %d bytes", PSKBytes)
	}
	if strings.TrimSpace(agentID) == "" {
		return nil, errors.New("agent ID is required for key derivation")
	}
	if purpose == "" {
		return nil, errors.New("key purpose is required")
	}
	info := strings.Join([]string{fmt.Sprintf("neodse/v%d", wire.ProtocolVersion), "agent", agentID, string(purpose)}, "\x00")
	return hkdf.Key(sha256.New, psk, nil, info, KeyBytes)
}

// DeriveHex returns a derived key in its lowercase hexadecimal representation.
func DeriveHex(psk []byte, agentID string, purpose Purpose) (string, error) {
	key, err := Derive(psk, agentID, purpose)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
