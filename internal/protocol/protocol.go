// File purpose: Defines versioned authenticated messages exchanged by controllers and stateless agents.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package protocol defines and authenticates transport-independent messages.
package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// Version is the protocol version carried and checked in every message.
const Version = wire.ProtocolVersion

// Receipt diagnostic limits apply to UTF-8 bytes before JSON encoding.
const (
	ReceiptErrorMaxBytes   = 1024
	ReceiptDetailsMaxBytes = 768
	ReceiptValueMaxBytes   = 32
)

// Frame is the transport-neutral envelope for one bounded protocol message.
type Frame struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Hello starts an authenticated agent session with a fresh client nonce.
type Hello struct {
	Protocol    int    `json:"protocol"`
	AgentID     string `json:"agent_id"`
	Version     string `json:"version"`
	ClientNonce string `json:"client_nonce"`
	Timestamp   string `json:"timestamp"`
	Signature   string `json:"signature"`
}

// Welcome completes an authenticated agent session with controller nonce and identity.
type Welcome struct {
	Protocol    int    `json:"protocol"`
	AgentID     string `json:"agent_id"`
	ClientNonce string `json:"client_nonce"`
	ServerNonce string `json:"server_nonce"`
	SessionID   string `json:"session_id"`
	Timestamp   string `json:"timestamp"`
	Signature   string `json:"signature"`
}

// DesiredState carries one complete durable instruction inside an authenticated session.
type DesiredState struct {
	Protocol   int                      `json:"protocol"`
	SessionID  string                   `json:"session_id"`
	Sequence   uint64                   `json:"sequence"`
	EventID    string                   `json:"event_id"`
	AgentID    string                   `json:"agent_id"`
	Timestamp  string                   `json:"timestamp"`
	Generation string                   `json:"generation"`
	Revision   uint64                   `json:"revision"`
	Apply      string                   `json:"apply,omitempty"`
	State      instruction.DesiredState `json:"state"`
	Signature  string                   `json:"signature"`
}

// Command carries one expiring transient operation inside an authenticated session.
type Command struct {
	Protocol  int                 `json:"protocol"`
	SessionID string              `json:"session_id"`
	Sequence  uint64              `json:"sequence"`
	EventID   string              `json:"event_id"`
	AgentID   string              `json:"agent_id"`
	Timestamp string              `json:"timestamp"`
	ExpiresAt string              `json:"expires_at"`
	Command   instruction.Command `json:"command"`
	Signature string              `json:"signature"`
}

// Receipt reports authenticated command progress from an agent.
type Receipt struct {
	Protocol  int    `json:"protocol"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	EventID   string `json:"event_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
	Operation string `json:"operation,omitempty"`
	Error     string `json:"error,omitempty"`
	Details   string `json:"details,omitempty"`
	Value     string `json:"value,omitempty"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

// Status is an authenticated agent heartbeat.
type Status struct {
	Protocol      int    `json:"protocol"`
	SessionID     string `json:"session_id"`
	Sequence      uint64 `json:"sequence"`
	AgentID       string `json:"agent_id"`
	FriendlyName  string `json:"friendly_name,omitempty"`
	Hostname      string `json:"hostname"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	StartedAt     string `json:"started_at"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
	LastEventID   string `json:"last_event_id,omitempty"`
	CECEnabled    bool   `json:"cec_enabled"`
	CECPower      string `json:"cec_power_status"`
	CECOutput     string `json:"cec_output,omitempty"`
	CECCheckedAt  string `json:"cec_checked_at,omitempty"`
	Timestamp     string `json:"timestamp"`
	Signature     string `json:"signature"`
}

// Display carries one authenticated chunk of a short-lived read-only image stream.
type Display struct {
	Protocol  int    `json:"protocol"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	AgentID   string `json:"agent_id"`
	StreamID  string `json:"stream_id"`
	Action    string `json:"action"`
	Data      []byte `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

// Decode parses exactly one protocol value and rejects fields outside the production contract.
func Decode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("protocol input contains more than one value")
		}
		return err
	}
	return nil
}

// SignDesiredState returns the desired-state-domain authentication tag for value.
func SignDesiredState(value DesiredState, key []byte) (string, error) {
	value.Signature = ""
	return sign("desired-state", value, key)
}

// SignCommand returns the transient-command-domain authentication tag for value.
func SignCommand(value Command, key []byte) (string, error) {
	value.Signature = ""
	return sign("command", value, key)
}

// SignReceipt returns the receipt-domain authentication tag for value.
func SignReceipt(value Receipt, key []byte) (string, error) {
	value.Signature = ""
	return sign("receipt", value, key)
}

// SignStatus returns the status-domain authentication tag for value.
func SignStatus(value Status, key []byte) (string, error) {
	value.Signature = ""
	return sign("status", value, key)
}

// SignDisplay returns the display-relay-domain authentication tag for value.
func SignDisplay(value Display, key []byte) (string, error) {
	value.Signature = ""
	return sign("display", value, key)
}

// SignHello returns the handshake-initiation authentication tag for value.
func SignHello(value Hello, key []byte) (string, error) {
	value.Signature = ""
	return sign("hello", value, key)
}

// SignWelcome returns the handshake-response authentication tag for value.
func SignWelcome(value Welcome, key []byte) (string, error) {
	value.Signature = ""
	return sign("welcome", value, key)
}

// Verify compares hexadecimal authentication tags in constant time.
func Verify(signature string, expected string) bool {
	if len(signature) != sha256.Size*2 || len(expected) != sha256.Size*2 {
		return false
	}
	provided, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(expected)
	return err == nil && hmac.Equal(want, provided)
}

// sign serializes a message and applies the protocol version and message-domain prefix.
func sign(domain string, value any, key []byte) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "neodse/protocol/v%d\x00%s\x00", Version, domain)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
