// File purpose: Defines the agent volatile runtime ownership, session keys, counters, and diagnostics.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/cec"
	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/gorilla/websocket"
)

// agentConnection owns one authenticated controller transport connection.
type agentConnection struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
}

// Config is the strict display-agent configuration contract.
type Config = config.Agent

// Agent owns all dependencies and mutable state for one display-agent instance.
type Agent struct {
	ctx                    context.Context
	workers                sync.WaitGroup
	config                 Config
	psk                    []byte
	commandKeys            *replay.Cache
	started                time.Time
	lastEventID            string
	desiredGeneration      string
	desiredRevision        uint64
	desiredUISocket        os.FileInfo
	rendererRetry          bool
	rendererReconcileMu    sync.Mutex
	rendererReconcileAfter time.Time
	reloadMu               sync.Mutex
	reloadTimer            *time.Timer
	reloadDelay            func() time.Duration
	version                string
	verbose                bool
	debug                  bool
	serialMu               sync.Mutex
	cecMu                  sync.Mutex
	cecDevice              *cec.Device
	cecAudioAddress        uint8
	cecAudioAddressKnown   bool
	stateMu                sync.RWMutex
	cecPower               string
	cecOutput              string
	cecCheckedAt           time.Time
	sessionMu              sync.Mutex
	sessionID              string
	sessionKeys            map[keyderivation.Purpose][]byte
	lastInboundSequence    uint64
	nextOutboundSequence   uint64
	transportConnected     atomic.Bool
	transportConnectedOnce atomic.Bool
	sessionProgress        atomic.Uint64
	connectionMu           sync.RWMutex
	connection             *agentConnection
	proxyRelayURL          string
	proxyRelayLogMu        sync.Mutex
	proxyRelayLastLog      time.Time
	proxyRelaySuppressed   uint64
	proxyRelayStateMu      sync.Mutex
	proxyRelayFailed       bool
	proxyRelayStatus       chan bool
	displayMu              sync.Mutex
	displayStreams         map[string]net.Conn
	vncAuthMu              sync.Mutex
	vncCredentials         map[[32]byte]vncCredential
	vncAuthListener        net.Listener
	restartUI              func() error
	displayController      func(instruction.DisplayOperation) error
	contentRenderer        func(instruction.ContentState) error
}

// installSession derives purpose-separated keys and resets both sequence directions.
func (a *Agent) installSession(sessionID, clientNonce, serverNonce string) error {
	keys, err := keyderivation.DeriveSessionKeys(a.psk, a.config.Agent.ID, clientNonce, serverNonce)
	if err != nil {
		return err
	}
	a.sessionMu.Lock()
	a.sessionID = sessionID
	a.sessionKeys = keys
	a.lastInboundSequence = 0
	a.nextOutboundSequence = 0
	a.sessionMu.Unlock()
	return nil
}

// clearSession erases session identifiers, keys, and sequence counters after disconnect.
func (a *Agent) clearSession() {
	a.closeDisplayStreams()
	a.sessionMu.Lock()
	a.sessionID = ""
	a.sessionKeys = nil
	a.lastInboundSequence = 0
	a.nextOutboundSequence = 0
	a.sessionMu.Unlock()
}

// verifyDesiredState validates and authenticates a complete state before advancing sequence.
func (a *Agent) verifyDesiredState(message protocol.DesiredState) bool {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if message.Protocol != protocol.Version || message.AgentID != a.config.Agent.ID || a.sessionID == "" || message.SessionID != a.sessionID || message.Sequence != a.lastInboundSequence+1 {
		return false
	}
	expected, err := protocol.SignDesiredState(message, a.sessionKeys[keyderivation.TransportCommand])
	if err != nil || !protocol.Verify(message.Signature, expected) {
		return false
	}
	generation, generationErr := hex.DecodeString(message.Generation)
	_, timestampErr := time.Parse(time.RFC3339Nano, message.Timestamp)
	if generationErr != nil || len(generation) != 16 || timestampErr != nil || message.EventID == "" || len(message.EventID) > 128 || message.Revision == 0 || (message.Apply != "" && message.Apply != "playback") || message.State.Validate() != nil {
		return false
	}
	if a.desiredGeneration == message.Generation && message.Revision < a.desiredRevision {
		return false
	}
	a.lastInboundSequence = message.Sequence
	return true
}

// commandVerification is the outcome of authenticating one transient command.
type commandVerification int

const (
	commandRejected commandVerification = iota
	commandAccepted
	// commandExpired is authentic and in sequence but too late to execute.
	commandExpired
)

// verifyCommand validates expiry and replay state after authentication and then advances sequence.
func (a *Agent) verifyCommand(message protocol.Command) commandVerification {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if message.Protocol != protocol.Version || message.AgentID != a.config.Agent.ID || a.sessionID == "" || message.SessionID != a.sessionID || message.Sequence != a.lastInboundSequence+1 {
		return commandRejected
	}
	expected, err := protocol.SignCommand(message, a.sessionKeys[keyderivation.TransportCommand])
	if err != nil || !protocol.Verify(message.Signature, expected) {
		return commandRejected
	}
	timestamp, timestampErr := time.Parse(time.RFC3339Nano, message.Timestamp)
	expiry, expiryErr := time.Parse(time.RFC3339Nano, message.ExpiresAt)
	now := time.Now().UTC()
	if timestampErr != nil || expiryErr != nil || message.EventID == "" || len(message.EventID) > 128 ||
		!expiry.After(timestamp) || expiry.Sub(timestamp) > 10*time.Minute || message.Command.Validate() != nil {
		return commandRejected
	}
	if now.After(expiry) {
		// The session sequence still rejects any replay of this message.
		a.lastInboundSequence = message.Sequence
		return commandExpired
	}
	if a.commandKeys.Accept(message.EventID, timestamp, now) != nil {
		return commandRejected
	}
	a.lastInboundSequence = message.Sequence
	return commandAccepted
}

// infof writes an operational message through the process-wide redacting logger.
func (a *Agent) infof(format string, values ...any) {
	log.Printf(format, values...)
}

// verbosef writes operation detail only when verbose diagnostics are enabled.
func (a *Agent) verbosef(format string, values ...any) {
	if a.verbose || a.debug {
		log.Printf(format, values...)
	}
}

// debugf writes protocol detail only when debug diagnostics are enabled.
func (a *Agent) debugf(format string, values ...any) {
	if a.debug {
		log.Printf(format, values...)
	}
}

// purposeKey derives a long-term purpose-separated key from the agent PSK.
func (a *Agent) purposeKey(purpose keyderivation.Purpose) ([]byte, error) {
	return keyderivation.Derive(a.psk, a.config.Agent.ID, purpose)
}
