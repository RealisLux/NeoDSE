// File purpose: Verifies controller-agent handshake authentication and safe failure classification.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
)

// TestHandleHelloAcceptsMatchingEnrollmentCredential verifies handle hello accepts matching enrollment credential.
func TestHandleHelloAcceptsMatchingEnrollmentCredential(t *testing.T) {
	const agentID = "display-01"
	pskValue := strings.Repeat("ab", keyderivation.PSKBytes)
	controller := testServerWithAgents(t, Config{}, map[string]string{agentID: pskValue})
	controller.agentConnected(agentID)
	var sent []protocol.Frame
	controller.sendOverride = func(gotAgentID string, frame protocol.Frame) error {
		if gotAgentID != agentID {
			t.Fatalf("frame target = %s, want %s", gotAgentID, agentID)
		}
		sent = append(sent, frame)
		return nil
	}
	psk, err := keyderivation.ParsePSK(pskValue)
	if err != nil {
		t.Fatal(err)
	}
	handshakeKey, err := keyderivation.Derive(psk, agentID, keyderivation.TransportHandshake)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: agentID, Version: "1.0.0", ClientNonce: hex.EncodeToString(nonce), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, err = protocol.SignHello(hello, handshakeKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.handleHello(agentID, "", mustJSON(t, hello), psk, handshakeKey); err != nil {
		t.Fatal(err)
	}
	if len(sent) < 1 || sent[0].Type != "welcome" {
		t.Fatalf("first controller frame = %#v, want welcome", sent)
	}
}

// TestHandleHelloClassifiesCredentialMismatch verifies handle hello classifies credential mismatch.
func TestHandleHelloClassifiesCredentialMismatch(t *testing.T) {
	const agentID = "display-01"
	controllerPSK, _ := keyderivation.ParsePSK(strings.Repeat("ab", keyderivation.PSKBytes))
	agentPSK, _ := keyderivation.ParsePSK(strings.Repeat("cd", keyderivation.PSKBytes))
	controllerKey, _ := keyderivation.Derive(controllerPSK, agentID, keyderivation.TransportHandshake)
	agentKey, _ := keyderivation.Derive(agentPSK, agentID, keyderivation.TransportHandshake)
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: agentID, Version: "1.0.0", ClientNonce: strings.Repeat("12", 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, _ = protocol.SignHello(hello, agentKey)
	controller := newServer(Config{}, "test")
	if err := controller.handleHello(agentID, "", mustJSON(t, hello), controllerPSK, controllerKey); err == nil || !strings.Contains(err.Error(), "credentials do not match") {
		t.Fatalf("credential mismatch classification = %v", err)
	}
}

// TestHandleHelloRejectsActiveSession preserves handshake capacity for unrelated agents.
func TestHandleHelloRejectsActiveSession(t *testing.T) {
	pskValue := strings.Repeat("ab", keyderivation.PSKBytes)
	controller := testServerWithAgents(t, Config{}, map[string]string{"display-01": pskValue, "display-02": pskValue})
	controller.clearSessions()
	controller.helloReplay = replay.New(2*time.Minute, 2)
	controller.sendOverride = func(string, protocol.Frame) error { return nil }
	psk, _ := keyderivation.ParsePSK(pskValue)
	hello := func(agentID, connectionID, nonce string) error {
		key, err := keyderivation.Derive(psk, agentID, keyderivation.TransportHandshake)
		if err != nil {
			t.Fatal(err)
		}
		message := protocol.Hello{Protocol: protocol.Version, AgentID: agentID, Version: "1.0.0", ClientNonce: strings.Repeat(nonce, 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		message.Signature, err = protocol.SignHello(message, key)
		if err != nil {
			t.Fatal(err)
		}
		return controller.handleHello(agentID, connectionID, mustJSON(t, message), psk, key)
	}
	if err := hello("display-01", "connection-01", "11"); err != nil {
		t.Fatal(err)
	}
	active := controller.sessionFor("display-01")
	if err := hello("display-01", "connection-01", "22"); err == nil {
		t.Fatal("fresh hello replaced an active session and consumed shared replay capacity")
	}
	if controller.sessionFor("display-01") != active {
		t.Fatal("rejected hello changed session authority")
	}
	if err := hello("display-02", "connection-02", "33"); err != nil {
		t.Fatalf("rejected rehandshake exhausted another agent's replay capacity: %v", err)
	}
}

// TestHandleHelloAcceptsFreshConnection preserves normal recovery after disconnection.
func TestHandleHelloAcceptsFreshConnection(t *testing.T) {
	const agentID = "display-01"
	pskValue := strings.Repeat("ab", keyderivation.PSKBytes)
	controller := testServerWithAgents(t, Config{}, map[string]string{agentID: pskValue})
	controller.agentConnected(agentID)
	controller.sendOverride = func(string, protocol.Frame) error { return nil }
	psk, _ := keyderivation.ParsePSK(pskValue)
	key, _ := keyderivation.Derive(psk, agentID, keyderivation.TransportHandshake)
	var previous *agentSession
	for index, nonce := range []string{"11", "22"} {
		connectionID := "connection-" + nonce
		message := protocol.Hello{Protocol: protocol.Version, AgentID: agentID, Version: "1.0.0", ClientNonce: strings.Repeat(nonce, 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		message.Signature, _ = protocol.SignHello(message, key)
		if err := controller.handleHello(agentID, connectionID, mustJSON(t, message), psk, key); err != nil {
			t.Fatalf("connection %d: %v", index, err)
		}
		current := controller.sessionFor(agentID)
		if current == nil || current == previous {
			t.Fatal("new connection did not receive fresh session authority")
		}
		previous = current
		controller.clearRouteSession(agentID, connectionID)
	}
}

// TestHandleHelloIsolatesReplayCapacity bounds a reconnecting identity while
// preserving replay checks and handshake capacity for a different agent.
func TestHandleHelloIsolatesReplayCapacity(t *testing.T) {
	pskValue := strings.Repeat("ab", keyderivation.PSKBytes)
	controller := testServerWithAgents(t, Config{}, map[string]string{"display-01": pskValue, "display-02": pskValue})
	controller.clearSessions()
	controller.helloReplay = replay.New(2*time.Minute, helloReplayPerAgent+1)
	controller.sendOverride = func(string, protocol.Frame) error { return nil }
	psk, _ := keyderivation.ParsePSK(pskValue)
	hello := func(agentID string, index int) error {
		key, err := keyderivation.Derive(psk, agentID, keyderivation.TransportHandshake)
		if err != nil {
			t.Fatal(err)
		}
		message := protocol.Hello{Protocol: protocol.Version, AgentID: agentID, Version: "1.0.0", ClientNonce: fmt.Sprintf("%064x", index), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		message.Signature, err = protocol.SignHello(message, key)
		if err != nil {
			t.Fatal(err)
		}
		connectionID := fmt.Sprintf("connection-%d", index)
		err = controller.handleHello(agentID, connectionID, mustJSON(t, message), psk, key)
		controller.clearRouteSession(agentID, connectionID)
		return err
	}
	for index := range helloReplayPerAgent {
		if err := hello("display-01", index); err != nil {
			t.Fatalf("reconnection %d: %v", index, err)
		}
	}
	if err := hello("display-01", helloReplayPerAgent); !errors.Is(err, replay.ErrFull) {
		t.Fatalf("agent exceeded its retained nonce quota: %v", err)
	}
	if err := hello("display-02", 0); err != nil {
		t.Fatalf("another identity lost handshake capacity: %v", err)
	}
}
