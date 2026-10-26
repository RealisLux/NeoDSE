// File purpose: Rejects established session authority after durable credential rotation or deletion.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
)

// TestCancelledCredentialLookupDoesNotRevokeSession keeps request cancellation
// from changing another client's live agent authority. Every later lookup must
// still check the persistent credential before accepting the cached session.
func TestCancelledCredentialLookupDoesNotRevokeSession(t *testing.T) {
	for _, failure := range []string{"cancelled", "deadline"} {
		for _, change := range []string{"unchanged", "rotated", "deleted"} {
			t.Run(failure+"/"+change, func(t *testing.T) {
				s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
				old := s.sessions["display"]
				relay := &displayRelay{agentID: "display", streamID: "viewer", session: old, done: make(chan struct{})}
				s.displayRelays[relay.streamID] = relay
				var ctx context.Context
				var cancel context.CancelFunc
				if failure == "cancelled" {
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
				} else {
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				}
				defer cancel()
				if s.authenticatedSession(ctx, "display") != nil {
					t.Fatal("cancelled lookup granted session authority")
				}
				if s.sessions["display"] != old {
					t.Fatal("cancelled lookup revoked a valid session")
				}
				select {
				case <-relay.done:
					t.Fatal("cancelled lookup closed another client's display relay")
				default:
				}
				var err error
				switch change {
				case "rotated":
					err = s.store.PutAgent(context.Background(), "display", strings.Repeat("cd", 32), "10.99.0.2", true, time.Now())
				case "deleted":
					err = s.store.RemoveAgent(context.Background(), "display")
				}
				if err != nil {
					t.Fatal(err)
				}
				current := s.sessionFor("display")
				if change == "unchanged" {
					if current != old {
						t.Fatal("fresh authoritative lookup did not recover valid session")
					}
				} else {
					if current != nil || s.sessions["display"] != nil {
						t.Fatal("fresh lookup accepted a revoked credential")
					}
					select {
					case <-relay.done:
					default:
						t.Fatal("fresh lookup retained a revoked display relay")
					}
				}
				if old.nextSend != 0 || old.lastReceived != 0 {
					t.Fatal("credential lookup advanced protocol state")
				}
			})
		}
	}
}

// TestCancelledAgentProjectionReturnsError rejects partial offline projections
// while preserving independently authenticated agent sessions.
func TestCancelledAgentProjectionReturnsError(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	old := s.sessions["display"]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	states, err := s.loadAgentStates(ctx, Principal{AllAgents: true})
	if !errors.Is(err, context.Canceled) || len(states) != 0 {
		t.Fatalf("cancelled projection states=%v error=%v", states, err)
	}
	if s.sessionFor("display") != old {
		t.Fatal("cancelled projection revoked an agent session")
	}
}

// TestRotatedCredentialRejectsEstablishedSession covers every authenticated frame family.
func TestRotatedCredentialRejectsEstablishedSession(t *testing.T) {
	for _, operation := range []string{"status", "receipt", "hardware", "desired", "projection"} {
		t.Run(operation, func(t *testing.T) {
			const id = "display"
			s := testServerWithAgents(t, Config{}, map[string]string{id: ""})
			old := s.sessions[id]
			ctx := context.Background()
			now := time.Now().UTC()
			status := protocol.Status{Protocol: protocol.Version, SessionID: old.id, Sequence: 1,
				AgentID: id, Hostname: "before", Version: "test", Status: "online",
				StartedAt: now.Add(-time.Hour).Format(time.RFC3339), Timestamp: now.Format(time.RFC3339Nano)}
			if err := s.store.SaveStatus(ctx, status, now); err != nil {
				t.Fatal(err)
			}
			records, err := s.store.CreateCommand(ctx, "event", "test", []string{id}, instruction.NewCommand(instruction.RebootCommand{}), now, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			// A separate database handle models the root provisioning process.
			maintenance, err := store.Open(ctx, s.config.Server.Database, testDatabaseKey)
			if err != nil {
				t.Fatal(err)
			}
			defer maintenance.Close()
			if err := maintenance.PutAgent(ctx, id, strings.Repeat("cd", 32), "10.99.0.2", true, now); err != nil {
				t.Fatal(err)
			}
			sent := 0
			s.sendOverride = func(string, protocol.Frame) error { sent++; return nil }
			switch operation {
			case "status":
				status.Hostname = "after-rotation"
				status.Signature, _ = protocol.SignStatus(status, old.keys[keyderivation.TransportStatus])
				s.handleAgentFrame(id, "", mustJSON(t, protocol.Frame{Type: "status", Payload: mustJSON(t, status)}))
				statuses, err := s.store.AgentStatuses(ctx)
				if err != nil || statuses[0].Hostname != "before" {
					t.Fatal("old session persisted status after rotation")
				}
			case "receipt":
				r := protocol.Receipt{Protocol: protocol.Version, SessionID: old.id, Sequence: 1, AgentID: id,
					EventID: "event", Status: "completed", Operation: "reboot", Timestamp: now.Format(time.RFC3339Nano)}
				r.Signature, _ = protocol.SignReceipt(r, old.keys[keyderivation.TransportReceipt])
				if err := s.handleReceipt(id, mustJSON(t, r)); err == nil {
					t.Fatal("old receipt accepted after rotation")
				}
			case "hardware":
				s.deliverCommand(records[0])
				event, err := s.store.Event(ctx, "event")
				if err != nil || event.Deliveries[0].Status != "rejected" {
					t.Fatal("revoked session accepted hardware action")
				}
			case "desired":
				record, err := s.store.DesiredState(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.publishDesiredState(record, "event"); err == nil {
					t.Fatal("state sent to revoked session")
				}
			case "projection":
				states, err := s.loadAgentStates(ctx, Principal{AllAgents: true})
				if err != nil || len(states) != 1 || states[0].IsAuthenticated {
					t.Fatal("revoked session presented as authenticated")
				}
			}
			if sent != 0 || old.lastReceived != 0 {
				t.Fatal("revoked session advanced protocol state")
			}
		})
	}
}

// TestEstablishedSessionFailsClosedWithoutCredentialAuthority covers deletion and store failure.
func TestEstablishedSessionFailsClosedWithoutCredentialAuthority(t *testing.T) {
	for _, failure := range []string{"deleted", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
			if failure == "deleted" {
				if err := s.store.RemoveAgent(context.Background(), "display"); err != nil {
					t.Fatal(err)
				}
			} else if err := s.store.Close(); err != nil {
				t.Fatal(err)
			}
			if s.sessionFor("display") != nil {
				t.Fatal("session survived loss of credential authority")
			}
			if s.sessions["display"] != nil {
				t.Fatal("invalid session retained")
			}
		})
	}
}

// TestFreshHandshakeUsesRotatedCredential accepts only the current persistent secret.
func TestFreshHandshakeUsesRotatedCredential(t *testing.T) {
	const id = "display"
	s := testServerWithAgents(t, Config{}, map[string]string{id: ""})
	newPSK := strings.Repeat("cd", keyderivation.PSKBytes)
	if err := s.store.PutAgent(context.Background(), id, newPSK, "10.99.0.2", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	psk, _ := keyderivation.ParsePSK(newPSK)
	key, _ := keyderivation.Derive(psk, id, keyderivation.TransportHandshake)
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: id, Version: "test", ClientNonce: strings.Repeat("12", 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, _ = protocol.SignHello(hello, key)
	s.agentConnected(id)
	var sent []string
	s.sendOverride = func(_ string, frame protocol.Frame) error { sent = append(sent, frame.Type); return nil }
	s.handleAgentFrame(id, "", mustJSON(t, protocol.Frame{Type: "hello", Payload: mustJSON(t, hello)}))
	current := s.sessionFor(id)
	if current == nil || current.credential != sha256.Sum256(psk) {
		t.Fatal("new credential did not establish authority")
	}
	if len(sent) < 2 || sent[0] != "welcome" || sent[1] != "desired_state" {
		t.Fatalf("missing authenticated reconciliation: %v", sent)
	}
}

// TestRotationDuringWelcomeCannotPublishSession closes the final handshake race.
func TestRotationDuringWelcomeCannotPublishSession(t *testing.T) {
	const id = "display"
	s := testServerWithAgents(t, Config{}, map[string]string{id: ""})
	psk, _ := keyderivation.ParsePSK(strings.Repeat("ab", keyderivation.PSKBytes))
	key, _ := keyderivation.Derive(psk, id, keyderivation.TransportHandshake)
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: id, Version: "test", ClientNonce: strings.Repeat("12", 32), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, _ = protocol.SignHello(hello, key)
	s.agentConnected(id)
	s.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type != "welcome" {
			t.Fatal("revoked handshake published agent content")
		}
		return s.store.PutAgent(context.Background(), id, strings.Repeat("cd", 32), "10.99.0.2", true, time.Now())
	}
	if err := s.handleHello(id, "", mustJSON(t, hello), psk, key); err == nil {
		t.Fatal("handshake survived rotation during welcome")
	}
	if s.sessionFor(id) != nil {
		t.Fatal("stale handshake remained usable")
	}
}
