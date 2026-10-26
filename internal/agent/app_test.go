// File purpose: Verifies agent diagnostics, session authentication, typed message handling, and command allowlists.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
)

// TestAgentRejectsPositionalArguments ensures a misplaced config path cannot
// silently stop flag parsing and launch the agent with a different configuration.
func TestAgentRejectsPositionalArguments(t *testing.T) {
	for _, args := range [][]string{
		{"agent.yaml"},
		{"--config", "missing.yaml", "extra"},
		{"extra", "--config", "missing.yaml"},
	} {
		if err := Run(context.Background(), args, "test"); err == nil || !strings.Contains(err.Error(), "positional arguments") {
			t.Fatalf("Run(%q) = %v, want positional argument rejection", args, err)
		}
	}
}

// TestPeripheralDiagnosticsFitReceiptContract covers long and non-UTF-8 device responses.
func TestPeripheralDiagnosticsFitReceiptContract(t *testing.T) {
	for _, value := range []string{"short", strings.Repeat("x", 4096), strings.Repeat("界", 1400), strings.Repeat("\xff", 4096), "nul\x00diagnostic"} {
		for _, limit := range []int{protocol.ReceiptErrorMaxBytes, protocol.ReceiptDetailsMaxBytes, protocol.ReceiptValueMaxBytes} {
			bounded := boundedDiagnostic(value, limit)
			if len(bounded) > limit || !utf8.ValidString(bounded) || strings.ContainsRune(bounded, '\x00') {
				t.Fatalf("diagnostic violates %d-byte wire limit: bytes=%d valid=%t", limit, len(bounded), utf8.ValidString(bounded))
			}
			if value == "short" && bounded != value {
				t.Fatal("short diagnostic changed")
			}
		}
	}
}

// TestDesiredRevisionCannotRegress rejects stale content within a committed generation.
func TestDesiredRevisionCannotRegress(t *testing.T) {
	agent, key := newSessionAgent(t)
	agent.desiredGeneration = strings.Repeat("01", 16)
	agent.desiredRevision = 4
	state := protocol.DesiredState{Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, AgentID: agent.config.Agent.ID, EventID: "event", Generation: agent.desiredGeneration, Revision: 3, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), State: instruction.DefaultState()}
	state.Signature, _ = protocol.SignDesiredState(state, key)
	if agent.verifyDesiredState(state) {
		t.Fatal("older committed revision accepted")
	}
	if agent.lastInboundSequence != 0 {
		t.Fatal("rejected revision advanced sequence")
	}
	state.Revision = 4
	state.Signature, _ = protocol.SignDesiredState(state, key)
	if !agent.verifyDesiredState(state) {
		t.Fatal("latest revision reconciliation rejected")
	}
}

// TestWelcomeReplayCannotResetSequence prevents transport replay from reopening executed commands.
func TestWelcomeReplayCannotResetSequence(t *testing.T) {
	agent, _ := newSessionAgent(t)
	agent.clearSession()
	clientNonce, serverNonce := strings.Repeat("11", 32), strings.Repeat("22", 32)
	hello := protocol.Hello{ClientNonce: clientNonce}
	handshake, err := keyderivation.Derive(agent.psk, agent.config.Agent.ID, keyderivation.TransportHandshake)
	if err != nil {
		t.Fatal(err)
	}
	welcome := protocol.Welcome{Protocol: protocol.Version, AgentID: agent.config.Agent.ID, ClientNonce: clientNonce, ServerNonce: serverNonce, SessionID: strings.Repeat("33", 16), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	welcome.Signature, _ = protocol.SignWelcome(welcome, handshake)
	payload, _ := json.Marshal(welcome)
	if err := agent.acceptWelcome(payload, hello, handshake); err != nil {
		t.Fatal(err)
	}
	agent.lastInboundSequence = 7
	agent.nextOutboundSequence = 9
	if err := agent.acceptWelcome(payload, hello, handshake); err == nil {
		t.Fatal("welcome replay accepted")
	}
	if agent.lastInboundSequence != 7 || agent.nextOutboundSequence != 9 {
		t.Fatal("replay reset sequence counters")
	}
}

// TestAgentDiagnosticLogLevels verifies agent diagnostic log levels.
func TestAgentDiagnosticLogLevels(t *testing.T) {
	var output bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(originalOutput)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})

	agent := &Agent{}
	agent.verbosef("verbose message")
	agent.debugf("debug message")
	if output.Len() != 0 {
		t.Fatalf("info level emitted diagnostic output: %q", output.String())
	}
	agent.verbose = true
	agent.verbosef("verbose message")
	agent.debugf("debug message")
	if got := output.String(); got != "verbose message\n" {
		t.Fatalf("verbose output = %q", got)
	}

	output.Reset()
	agent.verbose = false
	agent.debug = true
	agent.verbosef("verbose message")
	agent.debugf("debug message")
	if got := output.String(); got != "verbose message\ndebug message\n" {
		t.Fatalf("debug output = %q", got)
	}
}

// TestRunHelpDoesNotStartAgent verifies run help does not start agent.
func TestRunHelpDoesNotStartAgent(t *testing.T) {
	if err := Run(context.Background(), []string{"-help"}, "test-version"); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Run(-help) error = %v, want flag.ErrHelp", err)
	}
}

// TestTransportDialerIgnoresEnvironmentProxies keeps plaintext control traffic on WireGuard.
func TestTransportDialerIgnoresEnvironmentProxies(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://attacker.invalid:8080")
	}
	dialer := newTransportDialer("")
	if dialer.Proxy != nil {
		t.Fatal("agent WebSocket dialer inherited an environment proxy")
	}
	if dialer.HandshakeTimeout != transportDialTimeout || dialer.NetDialContext == nil {
		t.Fatal("agent WebSocket dialer is missing explicit network timeouts")
	}
}

// TestStableTransportSessionResetsBackoff verifies a recovered connection restores prompt retries.
func TestStableTransportSessionResetsBackoff(t *testing.T) {
	if got := resetTransportBackoff(transportRetryMax, time.Second, true); got != time.Second {
		t.Fatalf("successful short session backoff = %s, want 1s", got)
	}
	if got := resetTransportBackoff(transportRetryMax, stableTransportSession, false); got != time.Second {
		t.Fatalf("stable session backoff = %s, want 1s", got)
	}
	if got := resetTransportBackoff(transportRetryMax, stableTransportSession-time.Nanosecond, false); got != transportRetryMax {
		t.Fatalf("short session backoff = %s, want %s", got, transportRetryMax)
	}
}

// TestTypedMessagesShareOneAuthenticatedSequence verifies typed messages share one authenticated sequence.
func TestTypedMessagesShareOneAuthenticatedSequence(t *testing.T) {
	agent, key := newSessionAgent(t)
	desired := protocol.DesiredState{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "event-1",
		AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Generation: strings.Repeat("01", 16), Revision: 1, State: instruction.DefaultState(),
	}
	desired.Signature, _ = protocol.SignDesiredState(desired, key)
	if !agent.verifyDesiredState(desired) {
		t.Fatal("valid desired state was rejected")
	}

	command := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 2, EventID: "event-2",
		AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayMute}),
	}
	command.Signature, _ = protocol.SignCommand(command, key)
	if agent.verifyCommand(command) != commandAccepted {
		t.Fatal("valid command following desired state was rejected")
	}

	command.Sequence = 3
	command.EventID = "event-3"
	command.Signature = desired.Signature
	if agent.verifyCommand(command) != commandRejected {
		t.Fatal("cross-type signature was accepted")
	}
	command.Signature, _ = protocol.SignCommand(command, key)
	if agent.verifyCommand(command) != commandAccepted {
		t.Fatal("failed authentication advanced the shared sequence")
	}
	if agent.verifyDesiredState(desired) {
		t.Fatal("replayed desired state was accepted")
	}
}

// TestHandleCommandRejectsInvalidSemantics verifies handle command rejects invalid semantics.
func TestHandleCommandRejectsInvalidSemantics(t *testing.T) {
	agent, key := newSessionAgent(t)
	now := time.Now().UTC()
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "expired",
		AgentID: agent.config.Agent.ID, Timestamp: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayMute}),
	}
	message.Signature, _ = protocol.SignCommand(message, key)
	agent.handleCommand(message)
	if got := agent.currentLastEventID(); got != "" {
		t.Fatalf("rejected command changed last event ID to %q", got)
	}
	if agent.lastInboundSequence != 0 {
		t.Fatalf("rejected command advanced sequence to %d", agent.lastInboundSequence)
	}
}

// TestInvalidDesiredStateDoesNotAdvanceSequence verifies invalid desired state does not advance sequence.
func TestInvalidDesiredStateDoesNotAdvanceSequence(t *testing.T) {
	agent, key := newSessionAgent(t)
	message := protocol.DesiredState{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "event-state",
		AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Generation: "invalid", Revision: 1, State: instruction.DefaultState(),
	}
	message.Signature, _ = protocol.SignDesiredState(message, key)
	if agent.verifyDesiredState(message) || agent.lastInboundSequence != 0 {
		t.Fatal("invalid desired state consumed the shared sequence")
	}
	message.Generation = strings.Repeat("02", 16)
	message.Signature, _ = protocol.SignDesiredState(message, key)
	if !agent.verifyDesiredState(message) || agent.lastInboundSequence != 1 {
		t.Fatal("valid desired state was not accepted at the unconsumed sequence")
	}
}

// TestAppliedDesiredStateIsIdempotentAcrossSessions verifies reconnect
// reconciliation preserves existing WebViews while changed state is reapplied.
func TestAppliedDesiredStateIsIdempotentAcrossSessions(t *testing.T) {
	agent := &Agent{
		desiredGeneration: strings.Repeat("03", 16),
		desiredRevision:   7,
	}
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	agent.desiredUISocket, _ = os.Stat(agent.config.Agent.UISocket)
	if !agent.canApplyPlayback(strings.Repeat("03", 16), 8) {
		t.Fatal("contiguous playback update would unnecessarily rebuild the renderer")
	}
	if !agent.desiredStateAlreadyApplied(strings.Repeat("03", 16), 7) {
		t.Fatal("applied desired state was not recognized")
	}
	if agent.desiredStateAlreadyApplied(strings.Repeat("03", 16), 8) {
		t.Fatal("new desired-state revision was treated as already applied")
	}
	if agent.desiredStateAlreadyApplied(strings.Repeat("04", 16), 7) {
		t.Fatal("new desired-state generation was treated as already applied")
	}
	if (&Agent{}).desiredStateAlreadyApplied(strings.Repeat("03", 16), 7) {
		t.Fatal("fresh agent skipped initial desired-state application")
	}
}

// TestRendererReplacementReappliesDesiredState models volatile state loss without an agent restart.
func TestRendererReplacementReappliesDesiredState(t *testing.T) {
	agent, key := newSessionAgent(t)
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	applied := 0
	agent.contentRenderer = func(instruction.ContentState) error { applied++; return nil }
	message := protocol.DesiredState{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "event-state",
		AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Generation: strings.Repeat("03", 16), Revision: 7, State: instruction.DefaultState(),
	}
	message.Signature, _ = protocol.SignDesiredState(message, key)
	if err := agent.handleDesiredState(message); err != nil {
		t.Fatal(err)
	}
	agent.reconcileRenderer()
	if !agent.desiredStateAlreadyApplied(message.Generation, message.Revision) {
		t.Fatal("unchanged renderer lost its applied marker")
	}
	if err := os.Rename(agent.config.Agent.UISocket, agent.config.Agent.UISocket+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if agent.desiredStateAlreadyApplied(message.Generation, message.Revision) {
		t.Fatal("replacement renderer inherited old content marker")
	}
	agent.reconcileRenderer()
	if agent.desiredRevision != 0 || agent.desiredGeneration != "" {
		t.Fatal("renderer replacement did not request reconciliation")
	}
	message.Sequence++
	message.Signature, _ = protocol.SignDesiredState(message, key)
	if err := agent.handleDesiredState(message); err != nil || applied != 2 {
		t.Fatalf("state not reapplied: applied=%d error=%v", applied, err)
	}
	if err := os.Remove(agent.config.Agent.UISocket); err != nil {
		t.Fatal(err)
	}
	agent.reconcileRenderer()
	if agent.desiredRevision != message.Revision {
		t.Fatal("missing renderer triggered premature reconciliation")
	}
	message.Sequence++
	message.Signature, _ = protocol.SignDesiredState(message, key)
	if err := agent.handleDesiredState(message); err != nil || !agent.rendererRetry {
		t.Fatalf("unavailable renderer did not schedule reconciliation: %v", err)
	}
}

type reusedRendererSocketInfo struct {
	os.FileInfo
	modified time.Time
}

// ModTime overrides the embedded metadata timestamp for socket-reuse testing.
func (information reusedRendererSocketInfo) ModTime() time.Time { return information.modified }

// TestRendererSocketIdentityRejectsReusedInode covers immediate Unix-socket
// replacement where the filesystem returns the former device and inode pair.
func TestRendererSocketIdentityRejectsReusedInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	information, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameRendererSocket(information, information) {
		t.Fatal("unchanged renderer socket was rejected")
	}
	reused := reusedRendererSocketInfo{FileInfo: information, modified: information.ModTime().Add(time.Nanosecond)}
	if sameRendererSocket(information, reused) {
		t.Fatal("replacement renderer inherited a reused device and inode identity")
	}
}

// TestInvalidTransportFrameEndsSession verifies invalid transport frame ends session.
func TestInvalidTransportFrameEndsSession(t *testing.T) {
	agent, _ := newSessionAgent(t)
	err := agent.handleTransportFrame(protocol.Frame{Type: "unsupported"}, protocol.Hello{}, nil)
	if err == nil {
		t.Fatal("unsupported transport frame was accepted")
	}
}

// TestRunSystemCommandRejectsArbitraryInput verifies run system command rejects arbitrary input.
func TestRunSystemCommandRejectsArbitraryInput(t *testing.T) {
	if err := runSystemCommand("restart; reboot"); err == nil {
		t.Fatal("arbitrary system command was accepted")
	}
	if err := runSystemCommand(instruction.CommandRestart); err == nil {
		t.Fatal("agent restart was delegated to a system command")
	}
}

// TestRestartKeepsAgentRunning verifies the UI restarts without ending the receipt session.
func TestRestartKeepsAgentRunning(t *testing.T) {
	agent, key := newSessionAgent(t)
	uiRestarted := false
	agent.restartUI = func() error { uiRestarted = true; return nil }
	now := time.Now().UTC()
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "restart-event",
		AgentID: agent.config.Agent.ID, Timestamp: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.RestartCommand{}),
	}
	message.Signature, _ = protocol.SignCommand(message, key)
	if err := agent.handleCommand(message); err != nil {
		t.Fatal(err)
	}
	if !uiRestarted {
		t.Fatal("UI service was not restarted")
	}
	if agent.sessionID != "session-1" {
		t.Fatal("UI restart cleared the active control session")
	}
}

// TestRestartUIFailureKeepsAgentRunning verifies a failed UI restart does not stop the agent.
func TestRestartUIFailureKeepsAgentRunning(t *testing.T) {
	agent, key := newSessionAgent(t)
	agent.restartUI = func() error { return errors.New("service failed") }
	now := time.Now().UTC()
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "restart-failed",
		AgentID: agent.config.Agent.ID, Timestamp: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.RestartCommand{}),
	}
	message.Signature, _ = protocol.SignCommand(message, key)
	if err := agent.handleCommand(message); err != nil {
		t.Fatal(err)
	}
	if agent.sessionID != "session-1" {
		t.Fatal("failed UI restart cleared the active control session")
	}
}

// TestRestartDefersRendererReconciliation keeps the receipt session open while
// the UI socket is replaced and until the final receipt has had time to drain.
func TestRestartDefersRendererReconciliation(t *testing.T) {
	agent, key := newSessionAgent(t)
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	agent.desiredUISocket, _ = os.Stat(agent.config.Agent.UISocket)
	agent.desiredGeneration, agent.desiredRevision = "generation", 1
	started := make(chan struct{})
	finish := make(chan struct{})
	agent.restartUI = func() error {
		close(started)
		<-finish
		return nil
	}
	now := time.Now().UTC()
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "restart-reconcile",
		AgentID: agent.config.Agent.ID, Timestamp: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.RestartCommand{}),
	}
	message.Signature, _ = protocol.SignCommand(message, key)
	commandDone := make(chan error, 1)
	go func() { commandDone <- agent.handleCommand(message) }()
	<-started
	if err := os.Remove(agent.config.Agent.UISocket); err != nil {
		t.Fatal(err)
	}
	reconcileDone := make(chan struct{})
	go func() { agent.reconcileRenderer(); close(reconcileDone) }()
	select {
	case <-reconcileDone:
		t.Fatal("heartbeat reconciled before restart completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(finish)
	if err := <-commandDone; err != nil {
		t.Fatal(err)
	}
	<-reconcileDone
	if agent.desiredRevision != 1 {
		t.Fatal("heartbeat reconciled before the receipt drain interval")
	}
	agent.rendererReconcileMu.Lock()
	agent.rendererReconcileAfter = time.Time{}
	agent.rendererReconcileMu.Unlock()
	if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	agent.reconcileRenderer()
	if agent.desiredRevision != 0 {
		t.Fatal("renderer replacement was not reconciled after the drain interval")
	}
}

// TestIsWireGuardInterface verifies is wire guard interface.
func TestIsWireGuardInterface(t *testing.T) {
	var agentConfig Config
	agentConfig.Agent.WireGuardInterface = "neodse"
	agent := &Agent{config: agentConfig}
	if !agent.isWireGuardInterface("neodse") {
		t.Fatal("configured WireGuard interface was not recognized")
	}
	if agent.isWireGuardInterface("eth0") {
		t.Fatal("non-WireGuard interface was recognized")
	}
}

// newSessionAgent returns an agent with deterministic session keys for authentication tests.
func newSessionAgent(t *testing.T) (*Agent, []byte) {
	t.Helper()
	var cfg Config
	cfg.Agent.ID = "display-01"
	psk, err := keyderivation.ParsePSK(strings.Repeat("ab", keyderivation.PSKBytes))
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{config: cfg, psk: psk, commandKeys: replay.New(2*time.Minute, 128)}
	clientNonce := strings.Repeat("11", 32)
	serverNonce := strings.Repeat("22", 32)
	if err := agent.installSession("session-1", clientNonce, serverNonce); err != nil {
		t.Fatal(err)
	}
	key, err := keyderivation.DeriveSession(psk, cfg.Agent.ID, clientNonce, serverNonce, keyderivation.TransportCommand)
	if err != nil {
		t.Fatal(err)
	}
	return agent, key
}

// TestPlaybackReconciliationRestoresMissingContent prevents timing hints from
// marking skipped or failed playlist changes as successfully rendered.
func TestPlaybackReconciliationRestoresMissingContent(t *testing.T) {
	for _, scenario := range []string{"skipped revision", "new generation", "failed renderer"} {
		t.Run(scenario, func(t *testing.T) {
			agent, key := newSessionAgent(t)
			agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
			if err := os.WriteFile(agent.config.Agent.UISocket, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			agent.desiredUISocket, _ = os.Stat(agent.config.Agent.UISocket)
			agent.desiredGeneration = strings.Repeat("03", 16)
			agent.desiredRevision = 7
			message := protocol.DesiredState{
				Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "event-sync",
				AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Generation: agent.desiredGeneration, Revision: 8, Apply: "playback",
				State: instruction.DesiredState{Content: instruction.ContentState{
					Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/new"},
				}},
			}
			switch scenario {
			case "skipped revision":
				message.Revision = 9
			case "new generation":
				message.Generation = strings.Repeat("04", 16)
			case "failed renderer":
				agent.rendererRetry = true
			}
			applied := false
			agent.contentRenderer = func(content instruction.ContentState) error {
				applied = len(content.URLs) == 1 && content.URLs[0] == "https://example.test/new"
				return nil
			}
			message.Signature, _ = protocol.SignDesiredState(message, key)
			if err := agent.handleDesiredState(message); err != nil {
				t.Fatal(err)
			}
			if !applied || agent.desiredRevision != message.Revision || agent.rendererRetry {
				t.Fatal("timing update failed to restore the complete authoritative playlist")
			}
		})
	}
}

// TestReconnectReloadIsDeferred spreads fleet-wide reconnect reloads over time
// and drops a pending reload once newer content replaces the playlist.
func TestReconnectReloadIsDeferred(t *testing.T) {
	agent, key := newSessionAgent(t)
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	listener, err := net.Listen("unix", agent.config.Agent.UISocket)
	if err != nil {
		t.Fatal(err)
	}
	reloads := make(chan struct{}, 8)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			peer, err := listener.Accept()
			if err != nil {
				return
			}
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			var request map[string]any
			if json.NewDecoder(peer).Decode(&request) == nil && request["cmd"] == "reload" {
				reloads <- struct{}{}
			}
			_ = json.NewEncoder(peer).Encode(uiResponse{Status: "accepted"})
			_ = peer.Close()
		}
	}()
	t.Cleanup(func() { agent.cancelReconnectReload(); _ = listener.Close(); <-stopped })
	generation := strings.Repeat("05", 16)
	agent.desiredGeneration, agent.desiredRevision = generation, 4
	agent.desiredUISocket, _ = os.Stat(agent.config.Agent.UISocket)
	delay := 300 * time.Millisecond
	agent.reloadDelay = func() time.Duration { return delay }
	reconcile := func(sequence uint64) {
		t.Helper()
		message := protocol.DesiredState{
			Protocol: protocol.Version, SessionID: "session-1", Sequence: sequence, EventID: fmt.Sprintf("event-%d", sequence),
			AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Generation: generation, Revision: 4,
			State: instruction.DesiredState{Content: instruction.ContentState{
				Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/display"},
			}},
		}
		message.Signature, _ = protocol.SignDesiredState(message, key)
		if err := agent.handleDesiredState(message); err != nil {
			t.Fatal(err)
		}
	}

	started := time.Now()
	reconcile(1)
	select {
	case <-reloads:
		if elapsed := time.Since(started); elapsed < delay {
			t.Fatalf("reconnect reload ran after %s, before its %s delay", elapsed, delay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect reload never ran")
	}

	reconcile(2)
	agent.sessionMu.Lock()
	agent.desiredRevision = 5 // newer content was applied before the timer fired
	agent.sessionMu.Unlock()
	select {
	case <-reloads:
		t.Fatal("obsolete reconnect reload replaced newer content")
	case <-time.After(3 * delay):
	}
}

// TestDesiredStateWaitsForStartedReconnectReload keeps an already running
// reload from racing past cancellation and touching a replacement playlist.
func TestDesiredStateWaitsForStartedReconnectReload(t *testing.T) {
	agent, key := newSessionAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	agent.ctx = ctx
	agent.config.Agent.UISocket = filepath.Join(t.TempDir(), "ui.sock")
	listener, err := net.Listen("unix", agent.config.Agent.UISocket)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	reloadStarted := make(chan struct{})
	acknowledge := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
		var request uiReloadRequest
		if json.NewDecoder(peer).Decode(&request) != nil || request.Command != "reload" {
			return
		}
		close(reloadStarted)
		select {
		case <-acknowledge:
			_ = json.NewEncoder(peer).Encode(uiResponse{Status: "accepted"})
		case <-ctx.Done():
		}
	}()
	t.Cleanup(func() {
		cancel()
		agent.cancelReconnectReload()
		_ = listener.Close()
		<-serverDone
	})
	generation := strings.Repeat("06", 16)
	agent.desiredGeneration, agent.desiredRevision = generation, 4
	agent.desiredUISocket, _ = os.Stat(agent.config.Agent.UISocket)
	agent.reloadDelay = func() time.Duration { return 0 }
	agent.scheduleReconnectReload(generation, 4)
	select {
	case <-reloadStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect reload did not reach the renderer")
	}

	applied := make(chan struct{}, 1)
	agent.contentRenderer = func(instruction.ContentState) error { applied <- struct{}{}; return nil }
	message := protocol.DesiredState{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "event-new-playlist",
		AgentID: agent.config.Agent.ID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Generation: generation, Revision: 5,
		State: instruction.DesiredState{Content: instruction.ContentState{
			Mode: instruction.ContentPlaylist, URLs: []string{"https://example.test/new"},
		}},
	}
	message.Signature, _ = protocol.SignDesiredState(message, key)
	stateDone := make(chan error, 1)
	go func() { stateDone <- agent.handleDesiredState(message) }()
	select {
	case <-applied:
		t.Fatal("new content was applied before the running reload completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(acknowledge)
	select {
	case err := <-stateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("desired state did not resume after reload acknowledgement")
	}
	select {
	case <-applied:
	default:
		t.Fatal("new content was not applied")
	}
}
