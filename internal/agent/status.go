// File purpose: Publishes authenticated status, receipts, and frames from volatile agent state.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/gorilla/websocket"
)

const cecStatusPollInterval = time.Minute

// heartbeat publishes current volatile status at a bounded interval.
func (a *Agent) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(transportPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.reconcileRenderer()
		if !a.transportConnected.Load() {
			continue
		}
		if err := a.sendTransportPing(); err != nil {
			a.verbosef("! Transport keepalive failed: %v", err)
			continue
		}
		a.refreshCECStatusIfDue()
		if err := a.sendStatus(); err != nil {
			a.verbosef("! Transport status update failed: %v", err)
		}
	}
}

// sendTransportPing keeps an otherwise idle control connection observable from the agent.
func (a *Agent) sendTransportPing() error {
	a.connectionMu.RLock()
	conn := a.connection
	a.connectionMu.RUnlock()
	if conn == nil {
		return os.ErrNotExist
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	err := conn.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(transportWriteTimeout))
	if err != nil {
		_ = conn.ws.Close()
	}
	return err
}

// sendStatus signs and sends one status message for the active session.
func (a *Agent) sendStatus() error {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if a.sessionID == "" {
		return os.ErrNotExist
	}
	a.nextOutboundSequence++
	cecPower, cecOutput, cecCheckedAt := a.currentCECStatus()
	st := protocol.Status{Protocol: protocol.Version, SessionID: a.sessionID, Sequence: a.nextOutboundSequence, AgentID: a.config.Agent.ID, FriendlyName: a.config.Agent.FriendlyName, Hostname: hostname(), Version: a.version, Status: "online", StartedAt: a.started.UTC().Format(time.RFC3339), UptimeSeconds: uint64(time.Since(a.started).Seconds()), LastEventID: a.currentLastEventID(), CECEnabled: a.config.CEC.Enabled, CECPower: cecPower, CECOutput: cecOutput, CECCheckedAt: formatCECCheckedAt(cecCheckedAt), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	sig, err := protocol.SignStatus(st, a.sessionKeys[keyderivation.TransportStatus])
	if err != nil {
		return err
	}
	st.Signature = sig
	return a.send("status", st)
}

// refreshCECStatusIfDue refreshes the local CEC observation at a slower cadence
// than the heartbeat, preventing a hardware timeout from dominating transport work.
func (a *Agent) refreshCECStatusIfDue() {
	if !a.config.CEC.Enabled {
		return
	}
	_, _, checkedAt := a.currentCECStatus()
	if !checkedAt.IsZero() && time.Since(checkedAt) < cecStatusPollInterval {
		return
	}
	power, output, err := a.cecPowerStatus()
	if err != nil {
		a.verbosef("! HDMI-CEC status probe failed: %v", err)
	}
	a.rememberCECStatus(power, output)
}

// rememberCECStatus updates the CEC observation included in subsequent heartbeats.
func (a *Agent) rememberCECStatus(power, output string) {
	a.stateMu.Lock()
	a.cecPower = power
	a.cecOutput = output
	a.cecCheckedAt = time.Now().UTC()
	a.stateMu.Unlock()
}

// currentCECStatus reads one consistent CEC observation snapshot.
func (a *Agent) currentCECStatus() (string, string, time.Time) {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	power := a.cecPower
	if power == "" {
		power = "unknown"
	}
	return power, a.cecOutput, a.cecCheckedAt
}

// formatCECCheckedAt serializes an optional CEC observation timestamp.
func formatCECCheckedAt(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// hostname returns the local hostname or an empty value when lookup fails.
func hostname() string {
	host, _ := os.Hostname()
	return host
}

// currentLastEventID returns the latest volatile event identifier under read ownership.
func (a *Agent) currentLastEventID() string {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.lastEventID
}

// publishCommandReceipt signs and sends a bounded public command outcome.
func (a *Agent) publishCommandReceipt(eventID, status, operation, errorMessage string) {
	a.publishCommandReceiptWithResult(eventID, status, operation, errorMessage, "", "")
}

// publishCommandReceiptWithResult includes bounded diagnostics and a normalized
// result where a command provides one, such as display power or audio volume.
func (a *Agent) publishCommandReceiptWithResult(eventID, status, operation, errorMessage, details, value string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if a.sessionID == "" {
		return
	}
	a.nextOutboundSequence++
	r := protocol.Receipt{Protocol: protocol.Version, SessionID: a.sessionID, Sequence: a.nextOutboundSequence, EventID: eventID, AgentID: a.config.Agent.ID, Status: status, Operation: operation, Error: boundedDiagnostic(errorMessage, protocol.ReceiptErrorMaxBytes), Details: boundedDiagnostic(details, protocol.ReceiptDetailsMaxBytes), Value: boundedDiagnostic(value, protocol.ReceiptValueMaxBytes), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	sig, err := protocol.SignReceipt(r, a.sessionKeys[keyderivation.TransportReceipt])
	if err != nil {
		return
	}
	r.Signature = sig
	_ = a.send("receipt", r)
}

// send serializes one protocol value and writes it through the active connection.
func (a *Agent) send(kind string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	frame, err := json.Marshal(protocol.Frame{Type: kind, Payload: payload})
	if err != nil {
		return err
	}
	a.connectionMu.RLock()
	conn := a.connection
	a.connectionMu.RUnlock()
	if conn == nil {
		return os.ErrNotExist
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	_ = conn.ws.SetWriteDeadline(time.Now().Add(transportWriteTimeout))
	err = conn.ws.WriteJSON(frame)
	if err != nil {
		_ = conn.ws.Close()
	}
	return err
}

// boundedDiagnostic keeps peripheral text within the signed wire contract and valid UTF-8.
func boundedDiagnostic(value string, maximum int) string {
	value = strings.ReplaceAll(strings.ToValidUTF8(value, "�"), "\x00", "�")
	if len(value) > maximum {
		value = strings.ToValidUTF8(value[:maximum], "")
	}
	return value
}
