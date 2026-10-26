// File purpose: Streams read-only JPEG frames from Weston's local VNC backend.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

const (
	displayVNCAddress = "127.0.0.1:5900"
	displayChunkBytes = wire.MaxDisplayChunkBytes
)

// handleDisplay dispatches one authenticated display-control frame from the controller.
func (a *Agent) handleDisplay(message protocol.Display) error {
	if !a.verifyDisplay(message) {
		return errors.New("display relay authentication failed")
	}
	switch message.Action {
	case "prepare":
		_, err := a.prepareVNCCredential(message.StreamID)
		if err != nil {
			return a.sendDisplay(message.StreamID, "error", nil, "could not prepare VNC authentication")
		}
		return a.sendDisplay(message.StreamID, "ready", nil, "")
	case "open":
		return a.openDisplayStream(message.StreamID)
	case "close":
		a.closeDisplayStream(message.StreamID)
		return nil
	default:
		return errors.New("invalid display relay action")
	}
}

// verifyDisplay authenticates and advances the shared inbound transport sequence.
func (a *Agent) verifyDisplay(message protocol.Display) bool {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if message.Protocol != protocol.Version || message.AgentID != a.config.Agent.ID || a.sessionID == "" ||
		message.SessionID != a.sessionID || message.Sequence != a.lastInboundSequence+1 || len(message.StreamID) != 32 ||
		len(message.Data) != 0 || message.Error != "" ||
		(message.Action != "prepare" && message.Action != "open" && message.Action != "close") {
		return false
	}
	expected, err := protocol.SignDisplay(message, a.sessionKeys[keyderivation.TransportDisplay])
	if err != nil || !protocol.Verify(message.Signature, expected) {
		return false
	}
	timestamp, err := time.Parse(time.RFC3339Nano, message.Timestamp)
	if err != nil || !replay.Fresh(timestamp, time.Now().UTC(), wire.MaxClockSkew) {
		return false
	}
	a.lastInboundSequence = message.Sequence
	return true
}

// openDisplayStream connects the prepared stream to Weston's loopback VNC listener.
func (a *Agent) openDisplayStream(streamID string) error {
	credential, ok := a.vncCredentialForStream(streamID)
	if !ok {
		return a.sendDisplay(streamID, "error", nil, "VNC authentication credential expired")
	}
	configuration, err := loadVNCTLSConfig(vncCertificatePath)
	if err != nil {
		a.infof("! VNC TLS trust unavailable: %v", err)
		return a.sendDisplay(streamID, "error", nil, "local VNC TLS trust is unavailable")
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).Dial("tcp4", displayVNCAddress)
	if err != nil {
		return a.sendDisplay(streamID, "error", nil, "local VNC service is unavailable")
	}
	a.displayMu.Lock()
	if a.displayStreams == nil {
		a.displayStreams = make(map[string]net.Conn)
	}
	if len(a.displayStreams) != 0 {
		a.displayMu.Unlock()
		_ = connection.Close()
		return a.sendDisplay(streamID, "error", nil, "another display viewer is active")
	}
	a.displayStreams[streamID] = connection
	a.displayMu.Unlock()
	a.workers.Go(func() { a.captureDisplayStream(streamID, connection, credential, configuration) })
	return nil
}

// captureDisplayStream authenticates RFB and forwards bounded JPEG frames until closure.
func (a *Agent) captureDisplayStream(streamID string, connection net.Conn, credential string, configuration *tls.Config) {
	viewer := newRFBViewer(connection, credential, configuration)
	if err := viewer.initialize(); err != nil {
		a.infof("! Read-only display initialization failed: %v", err)
		a.removeDisplayStream(streamID, connection)
		_ = a.sendDisplay(streamID, "error", nil, boundedDiagnostic(err.Error(), 120))
		return
	}
	a.infof("| Read-only display connected at %dx%d", viewer.width, viewer.height)
	if err := a.sendDisplay(streamID, "open", nil, ""); err != nil {
		a.removeDisplayStream(streamID, connection)
		return
	}
	for {
		frame, err := viewer.nextJPEG()
		if err == nil {
			err = a.sendDisplay(streamID, "data", frame, "")
		}
		if err != nil {
			a.infof("! Read-only display capture closed: %v", err)
			a.removeDisplayStream(streamID, connection)
			if errors.Is(err, net.ErrClosed) {
				_ = a.sendDisplay(streamID, "close", nil, "")
			} else {
				_ = a.sendDisplay(streamID, "error", nil, "local VNC capture closed")
			}
			return
		}
	}
}

// sendDisplay signs and sends one display frame in the agent session sequence.
func (a *Agent) sendDisplay(streamID, action string, data []byte, publicError string) error {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if a.sessionID == "" {
		return net.ErrClosed
	}
	a.nextOutboundSequence++
	message := protocol.Display{Protocol: protocol.Version, SessionID: a.sessionID, Sequence: a.nextOutboundSequence,
		AgentID: a.config.Agent.ID, StreamID: streamID, Action: action, Data: data, Error: publicError,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	var err error
	message.Signature, err = protocol.SignDisplay(message, a.sessionKeys[keyderivation.TransportDisplay])
	if err != nil {
		return fmt.Errorf("sign display relay: %w", err)
	}
	return a.send("display", message)
}

// closeDisplayStream revokes credentials and closes the named active stream.
func (a *Agent) closeDisplayStream(streamID string) {
	a.revokeVNCCredentials(streamID)
	a.displayMu.Lock()
	connection := a.displayStreams[streamID]
	delete(a.displayStreams, streamID)
	a.displayMu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

// removeDisplayStream removes a stream only when it still owns the expected connection.
func (a *Agent) removeDisplayStream(streamID string, expected net.Conn) {
	a.revokeVNCCredentials(streamID)
	a.displayMu.Lock()
	if a.displayStreams[streamID] == expected {
		delete(a.displayStreams, streamID)
	}
	a.displayMu.Unlock()
	_ = expected.Close()
}

// closeDisplayStreams revokes and closes every stream during session teardown.
func (a *Agent) closeDisplayStreams() {
	a.displayMu.Lock()
	streams := a.displayStreams
	a.displayStreams = nil
	a.displayMu.Unlock()
	a.vncAuthMu.Lock()
	clear(a.vncCredentials)
	a.vncAuthMu.Unlock()
	for _, connection := range streams {
		_ = connection.Close()
	}
}
