// File purpose: Exposes authenticated, request-owned read-only dashboard image streams.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image/jpeg"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

const (
	displayChunkBytes            = wire.MaxDisplayChunkBytes
	displayAuthorizationInterval = 5 * time.Second
)

type displayRelay struct {
	tokenID     string
	tokenDigest [sha256.Size]byte
	agentID     string
	streamID    string
	session     *agentSession
	control     chan protocol.Display
	frames      chan []byte
	done        chan struct{}
	once        sync.Once
}

// newDisplayRelay allocates the control queue and the single pending frame slot.
func newDisplayRelay(agentID, streamID string, session *agentSession) *displayRelay {
	return &displayRelay{agentID: agentID, streamID: streamID, session: session,
		control: make(chan protocol.Display, 2), frames: make(chan []byte, 1), done: make(chan struct{})}
}

// close marks a relay closed exactly once for all concurrent participants.
func (relay *displayRelay) close() { relay.once.Do(func() { close(relay.done) }) }

// offerFrame keeps only the newest image the viewer has not written yet, so a
// viewer on a slower link skips intermediate frames instead of losing the
// stream. One ordered per-agent worker is the only producer for a relay.
func (relay *displayRelay) offerFrame(frame []byte) {
	for range 2 {
		select {
		case relay.frames <- frame:
			return
		default:
		}
		select {
		case <-relay.frames:
		default:
		}
	}
}

// displayStreamRoute owns capture and cleanup for one authenticated HTTP stream.
func (s *Server) displayStreamRoute(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		writeAPIError(w, http.StatusBadRequest, "display stream does not accept a request body")
		return
	}
	agentID := r.PathValue("agentId")
	agentSession := s.sessionFor(agentID)
	if agentSession == nil {
		writeAPIError(w, http.StatusConflict, "agent is offline")
		return
	}
	streamBytes := make([]byte, 16)
	if _, err := rand.Read(streamBytes); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not create display stream")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, "_")
	if len(parts) != 3 {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	relay := newDisplayRelay(agentID, hex.EncodeToString(streamBytes), agentSession)
	relay.tokenID, relay.tokenDigest = parts[1], sha256.Sum256([]byte(token))
	if !s.installDisplayRelay(relay) {
		writeAPIError(w, http.StatusConflict, "another display viewer is active")
		return
	}
	defer s.removeDisplayRelay(relay)
	for _, step := range []struct {
		action, reply string
		timeout       time.Duration
	}{{"prepare", "ready", 15 * time.Second}, {"open", "open", 15 * time.Second}} {
		if err := s.sendDisplayFrame(relay, step.action, nil); err != nil {
			writeAPIError(w, http.StatusConflict, "agent display session changed")
			return
		}
		timer := time.NewTimer(step.timeout)
		select {
		case message := <-relay.control:
			timer.Stop()
			if message.Action != step.reply {
				writeAPIError(w, http.StatusServiceUnavailable, "agent could not start read-only display capture")
				return
			}
		case <-relay.done:
			timer.Stop()
			writeAPIError(w, http.StatusServiceUnavailable, "agent display relay closed")
			return
		case <-timer.C:
			writeAPIError(w, http.StatusGatewayTimeout, "display capture startup timed out")
			return
		case <-r.Context().Done():
			timer.Stop()
			return
		}
	}
	if !s.displayAuthorized(r.Context(), relay) || s.sessionFor(agentID) != relay.session {
		writeAPIError(w, http.StatusForbidden, "display access revoked")
		return
	}
	response := http.NewResponseController(w)
	// Idle desktops may stay silent beyond the HTTP server's ordinary write timeout.
	if err := response.SetWriteDeadline(time.Time{}); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "display streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := response.Flush(); err != nil {
		return
	}
	authorizationTicker := time.NewTicker(displayAuthorizationInterval)
	defer authorizationTicker.Stop()
	for {
		select {
		case frame := <-relay.frames:
			size := len(frame)
			if size == 0 || size > displayChunkBytes {
				return
			}
			if err := response.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return
			}
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(size))
			if _, err := w.Write(length[:]); err != nil {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			if err := response.Flush(); err != nil {
				return
			}
			if err := response.SetWriteDeadline(time.Time{}); err != nil {
				return
			}
		case <-relay.control:
			// Capture closed or failed on the agent after the stream started.
			return
		case <-authorizationTicker.C:
			if s.sessionFor(relay.agentID) != relay.session || !s.displayAuthorized(r.Context(), relay) {
				return
			}
		case <-relay.done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// installDisplayRelay reserves the single viewer slot for an agent.
func (s *Server) installDisplayRelay(relay *displayRelay) bool {
	s.displayMu.Lock()
	defer s.displayMu.Unlock()
	for _, current := range s.displayRelays {
		if current.agentID == relay.agentID {
			return false
		}
	}
	s.displayRelays[relay.streamID] = relay
	return true
}

// removeDisplayRelay closes a relay and asks its agent to release local resources.
func (s *Server) removeDisplayRelay(relay *displayRelay) {
	relay.close()
	// Order local close before admitting a replacement capture on the agent channel.
	_ = s.sendDisplayFrame(relay, "close", nil)
	s.displayMu.Lock()
	if s.displayRelays[relay.streamID] == relay {
		delete(s.displayRelays, relay.streamID)
	}
	s.displayMu.Unlock()
}

// closeDisplayRelays closes every relay associated with an agent or all agents.
func (s *Server) closeDisplayRelays(agentID string) {
	s.displayMu.Lock()
	for streamID, relay := range s.displayRelays {
		if agentID == "" || relay.agentID == agentID {
			delete(s.displayRelays, streamID)
			relay.close()
		}
	}
	s.displayMu.Unlock()
}

// sendDisplayFrame signs one server-to-agent display control message.
func (s *Server) sendDisplayFrame(relay *displayRelay, action string, data []byte) error {
	session := s.sessionFor(relay.agentID)
	if session == nil || session != relay.session {
		return errors.New("agent session changed")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	s.mu.RLock()
	active := s.sessions[relay.agentID] == session
	s.mu.RUnlock()
	if !active || (s.link != nil && !s.link.currentRoute(relay.agentID, session.connectionID)) {
		return errors.New("agent session changed")
	}
	session.nextSend++
	message := protocol.Display{Protocol: protocol.Version, SessionID: session.id, Sequence: session.nextSend, AgentID: relay.agentID,
		StreamID: relay.streamID, Action: action, Data: data, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	var err error
	message.Signature, err = protocol.SignDisplay(message, session.keys[keyderivation.TransportDisplay])
	if err != nil {
		return err
	}
	return s.sendFrame(relay.agentID, session.connectionID, "display", message)
}

// handleDisplayFrame authenticates and dispatches one agent-to-browser display frame.
func (s *Server) handleDisplayFrame(agentID string, payload []byte) error {
	var message protocol.Display
	if protocol.Decode(payload, &message) != nil {
		return errors.New("malformed display message")
	}
	if message.Protocol != protocol.Version || message.AgentID != agentID ||
		len(message.StreamID) != 32 || len(message.Data) > displayChunkBytes || len(message.Error) > 256 {
		return errors.New("invalid display identity or field bounds")
	}
	if message.Action != "open" && message.Action != "data" && message.Action != "close" && message.Action != "error" && message.Action != "ready" {
		return errors.New("unsupported display action")
	}
	if (message.Action == "data") != (len(message.Data) > 0) || (message.Action != "error" && message.Error != "") {
		return errors.New("invalid display payload fields")
	}
	session := s.sessionFor(agentID)
	if session == nil {
		return errors.New("agent session unavailable")
	}
	session.receiveMu.Lock()
	defer session.receiveMu.Unlock()
	session.mu.Lock()
	if message.SessionID != session.id {
		session.mu.Unlock()
		return errors.New("display session changed")
	}
	if message.Sequence != session.lastReceived+1 {
		expected := session.lastReceived + 1
		session.mu.Unlock()
		return fmt.Errorf("nonconsecutive display sequence: received=%d expected=%d", message.Sequence, expected)
	}
	expected, err := protocol.SignDisplay(message, session.keys[keyderivation.TransportDisplay])
	if err != nil || !protocol.Verify(message.Signature, expected) {
		session.mu.Unlock()
		return errors.New("display authentication failed")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, message.Timestamp)
	if err != nil {
		session.mu.Unlock()
		return errors.New("invalid display timestamp")
	}
	if !replay.Fresh(timestamp, time.Now().UTC(), wire.MaxClockSkew) {
		session.mu.Unlock()
		return errors.New("stale display timestamp")
	}
	if message.Action == "data" {
		// Inspect only the JPEG header before the browser can allocate its decoded image.
		geometry, err := jpeg.DecodeConfig(bytes.NewReader(message.Data))
		if err != nil || geometry.Width <= 0 || geometry.Height <= 0 || int64(geometry.Width)*int64(geometry.Height) > wire.MaxDisplayPixels {
			session.mu.Unlock()
			return errors.New("invalid JPEG header or dimensions")
		}
	}
	session.lastReceived = message.Sequence
	session.mu.Unlock()
	s.displayMu.Lock()
	relay := s.displayRelays[message.StreamID]
	s.displayMu.Unlock()
	if relay == nil || relay.agentID != agentID {
		return nil
	}
	if message.Action == "data" {
		relay.offerFrame(message.Data)
		return nil
	}
	select {
	case relay.control <- message:
	default:
		relay.close()
	}
	return nil
}

// displayAuthorized fails closed when the originating token, scope, or account loses authority.
func (s *Server) displayAuthorized(ctx context.Context, relay *displayRelay) bool {
	ctx, cancel := context.WithTimeout(ctx, storeOperationTimeout)
	defer cancel()
	authentication, err := s.store.AuthenticateAccountDigest(ctx, relay.tokenID, relay.tokenDigest, time.Now().UTC())
	if err != nil {
		return false
	}
	if authentication.AllAgents {
		return true
	}
	return slices.Contains(authentication.Agents, relay.agentID)
}
