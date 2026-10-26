// File purpose: Maintains controller transport connectivity and authenticated per-agent sessions.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/wire"
	"github.com/gorilla/websocket"
)

type routedFrame = wire.RoutedFrame
type controllerLink struct {
	s        *Server
	url, psk string
	mu       sync.RWMutex
	conn     *websocket.Conn
	routes   map[string]string
	writeMu  sync.Mutex
	received atomic.Uint64
}

const (
	controllerMaxMessageBytes = wire.MaxFrameBytes
	controllerRetryMax        = time.Minute
	controllerDialTimeout     = 10 * time.Second
	controllerPongTimeout     = 45 * time.Second
	stableTransportSession    = time.Minute
	// A reconnecting agent may retain at most this many fresh hello nonces.
	// Entries live until their timestamps leave the two-minute skew window;
	// future timestamps can therefore retain capacity for four minutes.
	helloReplayPerAgent = 128
)

// newControllerLink constructs the controller's single reconnecting transport client.
func newControllerLink(s *Server, u, p string) *controllerLink {
	return &controllerLink{s: s, url: u, psk: p}
}

// Run reconnects with bounded backoff until the controller context is cancelled.
func (l *controllerLink) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		received := l.received.Load()
		if err := l.session(ctx); err != nil && ctx.Err() == nil {
			log.Printf("! Transport connection: %v", err)
		}
		backoff = resetControllerBackoff(backoff, time.Since(started), l.received.Load() != received)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < controllerRetryMax {
			backoff *= 2
			if backoff > controllerRetryMax {
				backoff = controllerRetryMax
			}
		}
	}
}

// resetControllerBackoff restores prompt retries after useful routed traffic or
// a stable connection; failed attempts without progress retain bounded backoff.
func resetControllerBackoff(current, sessionDuration time.Duration, progressed bool) time.Duration {
	if progressed || sessionDuration >= stableTransportSession {
		return time.Second
	}
	return current
}

// newControllerDialer constructs the IPv4-only, proxy-independent transport dialer.
func newControllerDialer(device string) websocket.Dialer {
	return websocket.Dialer{
		Proxy:            nil,
		HandshakeTimeout: controllerDialTimeout,
		NetDialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: controllerDialTimeout, KeepAlive: 30 * time.Second, Control: config.PlaintextSocketControl(device)}).DialContext(ctx, "tcp4", address)
		},
	}
}

// session authenticates one transport WebSocket and routes frames until it closes.
func (l *controllerLink) session(ctx context.Context) error {
	key, err := keyderivation.ParsePSK(l.psk)
	if err != nil {
		return fmt.Errorf("transport credential: %w", err)
	}
	u, err := url.Parse(l.url)
	if err != nil {
		return err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/controller"
	ts := time.Now().UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, key)
	nonceBytes := make([]byte, 32)
	if _, err = rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	_, _ = mac.Write([]byte("neodse/transport/v1\x00" + ts + "\x00" + nonce))
	header := http.Header{"Authorization": []string{"NeoDSE " + ts + ":" + hex.EncodeToString(mac.Sum(nil))}}
	header.Set("X-NeoDSE-Nonce", nonce)
	dialer := newControllerDialer(l.s.config.Server.WireGuardInterface)
	ws, _, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return err
	}
	defer ws.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stopClose()
	_ = ws.SetReadDeadline(time.Now().Add(controllerPongTimeout))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(controllerPongTimeout)) })
	ws.SetPingHandler(func(data string) error {
		_ = ws.SetReadDeadline(time.Now().Add(controllerPongTimeout))
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	ws.SetReadLimit(controllerMaxMessageBytes)
	l.mu.Lock()
	l.conn = ws
	l.routes = make(map[string]string)
	l.mu.Unlock()
	l.s.clearSessions()
	log.Printf("| Transport connected")
	defer func() {
		l.mu.Lock()
		owned := l.conn == ws
		if owned {
			l.conn = nil
		}
		l.mu.Unlock()
		if owned {
			l.s.clearSessions()
		}
	}()
	workCtx, cancel := context.WithCancel(ctx)
	var group sync.WaitGroup
	var queuedBytes atomic.Int64
	agentWorkers := newAgentFrameWorkers(workCtx, l, &group, &queuedBytes)
	defer func() {
		cancel()
		agentWorkers.stop()
		_ = ws.Close()
		l.mu.Lock()
		if l.conn == ws {
			l.conn = nil
		}
		l.mu.Unlock()
		l.s.clearSessions()
		group.Wait()
		l.s.clearSessions()
	}()
	for {
		var f routedFrame
		if err := ws.ReadJSON(&f); err != nil {
			return err
		}
		accepted, err := l.acceptRoute(f)
		if err != nil {
			return err
		}
		agentWorkers.lifecycle(f)
		if !accepted {
			agentWorkers.reap()
			continue
		}
		l.received.Add(1)
		if err := agentWorkers.enqueue(f); err != nil {
			// Both active and draining workers consume bounded capacity. A new
			// or saturated route cannot force healthy displays to reconnect.
			l.forgetRoute(f.AgentID, f.ConnectionID)
			agentWorkers.retire(f.AgentID, f.ConnectionID)
			if err := l.disconnect(f.AgentID, f.ConnectionID, err.Error()); err != nil {
				return err
			}
		}
	}
}

// send writes one agent envelope under exclusive connection ownership.
func (l *controllerLink) send(agentID, connectionID string, frame protocol.Frame) error {
	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	l.mu.RLock()
	c := l.conn
	current := connectionID != "" && l.routes[agentID] == connectionID
	l.mu.RUnlock()
	if c == nil || !current {
		return context.DeadlineExceeded
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.WriteJSON(routedFrame{Type: "to_agent", AgentID: agentID, ConnectionID: connectionID, Payload: payload})
}

// disconnect asks the transport to terminate one compromised or inconsistent agent session.
func (l *controllerLink) disconnect(agentID, connectionID, reason string) error {
	l.mu.RLock()
	connection := l.conn
	l.mu.RUnlock()
	if connection == nil {
		return context.DeadlineExceeded
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_ = connection.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return connection.WriteJSON(routedFrame{Type: "disconnect", AgentID: agentID, ConnectionID: connectionID, Reason: reason})
}

// connected reports whether the controller currently owns a transport WebSocket.
func (l *controllerLink) connected() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.conn != nil
}

// handleAgentFrame authenticates handshake traffic and dispatches bounded typed inbound frames.
func (s *Server) handleAgentFrame(agentID, connectionID string, raw []byte) {
	var f protocol.Frame
	if err := protocol.Decode(raw, &f); err != nil {
		s.rejectAgentFrame(agentID, connectionID, "malformed protocol frame")
		return
	}
	switch f.Type {
	case "hello":
		storeContext, cancel := boundedStoreContext()
		defer cancel()
		pskValue, ok := s.agentPSKValue(storeContext, agentID)
		if !ok {
			s.rejectAgentFrame(agentID, connectionID, "agent is not provisioned in the authority database")
			return
		}
		psk, err := keyderivation.ParsePSK(pskValue)
		if err != nil {
			s.rejectAgentFrame(agentID, connectionID, "stored agent credential is invalid")
			return
		}
		key, err := keyderivation.Derive(psk, agentID, keyderivation.TransportHandshake)
		if err != nil {
			s.rejectAgentFrame(agentID, connectionID, "could not derive handshake authority")
			return
		}
		if err := s.handleHello(agentID, connectionID, f.Payload, psk, key); err != nil {
			s.rejectAgentFrame(agentID, connectionID, err.Error())
		}
	case "status":
		if !s.handleStatus(agentID, f.Payload) {
			s.rejectAgentFrame(agentID, connectionID, "invalid authenticated status")
		}
	case "receipt":
		if err := s.handleReceipt(agentID, f.Payload); err != nil {
			s.rejectAgentFrame(agentID, connectionID, "invalid authenticated receipt: "+err.Error())
		}
	case "display":
		if err := s.handleDisplayFrame(agentID, f.Payload); err != nil {
			s.rejectAgentFrame(agentID, connectionID, "invalid authenticated display relay frame: "+err.Error())
		}
	default:
		s.rejectAgentFrame(agentID, connectionID, "unsupported protocol frame type")
	}
}

// handleHello authenticates a fresh handshake and installs its purpose-separated session keys.
func (s *Server) handleHello(agentID, connectionID string, payload, psk, handshakeKey []byte) error {
	s.mu.RLock()
	installed := s.sessions[agentID] != nil
	s.mu.RUnlock()
	if installed {
		return errors.New("hello cannot replace an active session")
	}
	var hello protocol.Hello
	if err := protocol.Decode(payload, &hello); err != nil {
		return errors.New("malformed hello message")
	}
	if hello.Protocol != protocol.Version {
		return fmt.Errorf("unsupported agent protocol version %d", hello.Protocol)
	}
	if hello.AgentID != agentID || len(hello.Version) == 0 || len(hello.Version) > 128 || !validHexBytes(hello.ClientNonce, 32) {
		return errors.New("invalid hello identity or fields")
	}
	expected, err := protocol.SignHello(hello, handshakeKey)
	timestamp, timestampErr := time.Parse(time.RFC3339Nano, hello.Timestamp)
	if err != nil || timestampErr != nil {
		return errors.New("invalid hello timestamp or signature encoding")
	}
	if !protocol.Verify(hello.Signature, expected) {
		return errors.New("hello authentication failed; agent and controller enrollment credentials do not match")
	}
	if err := s.helloReplay.AcceptScoped(agentID, hello.ClientNonce, timestamp, time.Now().UTC(), helloReplayPerAgent); err != nil {
		return fmt.Errorf("hello freshness or replay check failed: %w", err)
	}
	serverNonceBytes := make([]byte, 32)
	sessionIDBytes := make([]byte, 16)
	if _, err = rand.Read(serverNonceBytes); err != nil {
		return fmt.Errorf("generate server nonce: %w", err)
	}
	if _, err = rand.Read(sessionIDBytes); err != nil {
		return fmt.Errorf("generate session ID: %w", err)
	}
	serverNonce := hex.EncodeToString(serverNonceBytes)
	sessionID := hex.EncodeToString(sessionIDBytes)
	keys, err := keyderivation.DeriveSessionKeys(psk, agentID, hello.ClientNonce, serverNonce)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}
	session := &agentSession{id: sessionID, connectionID: connectionID, credential: sha256.Sum256(psk), keys: keys}
	welcome := protocol.Welcome{Protocol: protocol.Version, AgentID: agentID, ClientNonce: hello.ClientNonce, ServerNonce: serverNonce, SessionID: sessionID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	welcome.Signature, err = protocol.SignWelcome(welcome, handshakeKey)
	if err != nil {
		s.clearSession(agentID, session)
		return fmt.Errorf("sign welcome message: %w", err)
	}
	if err := s.sendFrame(agentID, connectionID, "welcome", welcome); err != nil {
		s.clearSession(agentID, session)
		return fmt.Errorf("deliver welcome message: %w", err)
	}
	s.mu.Lock()
	if s.link != nil && !s.link.currentRoute(agentID, connectionID) {
		s.mu.Unlock()
		return errors.New("transport connection changed during handshake")
	}
	s.sessions[agentID] = session
	s.mu.Unlock()
	if err := s.sendDesiredState(agentID); err != nil {
		s.clearSession(agentID, session)
		return fmt.Errorf("reconcile authoritative state: %w", err)
	}
	s.rejectPendingDeliveries(agentID)
	return nil
}

// rejectAgentFrame logs a non-secret cause, removes authority, and closes the agent connection.
func (s *Server) rejectAgentFrame(agentID, connectionID, reason string) {
	log.Printf("! Agent session rejected agent=%s reason=%s", agentID, reason)
	s.clearRouteSession(agentID, connectionID)
	if s.link != nil {
		_ = s.link.disconnect(agentID, connectionID, "controller rejected agent session")
	}
}

// sendFrame serializes one typed value into an opaque transport frame.
func (s *Server) sendFrame(agentID, connectionID, kind string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	frame := protocol.Frame{Type: kind, Payload: b}
	if s.sendOverride != nil {
		return s.sendOverride(agentID, frame)
	}
	return s.link.send(agentID, connectionID, frame)
}

// agentConnected removes stale authority before a transport connection performs a fresh handshake.
func (s *Server) agentConnected(id string) {
	s.closeDisplayRelays(id)
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// clearSessions revokes all agent authority when the controller transport link changes.
func (s *Server) clearSessions() {
	s.closeDisplayRelays("")
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
}

// clearSession removes a session only when it is still the caller's expected instance.
func (s *Server) clearSession(agentID string, expected *agentSession) {
	s.mu.Lock()
	removed := false
	if s.sessions[agentID] == expected {
		delete(s.sessions, agentID)
		removed = true
	}
	s.mu.Unlock()
	if removed {
		s.closeDisplayRelays(agentID)
	}
}

// resetAgentConnection clears local authority and requests remote disconnection.
func (s *Server) resetAgentConnection(agentID string, expected *agentSession) {
	s.clearSession(agentID, expected)
	if s.link != nil {
		_ = s.link.disconnect(agentID, expected.connectionID, "controller reset agent session")
	}
}

// sessionFor accepts only a session whose handshake credential remains current.
func (s *Server) sessionFor(agentID string) *agentSession {
	ctx, cancel := boundedStoreContext()
	defer cancel()
	return s.authenticatedSession(ctx, agentID)
}

// authenticatedSession revalidates persistent credentials before returning a live session.
func (s *Server) authenticatedSession(ctx context.Context, agentID string) *agentSession {
	s.mu.RLock()
	session := s.sessions[agentID]
	s.mu.RUnlock()
	if session == nil || (s.link != nil && !s.link.currentRoute(agentID, session.connectionID)) {
		return nil
	}
	if s.store == nil {
		s.clearSession(agentID, session)
		return nil
	}
	current, lookupErr := s.store.AgentPSK(ctx, agentID)
	// A cancelled caller cannot establish authority, but its request lifetime
	// must not revoke an unrelated agent connection or another viewer's relay.
	// The next call still checks SQLite before using the retained session.
	if errors.Is(lookupErr, context.Canceled) || errors.Is(lookupErr, context.DeadlineExceeded) {
		return nil
	}
	key, err := keyderivation.ParsePSK(current)
	if lookupErr != nil || err != nil || sha256.Sum256(key) != session.credential {
		s.clearSession(agentID, session)
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sessions[agentID] != session {
		return nil
	}
	return session
}

// processAgentFrames preserves per-agent order without blocking unrelated peers.
func (l *controllerLink) processAgentFrames(ctx context.Context, queue <-chan routedFrame, budget *atomic.Int64) {
	defer func() {
		for {
			select {
			case frame, ok := <-queue:
				if !ok {
					return
				}
				budget.Add(-int64(len(frame.Payload)))
			default:
				return
			}
		}
	}()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-queue:
			if !ok {
				return
			}
			l.processAgentFrame(f, budget)
		}
	}
}

// processAgentFrame retains the inbound byte reservation while decoding or
// waiting on storage, so active handlers share the same bound as queued frames.
func (l *controllerLink) processAgentFrame(frame routedFrame, budget *atomic.Int64) {
	defer budget.Add(-int64(len(frame.Payload)))
	if !l.currentRoute(frame.AgentID, frame.ConnectionID) {
		return
	}
	if frame.Type == "connected" {
		if reason := l.s.connectionSourceRejection(frame.AgentID, frame.RemoteAddress); reason != "" {
			// Forgetting the route drops anything this connection already sent.
			l.forgetRoute(frame.AgentID, frame.ConnectionID)
			l.s.rejectAgentFrame(frame.AgentID, frame.ConnectionID, reason)
		}
		return
	}
	l.s.handleAgentFrame(frame.AgentID, frame.ConnectionID, frame.Payload)
}
