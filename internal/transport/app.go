// File purpose: Implements the private authenticated WebSocket switching service.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package transport implements the independent, application-agnostic agent
// WebSocket switch. It deliberately owns no desired state or command history.
package transport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/netlimit"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/wire"
	"github.com/gorilla/websocket"
)

const (
	maxMessageBytes          = wire.MaxFrameBytes
	writeTimeout             = 15 * time.Second
	pongTimeout              = 45 * time.Second
	maxConcurrentAgentFrames = 16
	agentFrameAdmissionWait  = time.Second
	maxHandshakeMessageBytes = 2 << 10
	maxConcurrentHandshakes  = 16
	// Each display has one WireGuard address. Two pending connections allow a
	// reconnect to overlap its predecessor without letting one peer occupy
	// other displays' identities or the shared handshake decoders.
	maxPendingConnectionsPerSource = 2
	// Preserve live-agent and reconnect capacity while bounding sockets before
	// HTTP parsing. Loopback controller traffic shares only the total limit.
	maxAcceptedConnections          = 2*wire.MaxConnectedAgents + 32
	maxAcceptedConnectionsPerSource = 4
)

type routedFrame = wire.RoutedFrame

type service struct {
	queueBudget atomic.Int64
	agentFrames atomic.Int64
	frameInit   sync.Once
	frameSlots  chan struct{}
	helloFrames atomic.Int64
	helloInit   sync.Once
	helloSlots  chan struct{}
	closing     bool
	peers       map[*peer]struct{}
	handlers    sync.WaitGroup
	upgrader    websocket.Upgrader
	psk         []byte
	mu          sync.RWMutex
	controller  *peer
	agents      map[string]*peer
	pending     map[netip.Addr]int
	authNonces  *replay.Cache
}

// admitPendingSource bounds connections from one source address that the
// controller has not yet approved. Loopback peers run on the controller host.
func (s *service) admitPendingSource(source netip.Addr) bool {
	if source.IsLoopback() {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[source] >= maxPendingConnectionsPerSource {
		return false
	}
	if s.pending == nil {
		s.pending = make(map[netip.Addr]int)
	}
	s.pending[source]++
	return true
}

// releasePendingSource returns one pending slot after approval or disconnect.
func (s *service) releasePendingSource(source netip.Addr) {
	if source.IsLoopback() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[source] <= 1 {
		delete(s.pending, source)
		return
	}
	s.pending[source]--
}

// reserveAgent admits a bounded, unique live agent identity. Keeping this
// decision under one lock prevents a reconnect race from displacing an
// established end-to-end session.
func (s *service) reserveAgent(id string, candidate *peer) (*peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.agents[id] != nil || len(s.agents) >= wire.MaxConnectedAgents {
		return nil, false
	}
	s.agents[id] = candidate
	return s.controller, true
}

// Run loads configuration and serves until cancellation.
func Run(ctx context.Context, args []string, _ string) error {
	path := config.DefaultTransportPath
	flags := flag.NewFlagSet("neodse-transport", flag.ContinueOnError)
	flags.StringVar(&path, "config", path, "path to transport YAML configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("neodse-transport does not accept positional arguments")
	}
	cfg, err := config.LoadTransport(path)
	if err != nil {
		return fmt.Errorf("load transport configuration: %w", err)
	}
	if err := config.VerifyPlaintextLink(cfg.Transport.Listen, cfg.Transport.WireGuardInterface, true); err != nil {
		return err
	}
	psk, err := keyderivation.ParsePSK(cfg.Transport.ControllerPSK)
	if err != nil {
		return fmt.Errorf("controller credential: %w", err)
	}
	s := &service{psk: psk, agents: make(map[string]*peer), authNonces: replay.New(wire.MaxClockSkew, 8192), upgrader: websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin:      func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/controller", s.handleController)
	mux.HandleFunc("GET /v1/agents/{agentId}", s.handleAgent)
	httpServer := &http.Server{Addr: cfg.Transport.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	admission, err := netlimit.New(maxAcceptedConnections, maxAcceptedConnectionsPerSource)
	if err != nil {
		return fmt.Errorf("transport connection limits: %w", err)
	}
	listenerConfig := net.ListenConfig{Control: config.PlaintextSocketControl(cfg.Transport.WireGuardInterface)}
	listener, err := listenerConfig.Listen(ctx, "tcp4", cfg.Transport.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(admission.Wrap(listener)) }()
	watchContext, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	linkErr := make(chan error, 1)
	go func() {
		linkErr <- config.WatchPlaintextListener(watchContext, listener, cfg.Transport.WireGuardInterface)
	}()
	log.Printf("| NeoDSE transport serving on %s", cfg.Transport.Listen)
	select {
	case <-ctx.Done():
	case err = <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case err = <-linkErr:
	}
	s.stopPeers()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdown)
	return err
}

// handleController authenticates the sole controller and routes opaque agent envelopes.
func (s *service) handleController(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &peer{conn: c}
	p.start(&s.queueBudget, 1024, serviceQueueBytes)
	if !s.trackPeer(p) {
		p.close()
		return
	}
	defer s.releasePeer(p)
	s.mu.Lock()
	old := s.controller
	s.controller = p
	agents := make([]*peer, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	s.mu.Unlock()
	if old != nil {
		_ = old.conn.Close()
	}
	// Force a fresh end-to-end hello after controller replacement so no agent
	// remains attached to a session the new controller never authenticated.
	for _, agent := range agents {
		agent.stop()
	}
	defer func() {
		s.mu.Lock()
		var agents []*peer
		if s.controller == p {
			s.controller = nil
			agents = make([]*peer, 0, len(s.agents))
			for _, agent := range s.agents {
				agents = append(agents, agent)
			}
		}
		s.mu.Unlock()
		// An agent session is valid only while a controller owns the transport.
		// Closing peers forces a fresh end-to-end handshake after reconnection.
		for _, agent := range agents {
			agent.stop()
		}
		_ = c.Close()
	}()
	for {
		var frame routedFrame
		if err := c.ReadJSON(&frame); err != nil {
			return
		}
		if !s.routeControllerFrame(p, frame) {
			return
		}
	}
}

// routeControllerFrame binds work to both the controller and agent connection
// that accepted it. Queued work cannot migrate to a replacement connection.
func (s *service) routeControllerFrame(controller *peer, frame routedFrame) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.controller != controller {
		return false
	}
	agent := s.agents[frame.AgentID]
	if agent == nil || frame.ConnectionID == "" || frame.ConnectionID != agent.connectionID {
		return true
	}
	if frame.Type == "disconnect" {
		agent.reject(frame.Reason)
		return true
	}
	if frame.Type != "to_agent" || len(frame.Payload) == 0 {
		return true
	}
	if err := agent.writeJSON(frame.Payload); err != nil {
		agent.stop()
	} else {
		agent.approve()
	}
	return true
}

// handleAgent validates identity and routes opaque frames without interpreting application data.
func (s *service) handleAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("agentId")
	if !identity.ValidAgentID(id) {
		http.NotFound(w, r)
		return
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !remote.Addr().Unmap().Is4() {
		http.Error(w, "connection unavailable", http.StatusBadRequest)
		return
	}
	source := remote.Addr().Unmap()
	if !s.admitPendingSource(source) {
		http.Error(w, "too many pending connections", http.StatusTooManyRequests)
		return
	}
	releasePending := sync.OnceFunc(func() { s.releasePendingSource(source) })
	defer releasePending()
	var connectionID [16]byte
	if _, err := rand.Read(connectionID[:]); err != nil {
		http.Error(w, "connection unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &peer{conn: c, connectionID: hex.EncodeToString(connectionID[:])}
	p.start(&s.queueBudget, 32, peerQueueBytes)
	p.handshake = time.AfterFunc(10*time.Second, p.stop)
	if !s.trackPeer(p) {
		p.close()
		return
	}
	defer s.releasePeer(p)
	controller, admitted := s.reserveAgent(id, p)
	if !admitted {
		_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "agent connection unavailable"), time.Now().Add(writeTimeout))
		_ = c.Close()
		return
	}

	defer func() {
		s.mu.Lock()
		if s.agents[id] == p {
			if controller != nil && s.controller == controller {
				if err := controller.writeJSON(routedFrame{Type: "disconnected", AgentID: id, ConnectionID: p.connectionID}); err != nil {
					controller.stop()
				}
			}
			delete(s.agents, id)
		}
		s.mu.Unlock()
		_ = c.Close()
	}()
	if controller != nil {
		// The controller compares the source with the agent's enrolled tunnel
		// address before any message from this connection is accepted.
		if err := controller.writeJSON(routedFrame{Type: "connected", AgentID: id, ConnectionID: p.connectionID, RemoteAddress: source.String()}); err != nil {
			controller.stop()
			return
		}
	}
	route := func(payload []byte) bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if controller == nil || s.controller != controller {
			return false
		}
		return controller.writeJSON(routedFrame{Type: "from_agent", AgentID: id, ConnectionID: p.connectionID, Payload: payload}) == nil
	}
	// Unapproved peers get one small message and a separate decoder budget.
	// Do not enter the active pool until the trusted controller replies: a
	// pipelined second frame must not reserve active capacity before approval.
	c.SetReadLimit(maxHandshakeMessageBytes)
	if !s.readHandshakeFrame(c, route) {
		return
	}
	select {
	case <-p.approved:
		releasePending()
	case <-p.done:
		return
	}
	c.SetReadLimit(maxMessageBytes)
	for {
		if !s.readAgentFrame(c, route) {
			return
		}
	}
}

// readHandshakeFrame bounds the first opaque message independently of active
// traffic, consuming its entire frame before allowing controller approval.
func (s *service) readHandshakeFrame(c *websocket.Conn, route func([]byte) bool) bool {
	_, reader, err := c.NextReader()
	if err != nil {
		return false
	}
	s.helloInit.Do(func() { s.helloSlots = make(chan struct{}, maxConcurrentHandshakes) })
	timer := time.NewTimer(agentFrameAdmissionWait)
	defer timer.Stop()
	if !waitForFrameCapacity(s.helloSlots, timer.C) {
		return false
	}
	s.helloFrames.Add(1)
	defer func() {
		s.helloFrames.Add(-1)
		<-s.helloSlots
	}()
	encoded, err := io.ReadAll(io.LimitReader(reader, maxHandshakeMessageBytes+1))
	if err != nil || len(encoded) > maxHandshakeMessageBytes {
		return false
	}
	var payload []byte
	if json.Unmarshal(encoded, &payload) != nil {
		return false
	}
	return route(payload)
}

// readAgentFrame bounds allocations before decoding untrusted agent JSON and
// retains the reservation through routing and queue admission. Idle connections
// wait in NextReader without consuming capacity. The authenticated controller
// has its own reader so agent saturation cannot prevent session rejections.
func (s *service) readAgentFrame(c *websocket.Conn, route func([]byte) bool) bool {
	_, reader, err := c.NextReader()
	if err != nil {
		return false
	}
	s.frameInit.Do(func() { s.frameSlots = make(chan struct{}, maxConcurrentAgentFrames) })
	select {
	case s.frameSlots <- struct{}{}:
	default:
		// Backpressure a complete-frame burst while busy readers finish their
		// decoding and routing. Waiting allocates no decoded payload, and the
		// existing agent limit bounds waiting readers. The one-second budget
		// tolerates short CPU contention while still rejecting sustained
		// saturation without raising the simultaneous receive allocation bound.
		timer := time.NewTimer(agentFrameAdmissionWait)
		defer timer.Stop()
		if !waitForFrameCapacity(s.frameSlots, timer.C) {
			log.Print("! Transport agent frame rejected: receive capacity exhausted")
			return false
		}
	}
	s.agentFrames.Add(1)
	defer func() {
		s.agentFrames.Add(-1)
		<-s.frameSlots
	}()
	var payload []byte
	if err := json.NewDecoder(reader).Decode(&payload); err != nil {
		return false
	}
	return route(payload)
}

// waitForFrameCapacity prefers available capacity when both cases become ready
// during a scheduler pause. Expiry never starts another wait or raises the bound.
func waitForFrameCapacity(slots chan struct{}, expired <-chan time.Time) bool {
	select {
	case slots <- struct{}{}:
		return true
	case <-expired:
		select {
		case slots <- struct{}{}:
			return true
		default:
			return false
		}
	}
}

// authorized verifies controller freshness, nonce replay, and purpose-bound authentication.
func (s *service) authorized(r *http.Request) bool {
	return s.authorizedAt(r, time.Now())
}

// authorizedAt checks a controller request against one consistent clock snapshot.
func (s *service) authorizedAt(r *http.Request, now time.Time) bool {
	if len(s.psk) != keyderivation.PSKBytes {
		return false
	}
	value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "NeoDSE ")
	if !ok {
		return false
	}
	separator := strings.LastIndexByte(value, ':')
	if separator < 1 {
		return false
	}
	timestamp, signature := value[:separator], value[separator+1:]
	nonce := r.Header.Get("X-NeoDSE-Nonce")
	if len(nonce) != 64 {
		return false
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return false
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || !replay.Fresh(ts, now, wire.MaxClockSkew) {
		return false
	}
	mac := hmac.New(sha256.New, s.psk)
	_, _ = mac.Write([]byte("neodse/transport/v1\x00" + timestamp + "\x00" + nonce))
	want, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(want, mac.Sum(nil)) {
		return false
	}
	return s.authNonces != nil && s.authNonces.Accept(nonce, ts, now) == nil
}

// trackPeer atomically registers ownership or rejects a shutdown race.
func (s *service) trackPeer(p *peer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	if s.peers == nil {
		s.peers = make(map[*peer]struct{})
	}
	s.peers[p] = struct{}{}
	s.handlers.Add(1)
	return true
}

// releasePeer waits for workers before removing the handler from shutdown accounting.
func (s *service) releasePeer(p *peer) {
	p.close()
	s.mu.Lock()
	delete(s.peers, p)
	s.mu.Unlock()
	s.handlers.Done()
}

// stopPeers closes upgraded sockets explicitly before joining all handlers.
func (s *service) stopPeers() {
	s.mu.Lock()
	s.closing = true
	for p := range s.peers {
		p.stop()
	}
	s.mu.Unlock()
	s.handlers.Wait()
}
