// File purpose: Binds routing and session authority to an individual transport connection.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"errors"
	"net/netip"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// acceptRoute processes lifecycle notices in the reader, even when an agent's
// application queue is full. Only current application frames enter that queue.
func (l *controllerLink) acceptRoute(frame routedFrame) (bool, error) {
	if !identity.ValidAgentID(frame.AgentID) || !validHexBytes(frame.ConnectionID, 16) {
		return false, errors.New("invalid routing identity")
	}
	switch frame.Type {
	case "connected":
		l.mu.Lock()
		if len(l.routes) >= wire.MaxConnectedAgents && l.routes[frame.AgentID] == "" {
			l.mu.Unlock()
			return false, errors.New("controller route capacity reached")
		}
		l.routes[frame.AgentID] = frame.ConnectionID
		l.mu.Unlock()
		l.s.agentConnected(frame.AgentID)
		// The connection's own ordered worker checks its source before any
		// message from it, without making this reader wait for storage.
		return true, nil
	case "disconnected":
		l.forgetRoute(frame.AgentID, frame.ConnectionID)
		return false, nil
	case "from_agent":
		return l.currentRoute(frame.AgentID, frame.ConnectionID), nil
	default:
		return false, errors.New("invalid routing frame type")
	}
}

func (l *controllerLink) currentRoute(agentID, connectionID string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.conn != nil && connectionID != "" && l.routes[agentID] == connectionID
}

// forgetRoute revokes queued work and authority without touching a newer connection.
func (l *controllerLink) forgetRoute(agentID, connectionID string) {
	l.mu.Lock()
	if l.routes[agentID] == connectionID {
		delete(l.routes, agentID)
	}
	l.mu.Unlock()
	l.s.clearRouteSession(agentID, connectionID)
}

// connectionSourceRejection explains why a new transport connection must close
// before any of its messages are handled. WireGuard authenticates each peer's
// source address, so another display cannot hold an enrolled identity, and
// unknown identities are closed at once. Connections from the controller host
// are local. Unavailable authority must not bypass the source check: the hello
// authenticates a credential, but does not repeat this address lookup.
func (s *Server) connectionSourceRejection(agentID, remoteAddress string) string {
	if s.store == nil {
		return "agent enrollment authority unavailable"
	}
	ctx, cancel := boundedStoreContext()
	defer cancel()
	expected, err := s.store.AgentTunnelAddress(ctx, agentID)
	if errors.Is(err, store.ErrNotFound) {
		return "agent is not provisioned in the authority database"
	}
	if err != nil {
		return "agent enrollment authority unavailable"
	}
	source, err := netip.ParseAddr(remoteAddress)
	if err == nil && source.IsLoopback() {
		return ""
	}
	if err != nil || source.String() != expected {
		return "connection source does not match the enrolled tunnel address"
	}
	return ""
}

func (s *Server) clearRouteSession(agentID, connectionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session := s.sessions[agentID]; session != nil && session.connectionID == connectionID {
		delete(s.sessions, agentID)
	}
}
