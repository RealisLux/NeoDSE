// File purpose: Defines controller runtime ownership, API models, and volatile session state.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/sha256"
	"log"
	"sync"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/replay"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

const storeOperationTimeout = 6 * time.Second

// Config is the strict controller configuration contract.
type Config = config.Server

// Server owns all dependencies and mutable state for one control-server instance.
type Server struct {
	httpMu        sync.Mutex
	httpClosing   bool
	httpWorkers   sync.WaitGroup
	workers       sync.WaitGroup
	config        Config
	link          *controllerLink
	store         *store.Store
	version       string
	now           func() time.Time
	mu            sync.RWMutex
	sessions      map[string]*agentSession
	helloReplay   *replay.Cache
	verbose       bool
	debug         bool
	sendOverride  func(string, protocol.Frame) error
	displayMu     sync.Mutex
	displayRelays map[string]*displayRelay
	auditMu       sync.Mutex
	authFailures  map[string]auditWindow
}

// newServer applies runtime defaults and allocates all volatile controller state.
func newServer(serverConfig Config, version string) *Server {
	if serverConfig.Server.EventRetentionDays == 0 {
		serverConfig.Server.EventRetentionDays = 30
	}
	return &Server{
		config:        serverConfig,
		version:       version,
		now:           time.Now,
		sessions:      make(map[string]*agentSession),
		helloReplay:   replay.New(wire.MaxClockSkew, 8192),
		displayRelays: make(map[string]*displayRelay),
		verbose:       serverConfig.Server.LogLevel == "verbose",
		debug:         serverConfig.Server.LogLevel == "debug",
	}
}

// boundedStoreContext prevents background protocol and maintenance operations from blocking indefinitely.
func boundedStoreContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), storeOperationTimeout)
}

// agentSession tracks one authenticated agent transport session.
type agentSession struct {
	mu           sync.Mutex
	receiveMu    sync.Mutex
	id           string
	connectionID string
	credential   [sha256.Size]byte
	keys         map[keyderivation.Purpose][]byte
	nextSend     uint64
	lastReceived uint64
}

// verbosef writes one operation-level summary when diagnostics are enabled.
// Debug mode includes verbose output.
func (s *Server) verbosef(format string, values ...any) {
	if s.verbose || s.debug {
		log.Printf(format, values...)
	}
}

// AgentState is the controller's current volatile view of one authenticated agent.
type AgentState struct {
	Protocol        int       `json:"protocol"`
	AgentID         string    `json:"agent_id"`
	FriendlyName    string    `json:"friendly_name,omitempty"`
	Hostname        string    `json:"hostname"`
	Version         string    `json:"version"`
	Status          string    `json:"status"`
	StartedAt       string    `json:"started_at"`
	UptimeSeconds   uint64    `json:"uptime_seconds"`
	LastEventID     string    `json:"last_event_id"`
	LastSeen        time.Time `json:"last_seen"`
	IsAuthenticated bool      `json:"is_authenticated"`
	Timestamp       string    `json:"timestamp"`
}

// playlistRequest is the strict HTTP payload for replacing playlist content.
type playlistRequest struct {
	URLs       []string `json:"urls"`
	ProxyAllow []string `json:"proxy_allow,omitempty"`
	Interval   int      `json:"interval,omitempty"`
	StartAt    int64    `json:"start_at,omitempty"`
}

// syncRequest is the strict HTTP payload for playlist clock reconciliation.
type syncRequest struct {
	StartAt string `json:"start_at"`
}

// displayVolumeRequest is the strict HTTP payload for absolute CEC volume.
type displayVolumeRequest struct {
	Level *uint8 `json:"level"`
}

// serialRequest is the strict HTTP payload for a structured peripheral command.
type serialRequest struct {
	Command  instruction.SerialOperation `json:"command"`
	State    instruction.PeripheralState `json:"state,omitempty"`
	PeriodMS int                         `json:"period_ms,omitempty"`
	RelayID  int                         `json:"relay_id,omitempty"`
}

// bannerRequest is the strict HTTP payload for a transient UI overlay.
type bannerRequest struct {
	Message         string `json:"message"`
	Severity        string `json:"severity"`
	DurationSeconds int    `json:"duration_seconds"`
}

// authorizationContextKey prevents collisions with context keys from other packages.
type authorizationContextKey struct{}
