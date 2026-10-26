// File purpose: Defines explicit-proxy dependencies, connection limits, and diagnostic state.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
)

// Proxy owns the dependencies and mutable state of one explicit-proxy instance.
type Proxy struct {
	config             Config
	leaseMu            sync.Mutex
	leases             map[leaseKey]*authorizationLease
	leaseWorkers       sync.WaitGroup
	requestWorkers     sync.WaitGroup
	requestCancels     map[uint64]context.CancelFunc
	leaseDuration      time.Duration
	stopping           bool
	backendClient      *http.Client
	proxyClient        *http.Client
	requestID          atomic.Uint64
	internalToken      string
	authorizedNetworks []netip.Prefix
	connections        chan struct{}
	agentMu            sync.Mutex
	agentConnections   map[string]int
	agentLimit         int
	capacityWarnings   warningLimiter
	backendWarnings    warningLimiter
	verbose            bool
	debug              bool
	dialOverride       func(context.Context, string, string) (net.Conn, error)
}

// warningLogInterval limits repeated warnings during reload bursts and
// controller outages, when every display retries at once.
const warningLogInterval = 30 * time.Second

// warningLimiter admits the first warning of each interval and counts the
// repeats it suppresses, so request bursts cannot fill the journal.
type warningLimiter struct {
	mu         sync.Mutex
	logged     time.Time
	suppressed uint64
}

// allow reports whether a warning may be written now and how many repeats it summarizes.
func (limiter *warningLimiter) allow(now time.Time) (uint64, bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if !limiter.logged.IsZero() && now.Sub(limiter.logged) < warningLogInterval {
		limiter.suppressed++
		return 0, false
	}
	suppressed := limiter.suppressed
	limiter.logged, limiter.suppressed = now, 0
	return suppressed, true
}

// acquireAgentConnection reserves one of the bounded per-agent connection slots.
func (p *Proxy) acquireAgentConnection(agentID string) bool {
	limit := p.agentLimit
	if limit <= 0 {
		limit = config.DefaultProxyAgentConnections
	}
	p.agentMu.Lock()
	defer p.agentMu.Unlock()
	if p.agentConnections == nil {
		p.agentConnections = make(map[string]int)
	}
	if p.agentConnections[agentID] >= limit {
		return false
	}
	p.agentConnections[agentID]++
	return true
}

// logCapacityRejection reports refused connections at the default level. Pages
// whose subresources are refused render only partially, so operators need this
// signal; repeated rejections within the interval are counted instead. The
// warning never repeats a client-supplied identity or credential.
func (p *Proxy) logCapacityRejection(scope, setting string) {
	if suppressed, ok := p.capacityWarnings.allow(time.Now()); ok {
		log.Printf("! Proxy %s connection capacity reached suppressed=%d; raise %s", scope, suppressed, setting)
	}
}

// logAuthorizationUnavailable reports that the controller could not decide a
// request, for example while its database is locked. Displays keep retrying
// during such an outage, so repeats within the interval are counted instead.
// The controller has not authenticated the request yet, so the warning never
// repeats its claimed identity.
func (p *Proxy) logAuthorizationUnavailable(requestID uint64, detail string) {
	if suppressed, ok := p.backendWarnings.allow(time.Now()); ok {
		log.Printf("! Proxy authorization unavailable request_id=%d %s suppressed=%d", requestID, detail, suppressed)
	}
}

// releaseAgentConnection returns a reserved per-agent slot after request completion.
func (p *Proxy) releaseAgentConnection(agentID string) {
	p.agentMu.Lock()
	defer p.agentMu.Unlock()
	if p.agentConnections[agentID] <= 1 {
		delete(p.agentConnections, agentID)
		return
	}
	p.agentConnections[agentID]--
}

// verboseLog writes one structured request-level diagnostic when verbose
// diagnostics are enabled. Debug mode includes verbose output.
func (p *Proxy) verboseLog(message string, attributes ...any) {
	if p.verbose || p.debug {
		slog.Info(message, attributes...)
	}
}

// debugLog writes one structured request-processing diagnostic in debug mode.
func (p *Proxy) debugLog(message string, attributes ...any) {
	if p.debug {
		slog.Info(message, attributes...)
	}
}

// logRequestSummary writes one redacted proxy outcome through the normal service logger.
func (p *Proxy) logRequestSummary(request *proxyRequest) {
	if request == nil || (!p.verbose && !p.debug) {
		return
	}
	outcome := request.outcome
	if outcome == "" {
		outcome = "internal_error"
	}
	duration := max(time.Since(request.started).Milliseconds(), 0)
	attributes := []any{
		"request_id", request.id,
		"outcome", outcome,
		"duration_ms", duration,
		"bytes_to_destination", request.bytesToDestination,
		"bytes_to_client", request.bytesToClient,
	}
	if request.loggedAgentID != "" {
		attributes = append(attributes, "agent_id", request.loggedAgentID)
	}
	if request.destinationHost != "" {
		attributes = append(attributes,
			"destination_host", request.destinationHost,
			"destination_port", request.destinationPort,
			"protocol", request.protocol,
		)
	}
	p.verboseLog("proxy request", attributes...)
}

type authorizationDecision uint8

const (
	authorizationUnavailable authorizationDecision = iota
	authorizationCredentialsRejected
	authorizationDenied
	authorizationAllowed
)
