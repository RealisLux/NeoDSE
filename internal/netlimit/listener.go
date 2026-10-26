// File purpose: Bounds accepted TCP connections before protocol parsing or authentication.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package netlimit limits live connections using their actual network source.
package netlimit

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Pool shares total and per-source connection capacity between listeners.
// Loopback connections count toward the total but skip the per-source limit,
// because trusted local callers can carry traffic for multiple remote agents.
type Pool struct {
	mu             sync.Mutex
	limit          int
	perSourceLimit int
	active         int
	sources        map[netip.Addr]int
	logged         time.Time
	suppressed     uint64
}

// New constructs a connection pool with positive total and per-source limits.
func New(totalLimit, perSourceLimit int) (*Pool, error) {
	if totalLimit < 1 || perSourceLimit < 1 {
		return nil, errors.New("positive total and per-source connection limits are required")
	}
	return &Pool{
		limit:          totalLimit,
		perSourceLimit: perSourceLimit,
		sources:        make(map[netip.Addr]int),
	}, nil
}

// Wrap applies the pool before returning accepted connections to the caller.
// Excess connections and connections without a numeric IP source are closed
// immediately. Closing the listener retains ordinary net.Listener semantics:
// the caller must close accepted connections, including hijacked connections.
func (p *Pool) Wrap(listener net.Listener) net.Listener {
	return &limitedListener{Listener: listener, pool: p}
}

type limitedListener struct {
	net.Listener
	pool *Pool
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if source, ok := l.pool.acquire(conn.RemoteAddr()); ok {
			return &limitedConn{Conn: conn, pool: l.pool, source: source}, nil
		}
		l.pool.logRejection()
		_ = conn.Close()
	}
}

// logRejection reports overload without repeating attacker-controlled addresses
// or allowing a connection flood to produce an unbounded diagnostic stream.
func (p *Pool) logRejection() {
	now := time.Now()
	p.mu.Lock()
	if !p.logged.IsZero() && now.Sub(p.logged) < 30*time.Second {
		p.suppressed++
		p.mu.Unlock()
		return
	}
	suppressed := p.suppressed
	p.logged, p.suppressed = now, 0
	p.mu.Unlock()
	log.Printf("! TCP connection rejected total_limit=%d per_source_limit=%d suppressed=%d", p.limit, p.perSourceLimit, suppressed)
}

// acquire uses only the network address supplied by the accepted connection;
// application headers and claimed identities cannot select another quota.
func (p *Pool) acquire(remote net.Addr) (netip.Addr, bool) {
	if remote == nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}, false
	}
	// IPv4-mapped IPv6 addresses share the IPv4 quota. Interface zones cannot
	// create additional quotas for the same numeric address.
	source := address.Addr().Unmap().WithZone("")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active >= p.limit || (!source.IsLoopback() && p.sources[source] >= p.perSourceLimit) {
		return netip.Addr{}, false
	}
	p.active++
	if !source.IsLoopback() {
		p.sources[source]++
	}
	return source, true
}

func (p *Pool) release(source netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
	if !source.IsLoopback() {
		p.sources[source]--
		if p.sources[source] == 0 {
			delete(p.sources, source)
		}
	}
}

type limitedConn struct {
	net.Conn
	pool     *Pool
	source   netip.Addr
	close    sync.Once
	closeErr error
}

func (c *limitedConn) Close() error {
	c.close.Do(func() {
		c.closeErr = c.Conn.Close()
		c.pool.release(c.source)
	})
	return c.closeErr
}
