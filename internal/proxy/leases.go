// File purpose: Revokes active streams using bounded, shared authorization leases.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"sync"
	"time"
)

const authorizationLeaseDuration = 60 * time.Second
const authorizationRenewInterval = 30 * time.Second

// defaultLeaseLimit bounds shared leases when no connection limiter is configured.
const defaultLeaseLimit = 1024

// leaseLimit bounds distinct shared leases. Every lease belongs to a request
// that holds a fleet connection slot, so the configured connection limit also
// bounds leases; a smaller fixed cap would refuse requests below that capacity.
func (p *Proxy) leaseLimit() int {
	if p.connections != nil {
		return cap(p.connections)
	}
	return defaultLeaseLimit
}

type leaseKey struct{ agent, token, scheme, host, port string }
type authorizationLease struct {
	ctx    context.Context
	cancel context.CancelFunc
	refs   int
	done   chan struct{}
}

// bindLease shares renewal work while each new request still checks current policy.
func (p *Proxy) bindLease(request *proxyRequest, target proxyTarget) bool {
	key := leaseKey{request.agentID, request.token, target.scheme, target.host, target.port}
	p.leaseMu.Lock()
	if p.stopping {
		p.leaseMu.Unlock()
		return false
	}
	if p.leases == nil {
		p.leases = make(map[leaseKey]*authorizationLease)
	}
	lease := p.leases[key]
	if lease == nil || lease.ctx.Err() != nil {
		if len(p.leases) >= p.leaseLimit() {
			p.leaseMu.Unlock()
			return false
		}
		ctx, cancel := context.WithCancel(context.Background())
		lease = &authorizationLease{ctx: ctx, cancel: cancel, done: make(chan struct{})}
		p.leases[key] = lease
		p.leaseWorkers.Add(1)
		go p.renewLease(key, lease, request.authorizedAt)
	}
	lease.refs++
	p.leaseMu.Unlock()
	stop := context.AfterFunc(lease.ctx, request.cancel)
	var once sync.Once
	request.releaseLease = func() {
		once.Do(func() {
			stop()
			p.leaseMu.Lock()
			lease.refs--
			if lease.refs == 0 {
				lease.cancel()
				if p.leases[key] == lease {
					delete(p.leases, key)
				}
			}
			p.leaseMu.Unlock()
		})
	}
	return true
}

// renewLease closes consumers on denial, dependency failure, or the hard deadline.
func (p *Proxy) renewLease(key leaseKey, lease *authorizationLease, issued time.Time) {
	defer p.leaseWorkers.Done()
	defer close(lease.done)
	defer lease.cancel()
	duration := authorizationLeaseDuration
	interval := authorizationRenewInterval
	if p.leaseDuration > 0 {
		duration = p.leaseDuration
		interval = duration / 2
	}
	deadline := time.AfterFunc(time.Until(issued.Add(duration)), lease.cancel)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-lease.ctx.Done():
			return
		case <-ticker.C:
			started := time.Now()
			ctx, cancel := context.WithTimeout(lease.ctx, 5*time.Second)
			decision := p.authorize(ctx, 0, key.agent, key.token, key.host, key.port, key.scheme)
			cancel()
			if decision != authorizationAllowed || lease.ctx.Err() != nil {
				return
			}
			// Never extend an already expired grant, including a slow successful lookup.
			if !deadline.Stop() || time.Since(started) >= duration {
				return
			}
			deadline.Reset(time.Until(started.Add(duration)))
		}
	}
}

// stopLeases prevents new consumers and joins all renewal workers.
func (p *Proxy) stopLeases() {
	p.leaseMu.Lock()
	p.stopping = true
	for _, cancel := range p.requestCancels {
		cancel()
	}
	for _, lease := range p.leases {
		lease.cancel()
	}
	p.leaseMu.Unlock()
	p.leaseWorkers.Wait()
	p.requestWorkers.Wait()
}

// trackRequest rejects shutdown races before a handler begins external work.
func (p *Proxy) trackRequest(id uint64, cancel context.CancelFunc) bool {
	p.leaseMu.Lock()
	defer p.leaseMu.Unlock()
	if p.stopping {
		return false
	}
	if p.requestCancels == nil {
		p.requestCancels = make(map[uint64]context.CancelFunc)
	}
	p.requestCancels[id] = cancel
	p.requestWorkers.Add(1)
	return true
}

// releaseRequest relinquishes connection ownership after all copies have joined.
func (p *Proxy) releaseRequest(id uint64) {
	p.leaseMu.Lock()
	delete(p.requestCancels, id)
	p.leaseMu.Unlock()
	p.requestWorkers.Done()
}
