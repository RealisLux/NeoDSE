// File purpose: Provides bounded in-memory replay rejection for authenticated transient messages.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package replay provides a concurrency-safe, bounded replay window.
package replay

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

// Reasons why the cache refuses a message.
var (
	ErrExpired   = errors.New("message timestamp is outside the accepted clock skew")
	ErrDuplicate = errors.New("message ID was already accepted")
	ErrFull      = errors.New("replay window is at capacity")
)

// Cache remembers accepted identifiers for a configured clock-skew window.
type Cache struct {
	mu      sync.Mutex
	entries map[identifier]time.Time
	scopes  map[string]int
	expiry  expirationHeap
	maxAge  time.Duration
	limit   int
}

type identifier struct{ scope, id string }

// New constructs a replay cache with an age window and maximum entry count.
func New(maxAge time.Duration, limit int) *Cache {
	return &Cache{entries: make(map[identifier]time.Time), scopes: make(map[string]int), maxAge: maxAge, limit: limit}
}

// Accept records an identifier if its timestamp is current and it is not known.
func (c *Cache) Accept(id string, timestamp, now time.Time) error {
	return c.accept(identifier{id: id}, timestamp, now, 0)
}

// AcceptScoped isolates identifiers and caps retained entries for one identity.
// Scope counts expire with their entries and share the cache's total bound.
func (c *Cache) AcceptScoped(scope, id string, timestamp, now time.Time, scopeLimit int) error {
	if scope == "" || scopeLimit < 1 {
		return errors.New("replay scope and positive capacity are required")
	}
	return c.accept(identifier{scope: scope, id: id}, timestamp, now, scopeLimit)
}

// accept atomically applies freshness, replay, identity, and global capacity limits.
func (c *Cache) accept(id identifier, timestamp, now time.Time, scopeLimit int) error {
	if id.id == "" || !Fresh(timestamp, now, c.maxAge) {
		return ErrExpired
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if _, exists := c.entries[id]; exists {
		return ErrDuplicate
	}
	if len(c.entries) >= c.limit || (id.scope != "" && c.scopes[id.scope] >= scopeLimit) {
		return ErrFull
	}
	// A future timestamp remains acceptable until timestamp+maxAge, which can
	// be later than now+maxAge. Never forget it while a replay is still valid.
	expires := timestamp.Add(c.maxAge)
	c.entries[id] = expires
	if id.scope != "" {
		c.scopes[id.scope]++
	}
	heap.Push(&c.expiry, expiration{id: id, at: expires})
	return nil
}

// Fresh checks timestamp skew independently of replay state. Authenticated
// session sequences can reject replay without retaining every message ID.
func Fresh(timestamp, now time.Time, maxAge time.Duration) bool {
	return !timestamp.Before(now.Add(-maxAge)) && !timestamp.After(now.Add(maxAge))
}

// prune visits only expired entries; accepting a message never scans the window.
func (c *Cache) prune(now time.Time) {
	for len(c.expiry) > 0 && c.expiry[0].at.Before(now) {
		expired := heap.Pop(&c.expiry).(expiration)
		delete(c.entries, expired.id)
		if scope := expired.id.scope; scope != "" {
			c.scopes[scope]--
			if c.scopes[scope] == 0 {
				delete(c.scopes, scope)
			}
		}
	}
}

type expiration struct {
	id identifier
	at time.Time
}

type expirationHeap []expiration

func (h expirationHeap) Len() int           { return len(h) }
func (h expirationHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h expirationHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expirationHeap) Push(value any)    { *h = append(*h, value.(expiration)) }
func (h *expirationHeap) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	(*h)[last] = expiration{}
	*h = (*h)[:last]
	return value
}
