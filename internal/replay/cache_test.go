// File purpose: Verifies replay rejection, expiry, capacity bounds, and clock skew handling.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package replay

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCacheRejectsDuplicateAndExpiredMessages verifies cache rejects duplicate and expired messages.
func TestCacheRejectsDuplicateAndExpiredMessages(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 8)
	if err := cache.Accept("one", now, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Accept("one", now, now); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if err := cache.Accept("old", now.Add(-2*time.Minute), now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired error = %v", err)
	}
	if err := cache.Accept("future", now.Add(2*time.Minute), now); !errors.Is(err, ErrExpired) {
		t.Fatalf("future error = %v", err)
	}
	if err := cache.Accept("", now, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("empty ID error = %v", err)
	}
}

// TestCacheCapacityPreservesReplayProtection verifies overload cannot evict a
// still-valid identifier and thereby authorize a replay.
func TestCacheCapacityPreservesReplayProtection(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 2)
	if err := cache.Accept("one", now, now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Accept("two", now.Add(time.Second), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := cache.Accept("three", now.Add(2*time.Second), now.Add(2*time.Second)); !errors.Is(err, ErrFull) {
		t.Fatalf("full cache result: %v", err)
	}
	if err := cache.Accept("one", now, now.Add(3*time.Second)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("capacity pressure reopened a valid replay: %v", err)
	}
	if err := cache.Accept("fresh", now.Add(2*time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(cache.entries) != 1 || cache.entries[identifier{id: "fresh"}].IsZero() {
		t.Fatalf("expired entries were not pruned: %+v", cache.entries)
	}
}

// TestScopedCacheIsolatesCapacity verifies one identity cannot fill the shared
// cache and that expiry releases both nonce entries and identity accounting.
func TestScopedCacheIsolatesCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 3)
	for _, id := range []string{"one", "two"} {
		if err := cache.AcceptScoped("noisy", id, now, now, 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.AcceptScoped("noisy", "three", now, now, 2); !errors.Is(err, ErrFull) {
		t.Fatalf("identity quota: %v", err)
	}
	if err := cache.AcceptScoped("healthy", "one", now, now, 2); err != nil {
		t.Fatalf("another identity lost replay capacity: %v", err)
	}
	for index := range 100 {
		if err := cache.AcceptScoped(strconv.Itoa(index), "one", now, now, 2); !errors.Is(err, ErrFull) {
			t.Fatalf("shared capacity: %v", err)
		}
	}
	if len(cache.scopes) != 2 {
		t.Fatalf("failed admissions retained identity accounting: %d", len(cache.scopes))
	}
	if err := cache.AcceptScoped("noisy", "one", now, now.Add(time.Minute), 2); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("identity pressure reopened a valid replay: %v", err)
	}
	after := now.Add(time.Minute + time.Nanosecond)
	if err := cache.AcceptScoped("noisy", "fresh", after, after, 2); err != nil {
		t.Fatal(err)
	}
	if len(cache.entries) != 1 || len(cache.scopes) != 1 || cache.scopes["noisy"] != 1 {
		t.Fatalf("expired replay accounting retained: entries=%d scopes=%v", len(cache.entries), cache.scopes)
	}
}

// TestScopedCacheConcurrentAdmission verifies identity quotas are atomic.
func TestScopedCacheConcurrentAdmission(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 100)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for index := range 100 {
		workers.Go(func() {
			if err := cache.AcceptScoped("noisy", strconv.Itoa(index), now, now, 2); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrFull) {
				t.Errorf("unexpected admission: %v", err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 2 {
		t.Fatalf("identity quota admitted %d entries", accepted.Load())
	}
}

// TestScopedCacheRejectsInvalidLimits prevents invalid scopes from retaining state.
func TestScopedCacheRejectsInvalidLimits(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 3)
	for _, test := range []struct {
		scope string
		limit int
	}{{"", 1}, {"agent", 0}, {"agent", -1}} {
		if err := cache.AcceptScoped(test.scope, "nonce", now, now, test.limit); err == nil {
			t.Fatalf("invalid replay scope %q or capacity %d accepted", test.scope, test.limit)
		}
	}
	if len(cache.entries) != 0 || len(cache.scopes) != 0 {
		t.Fatal("invalid scoped admissions retained state")
	}
}

// TestCacheExpiryOrderAndConcurrentDuplicates checks expiration order independent
// of arrival order and atomic admission of a shared identifier.
func TestCacheExpiryOrderAndConcurrentDuplicates(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 2)
	if err := cache.Accept("future", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Accept("past", now.Add(-time.Minute), now); err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			err := cache.Accept("shared", now, now.Add(time.Second))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrDuplicate) {
				t.Errorf("unexpected concurrent admission result: %v", err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent admissions: %d", accepted.Load())
	}
	if err := cache.Accept("future", now.Add(time.Minute), now.Add(time.Second)); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expiry removed the wrong identifier: %v", err)
	}
}

// TestFutureTimestampRetainsReplayProtection covers the entire accepted skew
// window, including the exact final instant at which the timestamp is valid.
func TestFutureTimestampRetainsReplayProtection(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := New(time.Minute, 8)
	timestamp := now.Add(time.Minute)
	if err := cache.Accept("future", timestamp, now); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{time.Minute + time.Second, 2 * time.Minute} {
		if err := cache.Accept("future", timestamp, now.Add(elapsed)); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("replay at %s accepted or misclassified: %v", elapsed, err)
		}
	}
	if err := cache.Accept("future", timestamp, now.Add(2*time.Minute+time.Nanosecond)); !errors.Is(err, ErrExpired) {
		t.Fatalf("timestamp past full skew window: %v", err)
	}
}
