// File purpose: Verifies approved-address failover without weakening proxy egress policy.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

// TestResolvedDialTriesOtherApprovedAddresses keeps one failed DNS candidate from hiding a healthy endpoint.
func TestResolvedDialTriesOtherApprovedAddresses(t *testing.T) {
	p := &Proxy{authorizedNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("127.0.0.0/8")}}
	addresses := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.20.0.1"), netip.MustParseAddr("::ffff:10.20.0.2")}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var attempts []string
	connection, err := p.dialResolvedAddresses(context.Background(), "443", addresses, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" {
			t.Errorf("network=%s, want tcp4", network)
		}
		attempts = append(attempts, address)
		if address == "10.20.0.2:443" {
			return client, nil
		}
		return nil, errors.New("connection refused")
	})
	if err != nil || connection != client || !reflect.DeepEqual(attempts, []string{"10.20.0.1:443", "10.20.0.2:443"}) {
		t.Fatalf("connection=%v error=%v attempts=%v", connection, err, attempts)
	}
}

// TestResolvedDialStopsOnCancellation prevents further connections after the shared operation expires.
func TestResolvedDialStopsOnCancellation(t *testing.T) {
	p := &Proxy{authorizedNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	_, err := p.dialResolvedAddresses(ctx, "443", []netip.Addr{netip.MustParseAddr("10.20.0.1"), netip.MustParseAddr("10.20.0.2")}, func(context.Context, string, string) (net.Conn, error) {
		attempts++
		cancel()
		return nil, context.Canceled
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("error=%v attempts=%d", err, attempts)
	}
}

// TestResolvedDialRejectsDeniedCandidates makes an allowlist mandatory even during failover.
func TestResolvedDialRejectsDeniedCandidates(t *testing.T) {
	p := &Proxy{}
	_, err := p.dialResolvedAddresses(context.Background(), "443", []netip.Addr{netip.MustParseAddr("10.20.0.1")}, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("denied candidate was dialled")
		return nil, nil
	})
	if err == nil {
		t.Fatal("all-denied resolution was accepted")
	}
}
