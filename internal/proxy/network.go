// File purpose: Resolves each destination once and permits only policy-approved network addresses.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/destination"
)

// safeDialContext resolves once, filters every address, and dials only an approved numeric IP.
func (p *Proxy) safeDialContext(ctx context.Context, _, address string) (net.Conn, error) {
	// DNS resolution and every connection attempt share one deadline.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %w", err)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return p.dialResolvedAddresses(ctx, port, addresses, dialer.DialContext)
}

// dialResolvedAddresses applies policy to numeric candidates without another DNS lookup.
func (p *Proxy) dialResolvedAddresses(ctx context.Context, port string, addresses []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	var failures []error
	for _, candidate := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// LookupNetIP represents an IPv4 literal as an IPv4-mapped IPv6
		// address. Normalize it before applying the IPv4-only policy and
		// constructing the numeric dial target.
		candidate = candidate.Unmap()
		if !p.permittedAddress(candidate) {
			continue
		}
		connection, err := dial(ctx, "tcp4", net.JoinHostPort(candidate.String(), port))
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("approved destinations unavailable: %w", errors.Join(failures...))
	}
	return nil, errors.New("destination resolved only to denied addresses")
}

// dialDestination uses the secure production dialer unless a test seam is installed.
func (p *Proxy) dialDestination(ctx context.Context, network, address string) (net.Conn, error) {
	if p.dialOverride != nil {
		return p.dialOverride(ctx, network, address)
	}
	return p.safeDialContext(ctx, network, address)
}

// permittedAddress applies the configured network allowlist to a
// literal address or to each address produced by DNS resolution.
func (p *Proxy) permittedAddress(address netip.Addr) bool {
	return destination.PermittedAddress(address, p.authorizedNetworks)
}

// copyHeader copies only end-to-end headers between proxy messages.
func copyHeader(dst, src http.Header) {
	for key, values := range src {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// hopByHopHeaders are scoped to one connection and never forwarded (RFC 9110,
// section 7.6.1). Proxy-Connection is nonstandard, but clients still send it.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// removeHopByHopHeaders strips standard and Connection-nominated transport headers.
func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for field := range strings.SplitSeq(value, ",") {
			header.Del(strings.TrimSpace(field))
		}
	}
	for _, field := range hopByHopHeaders {
		header.Del(field)
	}
}

// isHopByHopHeader reports whether a header is scoped to one transport connection.
func isHopByHopHeader(header string) bool {
	return slices.ContainsFunc(hopByHopHeaders, func(field string) bool { return strings.EqualFold(field, header) })
}
