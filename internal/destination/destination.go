// File purpose: Centralizes HTTP destination identity and validation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package destination defines the shared HTTP origin identity.
package destination

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Canonical normalizes an HTTP destination for exact policy matching.
func Canonical(scheme, host, port string) (string, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if scheme != "http" && scheme != "https" {
		return "", errors.New("invalid proxy scheme")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("invalid proxy port")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if ForbiddenAddress(address) {
			return "", errors.New("forbidden proxy address")
		}
		host = address.String()
	} else if !ValidDNSName(host) {
		return "", errors.New("invalid proxy host")
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

// FromURL reduces an HTTP URL to the exact scheme, host, and port used by proxy policy.
func FromURL(rawURL string) (string, error) {
	parsed, err := ParseURL(rawURL)
	if err != nil {
		return "", err
	}
	return Canonical(parsed.Scheme, parsed.Hostname(), URLPort(parsed))
}

// ParseURL accepts only bounded absolute HTTP(S) URLs without credentials.
func ParseURL(rawURL string) (*url.URL, error) {
	if len(rawURL) == 0 || len(rawURL) > 8192 {
		return nil, errors.New("URL length is outside supported bounds")
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("URL must be absolute HTTP or HTTPS without credentials")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return nil, errors.New("URL contains an invalid port")
		}
	}
	if _, err := Canonical(parsed.Scheme, parsed.Hostname(), URLPort(parsed)); err != nil {
		return nil, err
	}
	return parsed, nil
}

// URLPort returns the explicit port of an HTTP(S) URL or its scheme's default.
func URLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	return "80"
}

// ValidDNSName applies conservative ASCII hostname rules before a proxy policy is stored.
func ValidDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// ForbiddenAddress identifies address classes that no configured exception can authorize.
func ForbiddenAddress(address netip.Addr) bool {
	return !address.IsValid() || !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast()
}

// PermittedAddress applies the explicit allowlist equally to literal and
// resolved destinations. Permanently forbidden address classes cannot be enabled.
func PermittedAddress(address netip.Addr, authorizedNetworks []netip.Prefix) bool {
	address = address.Unmap()
	if ForbiddenAddress(address) {
		return false
	}
	for _, prefix := range authorizedNetworks {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
