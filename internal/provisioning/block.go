// File purpose: Parses and writes bounded human-transferable provisioning request and response blocks.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package provisioning enrolls displays through operator-transferred text
// blocks and installs configuration atomically with the intended ownership.
package provisioning

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/RealisLux/NeoDSE/internal/destination"
	"github.com/RealisLux/NeoDSE/internal/identity"
	"golang.org/x/sys/unix"
)

// Version is the provisioning block format that ReadBlock accepts.
const Version = "1"

const (
	maxBlockFields    = 9
	maxBlockLineBytes = 4096
)

// ValidateServerEndpoint accepts a DNS name or IPv4 literal with an explicit UDP port.
func ValidateServerEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !address.Is4() {
			return errors.New("IPv6 endpoints are unsupported")
		}
	} else if !destination.ValidDNSName(strings.TrimSuffix(strings.ToLower(host), ".")) {
		return errors.New("invalid endpoint hostname")
	}
	if number, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil || number == 0 {
		return errors.New("endpoint port is invalid")
	}
	return nil
}

// AgentRequest is the bounded enrollment request produced by an unprovisioned agent.
type AgentRequest struct {
	AgentID            string
	WireGuardPublicKey string
}

// ServerResponse is the bounded enrollment response produced by the controller.
type ServerResponse struct {
	ServerPublicKey string
	PresharedKey    string
	ServerEndpoint  string
	ServerAddress   string
	TransportURL    string
	ProxyURL        string
	AgentAddress    string
	AgentPSK        string
}

// ReadBlock parses one bounded operator-input block. Polling stdin before each
// read lets cancellation interrupt incomplete input without leaving a blocked
// reader goroutine. The caller retains ownership of the input file.
func ReadBlock(ctx context.Context, input *os.File) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values, err := parseBlock(&blockInput{ctx: ctx, file: input})
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	return values, err
}

type blockInput struct {
	ctx  context.Context
	file *os.File
}

// Read waits for file input in short intervals so an idle terminal or pipe
// cannot retain the provisioning lock after SIGINT or SIGTERM.
func (input *blockInput) Read(buffer []byte) (int, error) {
	fd := input.file.Fd()
	if fd == ^uintptr(0) {
		return 0, os.ErrClosed
	}
	if fd > math.MaxInt32 {
		return 0, os.ErrInvalid
	}
	for {
		if err := input.ctx.Err(); err != nil {
			return 0, err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if ready > 0 {
			return input.file.Read(buffer)
		}
	}
}

// parseBlock enforces the bounded line-oriented provisioning syntax.
func parseBlock(r io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), maxBlockLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		if len(values) >= maxBlockFields {
			return nil, fmt.Errorf("provisioning block exceeds %d fields", maxBlockFields)
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, errors.New("invalid provisioning line; expected a nonempty KEY=VALUE pair")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate provisioning field")
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if values["NEODSE_PROVISIONING_VERSION"] != Version {
		return nil, errors.New("unsupported provisioning version")
	}
	return values, nil
}

// ParseAgentRequest validates the exact fields supplied by an unenrolled agent.
func ParseAgentRequest(values map[string]string) (AgentRequest, error) {
	if err := exactFields(values, "NEODSE_PROVISIONING_VERSION", "AGENT_ID", "WG_PUBLIC_KEY"); err != nil {
		return AgentRequest{}, err
	}
	r := AgentRequest{AgentID: values["AGENT_ID"], WireGuardPublicKey: values["WG_PUBLIC_KEY"]}
	if !identity.ValidAgentID(r.AgentID) {
		return AgentRequest{}, errors.New("invalid agent ID")
	}
	if !validWGKey(r.WireGuardPublicKey) {
		return AgentRequest{}, errors.New("invalid WireGuard public key")
	}
	return r, nil
}

// ParseServerResponse validates the exact controller enrollment response.
func ParseServerResponse(values map[string]string) (ServerResponse, error) {
	fields := []string{"NEODSE_PROVISIONING_VERSION", "SERVER_PUBLIC_KEY", "PRESHARED_KEY", "SERVER_ENDPOINT", "SERVER_ADDRESS", "TRANSPORT_URL", "PROXY_URL", "AGENT_ADDRESS", "AGENT_PSK"}
	if err := exactFields(values, fields...); err != nil {
		return ServerResponse{}, err
	}
	r := ServerResponse{values[fields[1]], values[fields[2]], values[fields[3]], values[fields[4]], values[fields[5]], values[fields[6]], values[fields[7]], values[fields[8]]}
	return ValidateServerResponse(r)
}

// ValidateServerResponse checks generated enrollment responses before installation.
func ValidateServerResponse(r ServerResponse) (ServerResponse, error) {
	if !validWGKey(r.ServerPublicKey) || !validWGKey(r.PresharedKey) {
		return ServerResponse{}, errors.New("invalid WireGuard key")
	}
	if err := ValidateServerEndpoint(r.ServerEndpoint); err != nil {
		return ServerResponse{}, fmt.Errorf("invalid server endpoint: %w", err)
	}
	serverIP, serverErr := netip.ParseAddr(r.ServerAddress)
	agentIP, agentErr := netip.ParseAddr(r.AgentAddress)
	if serverErr != nil || !serverIP.Is4() || !serverIP.IsPrivate() || agentErr != nil || !agentIP.Is4() || !agentIP.IsPrivate() || serverIP == agentIP {
		return ServerResponse{}, errors.New("server and agent addresses must be distinct private IPv4 addresses")
	}
	u, err := url.Parse(r.TransportURL)
	if err != nil || u.Scheme != "ws" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ServerResponse{}, errors.New("invalid transport URL")
	}
	if address, parseErr := netip.ParseAddr(u.Hostname()); parseErr != nil || address != serverIP {
		return ServerResponse{}, errors.New("transport URL must use the server WireGuard address")
	}
	proxyURL, err := url.Parse(r.ProxyURL)
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Host == "" || proxyURL.User != nil || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return ServerResponse{}, errors.New("invalid proxy URL")
	}
	if address, parseErr := netip.ParseAddr(proxyURL.Hostname()); parseErr != nil || address != serverIP {
		return ServerResponse{}, errors.New("proxy URL must use the server WireGuard address")
	}
	if len(r.AgentPSK) != 64 {
		return ServerResponse{}, errors.New("invalid agent PSK")
	}
	for _, c := range r.AgentPSK {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return ServerResponse{}, errors.New("invalid agent PSK")
		}
	}
	return r, nil
}

// WriteAgentRequest emits a deterministic operator-transfer request block.
func WriteAgentRequest(w io.Writer, r AgentRequest) error {
	_, err := fmt.Fprintf(w, "NEODSE_PROVISIONING_VERSION=%s\nAGENT_ID=%s\nWG_PUBLIC_KEY=%s\n\n", Version, r.AgentID, r.WireGuardPublicKey)
	return err
}

// WriteServerResponse emits a deterministic operator-transfer response block.
func WriteServerResponse(w io.Writer, r ServerResponse) error {
	_, err := fmt.Fprintf(w, "NEODSE_PROVISIONING_VERSION=%s\nSERVER_PUBLIC_KEY=%s\nPRESHARED_KEY=%s\nSERVER_ENDPOINT=%s\nSERVER_ADDRESS=%s\nTRANSPORT_URL=%s\nPROXY_URL=%s\nAGENT_ADDRESS=%s\nAGENT_PSK=%s\n\n", Version, r.ServerPublicKey, r.PresharedKey, r.ServerEndpoint, r.ServerAddress, r.TransportURL, r.ProxyURL, r.AgentAddress, r.AgentPSK)
	return err
}

// exactFields rejects missing, unknown, and empty provisioning fields.
func exactFields(values map[string]string, fields ...string) error {
	want := make(map[string]bool, len(fields))
	for _, field := range fields {
		want[field] = true
	}
	for key := range values {
		if !want[key] {
			return errors.New("unknown provisioning field")
		}
	}
	for _, field := range fields {
		if values[field] == "" {
			return fmt.Errorf("missing provisioning field %s", field)
		}
	}
	return nil
}

// validWGKey reports whether a value is one canonical 32-byte WireGuard key.
func validWGKey(value string) bool {
	b, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == value
}
