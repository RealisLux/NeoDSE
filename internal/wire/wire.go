// File purpose: Defines the opaque transport, proxy authorization, display and VNC authentication contracts and limits.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package wire contains data contracts shared across service boundaries.
package wire

import "time"

// ProtocolVersion identifies the application authentication and key-derivation contract.
const ProtocolVersion = 1

// MaxFrameBytes bounds one encoded routing frame.
const MaxFrameBytes = 4 << 20

// MaxDisplayPixels bounds decoded display image area before framebuffer or browser allocation.
const MaxDisplayPixels = 4096 * 4096

// MaxDisplayChunkBytes bounds one encoded JPEG frame of a read-only display stream.
const MaxDisplayChunkBytes = 2 << 20

// MaxConnectedAgents bounds the displays that the transport routes and the
// controller serves at the same time.
const MaxConnectedAgents = 4096

// MaxClockSkew bounds the difference between the timestamp of an authenticated
// message and the receiver's clock.
const MaxClockSkew = 2 * time.Minute

// VNCAuthSocketPath is the agent socket through which neodse-vnc-auth redeems
// one-use VNC credentials.
const VNCAuthSocketPath = "/run/neodse-vnc-auth/auth.sock"

// A VNC credential sent to VNCAuthSocketPath has this many bytes, excluding
// the terminating newline.
const (
	MinVNCTokenBytes = 32
	MaxVNCTokenBytes = 128
)

// RoutedFrame carries opaque application payloads through the transport.
// Connection notices include the peer's IPv4 source address, which WireGuard
// authenticates for every enrolled display.
type RoutedFrame struct {
	Type          string `json:"type"`
	AgentID       string `json:"agent_id,omitempty"`
	ConnectionID  string `json:"connection_id"`
	RemoteAddress string `json:"remote_address,omitempty"`
	Payload       []byte `json:"payload,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// AuthorizeRequest binds a credential to one destination.
type AuthorizeRequest struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	Scheme  string `json:"scheme"`
}

// AuthorizeResponse distinguishes identity failure from policy denial.
type AuthorizeResponse struct {
	Authenticated bool `json:"authenticated"`
	Allowed       bool `json:"allowed"`
}
