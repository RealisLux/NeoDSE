// File purpose: Verifies one-use, expiring, stream-scoped VNC credentials.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVNCCredentialIsOneUse proves a consumed capability cannot be replayed.
func TestVNCCredentialIsOneUse(t *testing.T) {
	const streamID = "0123456789abcdef0123456789abcdef"
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	agent := &Agent{displayStreams: map[string]net.Conn{streamID: local}, vncAuthListener: &testVNCListener{}}
	token, err := agent.prepareVNCCredential(streamID)
	if err != nil {
		t.Fatal(err)
	}
	if !agent.consumeVNCCredential(token) {
		t.Fatal("fresh credential was rejected")
	}
	if agent.consumeVNCCredential(token) {
		t.Fatal("credential was accepted twice")
	}
}

// TestVNCCredentialExpiryAndRevocation rejects stale and explicitly revoked capabilities.
func TestVNCCredentialExpiryAndRevocation(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	agent := &Agent{vncCredentials: make(map[[sha256.Size]byte]vncCredential), displayStreams: map[string]net.Conn{"expired": local, "stream-to-revoke": local}, vncAuthListener: &testVNCListener{}}
	expired := "expired-credential-that-is-long-enough"
	agent.vncCredentials[sha256.Sum256([]byte(expired))] = vncCredential{streamID: "expired", token: expired, expiresAt: time.Now().Add(-time.Second)}
	if agent.consumeVNCCredential(expired) {
		t.Fatal("expired credential was accepted")
	}
	token, err := agent.prepareVNCCredential("stream-to-revoke")
	if err != nil {
		t.Fatal(err)
	}
	agent.revokeVNCCredentials("stream-to-revoke")
	if agent.consumeVNCCredential(token) {
		t.Fatal("revoked credential was accepted")
	}
}

// TestVNCCredentialRequiresAuthenticationService fails issuance without a local authority.
func TestVNCCredentialRequiresAuthenticationService(t *testing.T) {
	agent := &Agent{}
	if _, err := agent.prepareVNCCredential("stream"); err == nil {
		t.Fatal("credential was issued without a PAM authority listener")
	}
}

type testVNCListener struct{}

// Accept implements the listener contract for credential issuance tests.
func (*testVNCListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }

// Close implements the listener contract for credential issuance tests.
func (*testVNCListener) Close() error { return nil }

// Addr implements the listener contract for credential issuance tests.
func (*testVNCListener) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

// TestVNCAuthRejectsOversizedUnterminatedToken bounds reads before a peer sends EOF.
func TestVNCAuthRejectsOversizedUnterminatedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{}
	done := make(chan struct{})
	go func() { agent.handleVNCAuthConnection(connection, uint32(os.Getuid())); close(done) }()
	if _, err := client.Write([]byte(strings.Repeat("a", vncTokenMaxBytes+2))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		client.Close()
		<-done
		t.Fatal("oversized input waited for EOF or the connection timeout")
	}
}

// TestVNCAuthConnectionRejectsWrongUIDAndConsumesCredential exercises kernel peer credentials and replay rejection.
func TestVNCAuthConnectionRejectsWrongUIDAndConsumesCredential(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	a := &Agent{displayStreams: map[string]net.Conn{"stream": local}, vncAuthListener: &testVNCListener{}}
	token, err := a.prepareVNCCredential("stream")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "auth.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, test := range []struct {
		name     string
		uid      uint32
		want     byte
		rejected bool
	}{
		{"wrong uid", uint32(os.Getuid() + 1), 0, true},
		{"allowed uid", uint32(os.Getuid()), 1, false},
		{"replay", uint32(os.Getuid()), 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := net.Dial("unix", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); a.handleVNCAuthConnection(peer, test.uid) }()
			_, _ = client.Write([]byte(token + "\n"))
			var result [1]byte
			n, err := client.Read(result[:])
			if test.rejected {
				if n != 0 || err == nil {
					t.Fatal("wrong UID received an authentication response")
				}
			} else if err != nil || n != 1 || result[0] != test.want {
				t.Fatalf("response=%v n=%d err=%v", result, n, err)
			}
			<-done
		})
	}
}
