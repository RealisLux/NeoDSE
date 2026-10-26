// File purpose: Bridges the stock pam_exec module to NeoDSE's one-use VNC credential authority.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// The neodse-vnc-auth command is the pam_exec helper of Weston's remote-access
// PAM service. It forwards one VNC credential to the agent and reports the
// agent's answer as its exit status.
package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/RealisLux/NeoDSE/internal/cli"
	"github.com/RealisLux/NeoDSE/internal/logging"
	"github.com/RealisLux/NeoDSE/internal/peercred"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

var version = "dev"

const (
	authSocketPath = wire.VNCAuthSocketPath
	agentUser      = "neodse-agent"
	allowedUser    = "neodse-ui"
	allowedService = "weston-remote-access"
	maxTokenBytes  = wire.MaxVNCTokenBytes
)

// main converts the helper's fail-closed result into pam_exec's process status.
func main() {
	logging.Configure()
	if cli.WriteVersion(os.Stdout, "neodse-vnc-auth", version, os.Args[1:]) {
		return
	}
	if err := cli.DisableProcessDumping(); err != nil {
		os.Exit(1)
	}
	os.Exit(run(os.Getenv, os.Stdin, authenticateToken))
}

// run validates the immutable PAM context before reading or forwarding a token.
func run(getenv func(string) string, input io.Reader, authenticate func([]byte) bool) int {
	if getenv("PAM_SERVICE") != allowedService || getenv("PAM_USER") != allowedUser {
		return 1
	}
	switch getenv("PAM_TYPE") {
	case "account":
		return 0
	case "auth":
		token, err := io.ReadAll(io.LimitReader(input, maxTokenBytes+1))
		if err != nil {
			return 1
		}
		defer clear(token)
		if len(token) < wire.MinVNCTokenBytes || len(token) > maxTokenBytes || !authenticate(token) {
			return 1
		}
		return 0
	default:
		return 1
	}
}

// authenticateToken submits one bounded token to the peer-authenticated agent socket.
func authenticateToken(token []byte) bool {
	account, err := user.Lookup(agentUser)
	if err != nil {
		return false
	}
	expectedUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", authSocketPath)
	if err != nil {
		return false
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || peercred.UID(unixConnection) != uint32(expectedUID) {
		return false
	}
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	request := make([]byte, len(token)+1)
	copy(request, token)
	request[len(token)] = '\n'
	defer clear(request)
	for sent := 0; sent < len(request); {
		written, err := connection.Write(request[sent:])
		if err != nil || written == 0 {
			return false
		}
		sent += written
	}
	response := []byte{0}
	if _, err := io.ReadFull(connection, response); err != nil {
		return false
	}
	return response[0] == 1
}
