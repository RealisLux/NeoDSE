// File purpose: Reads the kernel-authenticated user of a connected Unix socket peer.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package peercred identifies the local process on the other end of a Unix
// socket from credentials that the kernel records at connect time.
package peercred

import (
	"net"

	"golang.org/x/sys/unix"
)

// UnknownUID is returned when the peer's credentials cannot be read. No
// account has this UID, so comparing it with an expected UID always fails.
const UnknownUID = ^uint32(0)

// UID returns the effective UID of the process that connected the socket, or
// UnknownUID.
func UID(connection *net.UnixConn) uint32 {
	raw, err := connection.SyscallConn()
	if err != nil {
		return UnknownUID
	}
	uid := UnknownUID
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialErr == nil {
			uid = credential.Uid
		}
	}); err != nil {
		return UnknownUID
	}
	return uid
}
