// File purpose: Verifies kernel peer credentials for connected and closed Unix sockets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package peercred

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestUIDReportsConnectedProcess reads this process's UID from its own peer
// and fails closed once the connection is closed.
func TestUIDReportsConnectedProcess(t *testing.T) {
	local, remote := socketPair(t)
	defer remote.Close()
	if got, want := UID(local), uint32(os.Geteuid()); got != want {
		t.Fatalf("UID = %d, want %d", got, want)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	if got := UID(local); got != UnknownUID {
		t.Fatalf("closed connection UID = %d, want UnknownUID", got)
	}
}

// socketPair returns both ends of a connected Unix stream socket without a filesystem path.
func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "socketpair")
		connection, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection.(*net.UnixConn))
	}
	return connections[0], connections[1]
}
