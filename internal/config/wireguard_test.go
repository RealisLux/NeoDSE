// File purpose: Tests plaintext link rejection and bounded netlink decoding.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package config

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPlaintextSocketControl rejects ambiguous peers and propagates every socket failure.
func TestPlaintextSocketControl(t *testing.T) {
	for _, item := range []struct{ network, address, device string }{
		{"tcp", "10.90.0.1:80", "lo"},
		{"tcp6", "[::1]:80", "lo"},
		{"tcp4", "example.com:80", "lo"},
		{"tcp4", "10.90.0.1", "lo"},
		{"tcp4", "10.90.0.1:80", ""},
		{"tcp4", "10.90.0.1:80", "invalid/interface"},
	} {
		if err := PlaintextSocketControl(item.device)(item.network, item.address, nil); err == nil {
			t.Fatalf("invalid socket authority accepted: %+v", item)
		}
	}
	if err := PlaintextSocketControl("")("tcp4", "127.0.0.1:80", nil); err != nil {
		t.Fatalf("loopback needs no device: %v", err)
	}
	want := errors.New("socket unavailable")
	if err := PlaintextSocketControl("lo")("tcp4", "10.90.0.1:80", failedSocket{want}); !errors.Is(err, want) {
		t.Fatalf("raw socket failure: %v", err)
	}
}

// failedSocket reports a socket lifecycle failure without executing its callback.
type failedSocket struct{ err error }

func (s failedSocket) Control(func(uintptr)) error    { return s.err }
func (s failedSocket) Read(func(uintptr) bool) error  { return s.err }
func (s failedSocket) Write(func(uintptr) bool) error { return s.err }

// TestPlaintextSocketControlIntegration always checks real kernel socket binding.
// The dedicated namespace runner additionally removes WireGuard while sockets
// remain open, with all socket operations performed as an unprivileged user.
func TestPlaintextSocketControlIntegration(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "plaintext-socket")
	defer file.Close()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := PlaintextSocketControl("neodse-missing")("tcp4", "10.90.0.1:80", raw); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("missing interface must fail before connect: %v", err)
	}
	if err := PlaintextSocketControl("lo")("tcp4", "10.90.0.1:80", raw); err != nil {
		t.Fatalf("fresh socket binding requires no capabilities: %v", err)
	}
	device, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil || device != "lo" {
		t.Fatalf("kernel socket binding = %q, %v", device, err)
	}
	listener, err := (&net.ListenConfig{Control: PlaintextSocketControl("")}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	loopback, err := (&net.Dialer{Timeout: time.Second, Control: PlaintextSocketControl("")}).DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	loopback.Close()
	if os.Getenv("NEODSE_WIREGUARD_SOCKET_TEST") != "1" {
		return
	}
	testWireGuardSocketRemoval(t)
}

// testWireGuardSocketRemoval proves routed fallback cannot carry a pinned socket.
func testWireGuardSocketRemoval(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("namespace socket operations must run without root privileges")
	}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &capabilities[0]); err != nil || capabilities != [2]unix.CapUserData{} {
		t.Fatalf("namespace socket operations retained capabilities: %+v, %v", capabilities, err)
	}
	syncDir := os.Getenv("NEODSE_WIREGUARD_SOCKET_SYNC")
	if syncDir == "" {
		t.Fatal("namespace coordination directory missing")
	}
	listenConfig := net.ListenConfig{Control: PlaintextSocketControl("neodse")}
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "10.90.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := VerifyPlaintextLink(listener.Addr().String(), "neodse", true); err != nil {
		t.Fatalf("initial WireGuard listener: %v", err)
	}
	dialer := net.Dialer{Timeout: 300 * time.Millisecond, Control: PlaintextSocketControl("neodse")}
	conn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("unprivileged WireGuard connection: %v", err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	boundIndex := socketInterfaceIndex(t, conn)
	iface, err := net.InterfaceByName("neodse")
	if err != nil || boundIndex != iface.Index {
		t.Fatalf("connected socket is not pinned to WireGuard: %d, %+v, %v", boundIndex, iface, err)
	}
	if socketInterfaceIndex(t, accepted) != boundIndex {
		t.Fatal("accepted listener socket lost the WireGuard binding")
	}
	fallback, err := net.Listen("tcp4", "10.90.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fallback.Close()
	assertUnboundReachable(t, fallback.Addr().String())
	if leaked, err := dialer.DialContext(context.Background(), "tcp4", fallback.Addr().String()); err == nil {
		leaked.Close()
		t.Fatal("WireGuard-bound socket reached a different interface")
	}
	watchContext, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()
	watchResult := make(chan error, 1)
	go func() { watchResult <- WatchPlaintextListener(watchContext, listener, "neodse") }()
	select {
	case err := <-watchResult:
		t.Fatalf("listener supervision stopped while WireGuard was present: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(syncDir, "remove-interface"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(syncDir, "interface-removed")); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("WireGuard removal was not acknowledged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if socketInterfaceIndex(t, conn) != boundIndex || socketInterfaceIndex(t, accepted) != boundIndex {
		t.Fatal("established sockets lost their binding when WireGuard disappeared")
	}
	select {
	case err := <-watchResult:
		if err == nil {
			t.Fatal("listener supervision ignored the removed WireGuard interface")
		}
	case <-time.After(3 * plaintextLinkWatchInterval):
		t.Fatal("listener supervision missed the removed WireGuard interface")
	}
	assertUnboundReachable(t, fallback.Addr().String())
	if leaked, err := dialer.DialContext(context.Background(), "tcp4", fallback.Addr().String()); err == nil {
		leaked.Close()
		t.Fatal("new socket fell back after WireGuard removal")
	} else if !errors.Is(err, unix.ENODEV) {
		t.Fatalf("missing WireGuard must fail before connect: %v", err)
	}
}

// TestWatchBoundDeviceRequiresTheConfiguredInterface reports removed or replaced
// tunnels and leaves unconfined loopback listeners running until cancellation.
func TestWatchBoundDeviceRequiresTheConfiguredInterface(t *testing.T) {
	removed := errors.New("no such device")
	for _, scenario := range []struct {
		name   string
		probes []string
		fail   bool
	}{
		{name: "removed", probes: []string{"neodse"}, fail: true},
		{name: "renamed", probes: []string{"neodse", "other"}, fail: true},
		{name: "different interface", probes: []string{"other"}, fail: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			probe := func() (string, error) {
				calls++
				if calls > len(scenario.probes) {
					return "", removed
				}
				return scenario.probes[calls-1], nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := watchBoundDevice(ctx, "neodse", time.Millisecond, probe); err == nil || ctx.Err() != nil {
				t.Fatalf("watcher result=%v context=%v", err, ctx.Err())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, bound := range []string{"", "neodse"} {
		if err := watchBoundDevice(ctx, "neodse", time.Millisecond, func() (string, error) { return bound, nil }); err != nil {
			t.Fatalf("cancelled supervision of %q failed: %v", bound, err)
		}
	}
	if err := watchBoundDevice(ctx, "neodse", time.Millisecond, func() (string, error) { return "", removed }); err == nil {
		t.Fatal("an uninspectable listener was accepted")
	}
}

// TestWatchPlaintextListenerReadsKernelBinding checks a real loopback-bound socket
// and an unconfined listener without changing host networking.
func TestWatchPlaintextListenerReadsKernelBinding(t *testing.T) {
	bindLoopback := func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
		}); err != nil {
			return err
		}
		return bindErr
	}
	bound, err := (&net.ListenConfig{Control: bindLoopback}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	if err := WatchPlaintextListener(context.Background(), bound, "neodse"); err == nil {
		t.Fatal("listener bound to another interface was accepted")
	}
	unconfined, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unconfined.Close()
	for _, listener := range []net.Listener{bound, unconfined} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		device := "lo"
		if listener == unconfined {
			device = ""
		}
		if err := WatchPlaintextListener(ctx, listener, device); err != nil || ctx.Err() == nil {
			t.Fatalf("supervised listener stopped early: %v", err)
		}
		cancel()
	}
}

// socketInterfaceIndex reads the retained kernel binding even after device deletion.
func socketInterfaceIndex(t *testing.T, conn net.Conn) int {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		index, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil || index <= 0 {
		t.Fatalf("socket interface index: %d, %v", index, socketErr)
	}
	return index
}

// assertUnboundReachable provides a positive control for the available fallback path.
func assertUnboundReachable(t *testing.T, address string) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp4", address)
	if err != nil {
		t.Fatalf("fallback path is unavailable: %v", err)
	}
	conn.Close()
}

// TestPlaintextLinkBoundary permits loopback and rejects missing tunnel authority.
func TestPlaintextLinkBoundary(t *testing.T) {
	if err := VerifyPlaintextLink("ws://127.0.0.1:8081", "", false); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"ws://10.0.0.1:8081", "10.0.0.1:3128", "ws://example.com:8081", "ws://[::1]:8081"} {
		if err := VerifyPlaintextLink(endpoint, "", false); err == nil {
			t.Fatalf("insecure link accepted %s", endpoint)
		}
	}
	if err := VerifyPlaintextLink("10.0.0.1:3128", "lo", true); err == nil {
		t.Fatal("loopback device masqueraded as WireGuard")
	}
}

// FuzzNetlinkAttributes rejects malformed kernel-style attribute lengths without panics.
func FuzzNetlinkAttributes(f *testing.F) {
	f.Add([]byte{4, 0, 1, 0})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = netlinkAttributes(data) })
}

// TestInterfaceValidation checks positive tunnel authority and each route or address denial.
func TestInterfaceValidation(t *testing.T) {
	peer := netip.MustParseAddr("10.90.0.1")
	_, assigned, _ := net.ParseCIDR("10.90.0.2/24")
	assigned.IP = net.ParseIP("10.90.0.2")
	iface := net.Interface{Index: 7, Flags: net.FlagUp}
	for _, item := range []struct {
		name      string
		listener  bool
		kind      string
		flags     net.Flags
		addresses []net.Addr
		route     int
		routeErr  error
		want      bool
	}{
		{"remote", false, "wireguard", net.FlagUp, []net.Addr{assigned}, 7, nil, true},
		{"wrong route", false, "wireguard", net.FlagUp, []net.Addr{assigned}, 8, nil, false},
		{"route failure", false, "wireguard", net.FlagUp, []net.Addr{assigned}, 0, errors.New("route unavailable"), false},
		{"wrong listener", true, "wireguard", net.FlagUp, []net.Addr{assigned}, 7, nil, false},
		{"no address", false, "wireguard", net.FlagUp, nil, 7, nil, false},
		{"wrong kind", false, "bridge", net.FlagUp, []net.Addr{assigned}, 7, nil, false},
		{"down", false, "wireguard", 0, []net.Addr{assigned}, 7, nil, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			iface.Flags = item.flags
			err := verifyInterface(peer, item.listener, iface, item.kind, item.addresses, func(netip.Addr) (int, error) { return item.route, item.routeErr })
			if (err == nil) != item.want {
				t.Fatalf("validation: %v", err)
			}
		})
	}
	if err := verifyInterface(netip.MustParseAddr("10.90.0.2"), true, net.Interface{Index: 7, Flags: net.FlagUp}, "wireguard", []net.Addr{assigned}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestKernelLinkAndRouteQueries exercises read-only netlink parsing on the real kernel.
func TestKernelLinkAndRouteQueries(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	kind, err := interfaceKind(loopback.Index)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "wireguard" {
		t.Fatal("loopback identified as WireGuard")
	}
	if _, err := interfaceKind(0x7fffffff); err == nil {
		t.Fatal("missing kernel interface accepted")
	}
	// A local route must not be accepted as a remote unicast WireGuard path.
	if _, err := routeInterface(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("local route accepted")
	}
	index, err := routeInterface(netip.MustParseAddr("192.0.2.1"))
	if err == nil && index <= 0 {
		t.Fatal("kernel route lacks interface")
	}
}
