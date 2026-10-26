// File purpose: Verifies plaintext links use an active kernel WireGuard interface.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package config

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// PlaintextSocketControl confines non-loopback TCP sockets to the configured
// WireGuard device before connect or listen. Startup verifies the device's kind;
// binding prevents route changes from sending plaintext through another device.
// Fresh sockets need no extra capabilities on the supported Linux kernels.
func PlaintextSocketControl(device string) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		if network != "tcp4" {
			return errors.New("plaintext socket requires IPv4 TCP")
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		peer, err := netip.ParseAddr(host)
		if err != nil || !peer.Is4() {
			return errors.New("plaintext socket peer must be an IPv4 literal")
		}
		if peer.IsLoopback() {
			return nil
		}
		if !ValidInterfaceName(device) {
			return errors.New("non-loopback plaintext socket requires wireguard_interface")
		}
		var bindErr error
		if err := raw.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		if bindErr != nil {
			return fmt.Errorf("bind plaintext socket to WireGuard: %w", bindErr)
		}
		return nil
	}
}

// plaintextLinkWatchInterval bounds how long a service keeps a listener whose
// WireGuard interface was removed or recreated.
const plaintextLinkWatchInterval = 2 * time.Second

// WatchPlaintextListener returns an error once a listener confined to a
// WireGuard interface can no longer receive connections. SO_BINDTODEVICE keeps
// the interface index, so deleting or recreating the tunnel (for example with
// systemctl restart wg-quick@<instance>) leaves the socket bound to an interface
// that no longer exists. The service exits so systemd binds a fresh listener.
// Loopback listeners are not confined and only wait for cancellation.
func WatchPlaintextListener(ctx context.Context, listener net.Listener, device string) error {
	syscallListener, ok := listener.(syscall.Conn)
	if !ok {
		return errors.New("plaintext listener does not expose its socket")
	}
	raw, err := syscallListener.SyscallConn()
	if err != nil {
		return err
	}
	return watchBoundDevice(ctx, device, plaintextLinkWatchInterval, func() (string, error) {
		return boundDevice(raw)
	})
}

// watchBoundDevice polls the interface bound to a socket until it disappears,
// changes, or the context ends. An unbound socket needs no supervision.
func watchBoundDevice(ctx context.Context, device string, interval time.Duration, probe func() (string, error)) error {
	bound, err := probe()
	if err != nil {
		return fmt.Errorf("inspect plaintext listener binding: %w", err)
	}
	if bound == "" {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if bound != device {
			return fmt.Errorf("WireGuard interface %s was removed or recreated; restarting to bind the current interface", device)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if bound, err = probe(); err != nil {
			return fmt.Errorf("WireGuard interface %s was removed or recreated; restarting to bind the current interface", device)
		}
	}
}

// boundDevice reports the interface currently bound to a socket. The kernel
// resolves the stored interface index, so a removed interface reports an error.
func boundDevice(raw syscall.RawConn) (string, error) {
	var name string
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		name, optionErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return "", err
	}
	return name, optionErr
}

// VerifyPlaintextLink validates the actual interface, address, and direct route.
// Local loopback links need no tunnel. Non-loopback links fail closed when the
// interface is down, is not WireGuard, or routes through a different interface.
func VerifyPlaintextLink(endpoint, device string, listener bool) error {
	address := endpoint
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return err
		}
		address = parsed.Host
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !peer.Is4() {
		return errors.New("plaintext peer must be an IPv4 literal")
	}
	if peer.IsLoopback() {
		return nil
	}
	if !ValidInterfaceName(device) {
		return errors.New("non-loopback plaintext link requires wireguard_interface")
	}
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("WireGuard interface: %w", err)
	}
	kind, err := interfaceKind(iface.Index)
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	return verifyInterface(peer, listener, *iface, kind, addrs, routeInterface)
}

// verifyInterface evaluates a kernel snapshot and effective route without mutating networking.
func verifyInterface(peer netip.Addr, listener bool, iface net.Interface, kind string, addrs []net.Addr, route func(netip.Addr) (int, error)) error {
	if iface.Flags&net.FlagUp == 0 {
		return errors.New("WireGuard interface is down")
	}
	if kind != "wireguard" {
		return errors.New("configured interface is not kernel WireGuard")
	}
	hasIPv4 := false
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil && prefix.Addr().Is4() {
			hasIPv4 = true
			if prefix.Addr() == peer {
				return nil
			}
		}
	}
	if listener {
		return errors.New("listener address is not assigned to WireGuard")
	}
	if !hasIPv4 {
		return errors.New("WireGuard interface has no IPv4 address")
	}
	index, err := route(peer)
	if err != nil {
		return err
	}
	if index != iface.Index {
		return errors.New("plaintext peer is not directly routed through WireGuard")
	}
	return nil
}

// netlinkAttributes decodes bounded kernel TLVs including nested link metadata.
func netlinkAttributes(data []byte) (map[uint16][]byte, error) {
	attrs := make(map[uint16][]byte)
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated netlink attribute")
		}
		size := int(binary.NativeEndian.Uint16(data))
		kind := binary.NativeEndian.Uint16(data[2:]) & 0x3fff
		if size < 4 || size > len(data) {
			return nil, errors.New("invalid netlink attribute")
		}
		attrs[kind] = data[4:size]
		aligned := (size + 3) &^ 3
		if aligned > len(data) {
			if size == len(data) {
				break
			}
			return nil, errors.New("invalid netlink padding")
		}
		data = data[aligned:]
	}
	return attrs, nil
}

// interfaceKind reads the kernel's link kind without invoking privileged helpers.
func interfaceKind(index int) (string, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return "", err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return "", err
	}
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWLINK || len(m.Data) < 16 || int(binary.NativeEndian.Uint32(m.Data[4:8])) != index {
			continue
		}
		attrs, err := netlinkAttributes(m.Data[16:])
		if err != nil {
			return "", err
		}
		nested, err := netlinkAttributes(attrs[18])
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(nested[1]), "\x00"), nil
	}
	return "", errors.New("interface disappeared during validation")
}

// routeInterface asks the kernel for the effective route, including policy rules.
func routeInterface(peer netip.Addr) (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2}); err != nil {
		return 0, err
	}
	request := make([]byte, 36)
	binary.NativeEndian.PutUint32(request[0:4], 36)
	binary.NativeEndian.PutUint16(request[4:6], syscall.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[16], request[17] = syscall.AF_INET, 32
	binary.NativeEndian.PutUint16(request[28:30], 8)
	binary.NativeEndian.PutUint16(request[30:32], syscall.RTA_DST)
	raw := peer.As4()
	copy(request[32:], raw[:])
	if err := syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, err
	}
	response := make([]byte, 8192)
	n, from, err := syscall.Recvfrom(fd, response, 0)
	if err != nil {
		return 0, err
	}
	origin, ok := from.(*syscall.SockaddrNetlink)
	if !ok || origin.Pid != 0 {
		return 0, errors.New("untrusted route response")
	}
	messages, err := syscall.ParseNetlinkMessage(response[:n])
	if err != nil {
		return 0, err
	}
	for _, m := range messages {
		if m.Header.Seq != 1 || m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < 12 || m.Data[0] != syscall.AF_INET || m.Data[7] != syscall.RTN_UNICAST {
			continue
		}
		attrs, err := netlinkAttributes(m.Data[12:])
		if err != nil {
			return 0, err
		}
		out := attrs[syscall.RTA_OIF]
		if len(out) == 4 {
			return int(binary.NativeEndian.Uint32(out)), nil
		}
	}
	return 0, errors.New("plaintext peer has no supported unicast route")
}
