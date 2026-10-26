// File purpose: Discovers WireGuard connectivity and reports volatile connection status to the UI.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"net"
	"os"
)

// firstIPv4Address returns the first usable IPv4 address assigned to an interface.
func firstIPv4Address(iface net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}

// isWireGuardInterface reports whether a network interface is the configured tunnel.
func (a *Agent) isWireGuardInterface(name string) bool {
	return name == a.config.Agent.WireGuardInterface
}

// localIPv4 returns the first non-loopback IPv4 address visible to the UI.
func (a *Agent) localIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || a.isWireGuardInterface(iface.Name) {
			continue
		}
		if ip := firstIPv4Address(iface); ip != "" {
			return ip
		}
	}
	return ""
}

// tunnelIPv4 returns the current IPv4 address of the configured WireGuard interface.
func (a *Agent) tunnelIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || !a.isWireGuardInterface(iface.Name) {
			continue
		}
		if ip := firstIPv4Address(iface); ip != "" {
			return ip
		}
	}
	return ""
}

// sendUIStatus publishes bounded volatile connectivity details to the UI.
func (a *Agent) sendUIStatus(stage, severity, message string) error {
	return a.sendUICommand(uiStatusRequest{
		Command: "status", AgentName: a.config.Agent.ID, FriendlyName: a.config.Agent.FriendlyName,
		AgentIP: a.localIPv4(), TunnelIP: a.tunnelIPv4(),
		Stage: stage, Severity: severity, Message: message,
	})
}

// updateControlConnectionStatus refreshes the UI indicator without persisting it.
func (a *Agent) updateControlConnectionStatus() {
	if _, err := os.Stat(a.config.Agent.UISocket); err != nil {
		return
	}
	if a.transportConnected.Load() {
		if err := a.sendUIStatus("waiting_for_playlist", "success", "Connected to the control server; waiting for playlist configuration"); err != nil {
			a.verbosef("! Could not update UI connection status: %v", err)
		}
		return
	}

	stage, severity, message := "connecting_control", "info", "Connecting to the control server"
	if a.transportConnectedOnce.Load() {
		stage, severity, message = "connection_lost", "critical", "Control server connection lost — reconnecting in the background"
	}
	if err := a.sendUIStatus(stage, severity, message); err != nil {
		a.verbosef("! Could not update UI connection status: %v", err)
	}
}
