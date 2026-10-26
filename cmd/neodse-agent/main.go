// File purpose: Starts the NeoDSE display agent with secure logging and cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// The neodse-agent command runs on each display. It keeps the authenticated
// controller session, drives the renderer and HDMI-CEC, and relays web content
// to the explicit proxy.
package main

import (
	"github.com/RealisLux/NeoDSE/internal/agent"
	"github.com/RealisLux/NeoDSE/internal/cli"
)

var version = "dev"

// main runs the agent until SIGINT or SIGTERM.
func main() {
	cli.Main("neodse-agent", version, agent.Run)
}
