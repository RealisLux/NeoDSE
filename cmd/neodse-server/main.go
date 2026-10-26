// File purpose: Starts the NeoDSE controller with secure logging and cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// The neodse-server command is the controller. It serves the management API
// and dashboard, owns the encrypted database, and provides the root
// maintenance commands.
package main

import (
	"github.com/RealisLux/NeoDSE/internal/cli"
	"github.com/RealisLux/NeoDSE/internal/server"
)

var version = "dev"

// main runs the controller until SIGINT or SIGTERM.
func main() {
	cli.Main("neodse-server", version, server.Run)
}
