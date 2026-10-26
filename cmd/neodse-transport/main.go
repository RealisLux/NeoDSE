// File purpose: Starts the private NeoDSE transport switching service.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// The neodse-transport command routes authenticated WebSocket traffic between
// the controller and the displays without interpreting application messages.
package main

import (
	"github.com/RealisLux/NeoDSE/internal/cli"
	"github.com/RealisLux/NeoDSE/internal/transport"
)

var version = "dev"

// main runs the transport until SIGINT or SIGTERM.
func main() {
	cli.Main("neodse-transport", version, transport.Run)
}
