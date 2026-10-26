// File purpose: Starts the NeoDSE explicit proxy with secure logging and cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// The neodse-proxy command is the explicit HTTP proxy for display web content.
// It forwards only destinations that the controller authorizes for the
// requesting display.
package main

import (
	"github.com/RealisLux/NeoDSE/internal/cli"
	"github.com/RealisLux/NeoDSE/internal/proxy"
)

var version = "dev"

// main runs the proxy until SIGINT or SIGTERM.
func main() {
	cli.Main("neodse-proxy", version, proxy.Run)
}
