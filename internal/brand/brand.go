// File purpose: Embeds the canonical NeoDSE brand assets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package brand exposes the canonical NeoDSE brand assets.
package brand

import _ "embed"

// LogoPNG contains the canonical NeoDSE logo.
//
//go:embed logo.png
var LogoPNG []byte
