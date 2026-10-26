// File purpose: Derives the credential shared only by the controller and its explicit proxy.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package proxyauth derives the internal credential that authenticates the
// explicit proxy to the controller. Display proxy credentials are the
// session keys that the transport handshake derives for each connection.
package proxyauth

import "github.com/RealisLux/NeoDSE/internal/keyderivation"

// InternalToken derives the credential shared only by the server and proxy.
func InternalToken(pskValue string) (string, error) {
	psk, err := keyderivation.ParsePSK(pskValue)
	if err != nil {
		return "", err
	}
	return keyderivation.DeriveHex(psk, "control-plane", keyderivation.ProxyInternal)
}
