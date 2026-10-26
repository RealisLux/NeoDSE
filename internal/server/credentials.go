// File purpose: Validates and persists provisioned agent credentials through the concrete store.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
)

// createAgentCredential validates identifiers, secret shape and the enrolled
// tunnel address before persistence.
func (s *Server) createAgentCredential(agentID, psk, tunnelAddress string, replace bool) error {
	if !identity.ValidAgentID(agentID) {
		return fmt.Errorf("invalid agent ID %q", agentID)
	}
	if _, err := keyderivation.ParsePSK(psk); err != nil {
		return err
	}
	address, err := netip.ParseAddr(tunnelAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return errors.New("agent tunnel address must be a private IPv4 address")
	}
	storeContext, cancel := boundedStoreContext()
	defer cancel()
	return s.store.PutAgent(storeContext, agentID, psk, address.String(), replace, time.Now().UTC())
}

// deleteAgentCredential removes one agent and its cascading operational records.
func (s *Server) deleteAgentCredential(agentID string) error {
	storeContext, cancel := boundedStoreContext()
	defer cancel()
	return s.store.RemoveAgent(storeContext, agentID)
}
