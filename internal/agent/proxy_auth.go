// File purpose: Supplies session-bound proxy credentials held only in volatile UI state.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
)

// sendProxyAuthToUI replaces volatile WebKit proxy authentication data.
func (a *Agent) sendProxyAuthToUI() error {
	if strings.TrimSpace(a.config.Proxy.URL) == "" {
		return nil
	}
	a.sessionMu.Lock()
	key := a.sessionKeys[keyderivation.ProxyClient]
	token := hex.EncodeToString(key)
	a.sessionMu.Unlock()
	if len(key) != keyderivation.KeyBytes {
		return errors.New("proxy authentication requires an established transport session")
	}
	payload := uiProxyAuthRequest{
		Command: "proxy_auth",
		AgentID: a.config.Agent.ID,
		Token:   token,
	}
	return a.sendUICommand(payload)
}

// sendProxyConfigToUI supplies the mandatory loopback relay URL to WebKit.
func (a *Agent) sendProxyConfigToUI() error {
	if strings.TrimSpace(a.proxyRelayURL) == "" {
		return errors.New("local proxy relay is unavailable")
	}
	payload := uiProxyConfigRequest{
		Command: "proxy_config",
		URL:     a.proxyRelayURL,
	}
	return a.sendUICommand(payload)
}

// prepareUIForRemoteContent refreshes proxy data before remote state is applied.
func (a *Agent) prepareUIForRemoteContent() error {
	if err := a.sendProxyConfigToUI(); err != nil {
		return fmt.Errorf("send proxy configuration: %w", err)
	}
	if err := a.sendProxyAuthToUI(); err != nil {
		return fmt.Errorf("send proxy authentication: %w", err)
	}
	return nil
}
