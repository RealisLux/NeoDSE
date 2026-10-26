// File purpose: Verifies display control authentication before any state mutation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// TestDisplayFreshnessAndShape rejects malformed or stale authenticated controls.
func TestDisplayFreshnessAndShape(t *testing.T) {
	for _, mode := range []string{"stale", "future", "unexpected-data", "unexpected-error", "invalid-action", "bad-signature", "bad-session", "bad-sequence", "bad-time", "bad-protocol", "bad-agent", "bad-stream"} {
		t.Run(mode, func(t *testing.T) {
			a := &Agent{sessionID: "session", sessionKeys: map[keyderivation.Purpose][]byte{keyderivation.TransportDisplay: []byte("test-key")}, config: config.Agent{}}
			a.config.Agent.ID = "display"
			m := protocol.Display{Protocol: protocol.Version, AgentID: "display", SessionID: "session", Sequence: 1, StreamID: strings.Repeat("a", 32), Action: "prepare", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
			switch mode {
			case "stale":
				m.Timestamp = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			case "future":
				m.Timestamp = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "unexpected-data":
				m.Data = []byte{1}
			case "unexpected-error":
				m.Error = "not allowed"
			case "bad-session":
				m.SessionID = "other"
			case "bad-sequence":
				m.Sequence = 2
			case "bad-time":
				m.Timestamp = "invalid"
			case "bad-protocol":
				m.Protocol = protocol.Version + 1
			case "bad-agent":
				m.AgentID = "other"
			case "bad-stream":
				m.StreamID = "short"
			case "invalid-action":
				m.Action = "invalid"
			}
			m.Signature, _ = protocol.SignDisplay(m, a.sessionKeys[keyderivation.TransportDisplay])
			if mode == "bad-signature" {
				m.Signature = "invalid"
			}
			if a.verifyDisplay(m) {
				t.Errorf("accepted %s and advanced inbound sequence=%d", mode, a.lastInboundSequence)
			}
			if a.lastInboundSequence != 0 {
				t.Fatal("rejected message advanced sequence")
			}
			m = protocol.Display{Protocol: protocol.Version, AgentID: "display", SessionID: "session", Sequence: 1, StreamID: strings.Repeat("a", 32), Action: "prepare", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
			m.Signature, _ = protocol.SignDisplay(m, a.sessionKeys[keyderivation.TransportDisplay])
			if !a.verifyDisplay(m) || a.lastInboundSequence != 1 {
				t.Fatal("valid command rejected after invalid command")
			}
		})
	}
}
