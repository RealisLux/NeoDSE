// File purpose: Rejects authenticated image frames that could exhaust the dashboard decoder.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/jpeg"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// displayGeometryJPEG changes only an encoded JPEG's dimensions without allocating its claimed image.
func displayGeometryJPEG(t *testing.T, width, height uint16) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 8, 6)), nil); err != nil {
		t.Fatal(err)
	}
	data := encoded.Bytes()
	for index := 2; index+9 < len(data); index++ {
		if data[index] == 0xff && data[index+1] == 0xc0 {
			binary.BigEndian.PutUint16(data[index+5:index+7], height)
			binary.BigEndian.PutUint16(data[index+7:index+9], width)
			return data
		}
	}
	t.Fatal("fixture JPEG has no baseline frame header")
	return nil
}

// TestAuthenticatedDisplayFrameGeometry validates image geometry before forwarding or advancing sequence.
func TestAuthenticatedDisplayFrameGeometry(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		data     func(*testing.T) []byte
		accepted bool
	}{
		{"ordinary JPEG", func(t *testing.T) []byte { return displayGeometryJPEG(t, 8, 6) }, true},
		{"maximum pixel area", func(t *testing.T) []byte { return displayGeometryJPEG(t, 4096, 4096) }, true},
		{"wide bounded image", func(t *testing.T) []byte { return displayGeometryJPEG(t, 8192, 2048) }, true},
		{"area above maximum", func(t *testing.T) []byte { return displayGeometryJPEG(t, 4097, 4096) }, false},
		{"tiny JPEG claiming huge image", func(t *testing.T) []byte { return displayGeometryJPEG(t, 65535, 65535) }, false},
		{"non JPEG", func(*testing.T) []byte { return []byte("not an image") }, false},
		{"truncated header", func(t *testing.T) []byte { return displayGeometryJPEG(t, 8, 6)[:12] }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
			session := server.sessions["display"]
			relay := newDisplayRelay("display", strings.Repeat("a", 32), session)
			server.displayRelays[relay.streamID] = relay
			message := protocol.Display{Protocol: protocol.Version, AgentID: "display", SessionID: session.id,
				Sequence: 1, StreamID: relay.streamID, Action: "data", Data: scenario.data(t),
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
			var err error
			message.Signature, err = protocol.SignDisplay(message, session.keys[keyderivation.TransportDisplay])
			if err != nil {
				t.Fatal(err)
			}
			err = server.handleDisplayFrame("display", mustJSON(t, message))
			if (err == nil) != scenario.accepted {
				t.Fatalf("accepted=%t, want=%t; compressed frame bytes=%d error=%v", err == nil, scenario.accepted, len(message.Data), err)
			}
			if scenario.accepted {
				if len(relay.frames) != 1 || session.lastReceived != 1 {
					t.Fatal("valid frame was not forwarded exactly once")
				}
			} else {
				if err.Error() != "invalid JPEG header or dimensions" {
					t.Fatalf("missing image rejection reason: %v", err)
				}
				if len(relay.frames) != 0 || session.lastReceived != 0 {
					t.Fatal("invalid image reached the viewer or advanced protocol state")
				}
			}
		})
	}
}
