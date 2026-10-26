// File purpose: Verifies authenticated protocol domains, field binding, malformed input handling, and frame parsing.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// TestSignatureVersionDomain verifies the supported protocol and its authentication namespace.
func TestSignatureVersionDomain(t *testing.T) {
	if Version != 1 {
		t.Fatalf("supported protocol=%d, want 1", Version)
	}
	key := []byte("01234567890123456789012345678901")
	message := Hello{Protocol: Version, AgentID: "display", Version: "1.0.0"}
	got, err := SignHello(message, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("neodse/protocol/v1\x00hello\x00"))
	_, _ = mac.Write(payload)
	if !Verify(got, hex.EncodeToString(mac.Sum(nil))) {
		t.Fatal("signature namespace differs from the advertised protocol version")
	}
}

// FuzzProtocolFrame exercises protocol frame with generated inputs.
func FuzzProtocolFrame(f *testing.F) {
	f.Add([]byte(fmt.Sprintf(`{"type":"command","payload":{"protocol":%d}}`, Version)))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		var frame Frame
		if Decode(input, &frame) == nil && len(frame.Payload) > 0 {
			var command Command
			_ = Decode(frame.Payload, &command)
		}
	})
}

// TestDecodeRejectsUnknownFieldsAndTrailingValues verifies decode rejects unknown fields and trailing values.
func TestDecodeRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`{"type":"command","unknown":true}`),
		[]byte(`{"type":"command"} {"type":"command"}`),
		[]byte(`{} {}`),
	} {
		var frame Frame
		if Decode(input, &frame) == nil {
			t.Fatalf("invalid protocol input was accepted: %s", input)
		}
	}
}

// TestDecodeAcceptsOneStrictValue verifies decode accepts one strict value.
func TestDecodeAcceptsOneStrictValue(t *testing.T) {
	var frame Frame
	if err := Decode([]byte("  {\"type\":\"command\"}\n"), &frame); err != nil || frame.Type != "command" {
		t.Fatalf("decoded frame=%#v error=%v", frame, err)
	}
}

// TestSignReportsUnsupportedValues verifies sign reports unsupported values.
func TestSignReportsUnsupportedValues(t *testing.T) {
	if _, err := sign("test", func() {}, []byte("key")); err == nil {
		t.Fatal("unsupported signed value did not return an error")
	}
}

// TestDesiredStateSignatureBindsSessionAndState verifies desired state signature binds session and state.
func TestDesiredStateSignatureBindsSessionAndState(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	message := DesiredState{
		Protocol: Version, SessionID: "session-1", Sequence: 1, EventID: "event-1",
		AgentID: "display-1", Timestamp: "2026-01-01T00:00:00Z", Generation: "generation-1", Revision: 1,
		State: instruction.DefaultState(),
	}
	signature, err := SignDesiredState(message, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(signature); err != nil {
		t.Fatal(err)
	}

	mutations := []func(*DesiredState){
		func(value *DesiredState) { value.SessionID = "session-2" },
		func(value *DesiredState) { value.Sequence++ },
		func(value *DesiredState) { value.AgentID = "display-2" },
		func(value *DesiredState) {
			value.State.Content.Mode = instruction.ContentPlaylist
			value.State.Content.URLs = []string{"https://example.test"}
		},
	}
	for index, mutate := range mutations {
		changed := message
		mutate(&changed)
		changedSignature, signErr := SignDesiredState(changed, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if Verify(signature, changedSignature) {
			t.Fatalf("mutation %d did not invalidate desired-state signature", index)
		}
	}
}

// TestCommandSignatureBindsExpiryAndPayload verifies command signature binds expiry and payload.
func TestCommandSignatureBindsExpiryAndPayload(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	message := Command{
		Protocol: Version, SessionID: "session-1", Sequence: 2, EventID: "event-2", AgentID: "display-1",
		Timestamp: "2026-01-01T00:00:00Z", ExpiresAt: "2026-01-01T00:01:00Z",
		Command: instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance soon", Severity: instruction.BannerWarning, DurationSeconds: 30}),
	}
	signature, err := SignCommand(message, key)
	if err != nil {
		t.Fatal(err)
	}
	message.ExpiresAt = "2026-01-01T00:02:00Z"
	changedExpiry, _ := SignCommand(message, key)
	if Verify(signature, changedExpiry) {
		t.Fatal("command signature remained valid after changing expiry")
	}
	message.ExpiresAt = "2026-01-01T00:01:00Z"
	mutations := []func(*Command){
		func(value *Command) {
			value.Command = instruction.NewCommand(instruction.BannerCommand{Message: "Changed", Severity: instruction.BannerWarning, DurationSeconds: 30})
		},
		func(value *Command) {
			value.Command = instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance soon", Severity: instruction.BannerCritical, DurationSeconds: 30})
		},
		func(value *Command) {
			value.Command = instruction.NewCommand(instruction.BannerCommand{Message: "Maintenance soon", Severity: instruction.BannerWarning, DurationSeconds: 31})
		},
	}
	for index, mutate := range mutations {
		changed := message
		mutate(&changed)
		changedPayload, signErr := SignCommand(changed, key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if Verify(signature, changedPayload) {
			t.Fatalf("banner payload mutation %d did not invalidate command signature", index)
		}
	}
}

// TestSignatureDomainsPreventCrossTypeSubstitution checks each public signer
// against its specified domain over that message's unsigned payload. Comparing tags
// of different message shapes alone would not detect a shared or missing domain.
func TestSignatureDomainsPreventCrossTypeSubstitution(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	command := instruction.NewCommand(instruction.RestartCommand{})
	for _, test := range []struct {
		domain string
		value  any
		sign   func() (string, error)
	}{
		{"hello", Hello{Protocol: Version}, func() (string, error) {
			return SignHello(Hello{Protocol: Version, Signature: "discard-me"}, key)
		}},
		{"welcome", Welcome{Protocol: Version}, func() (string, error) {
			return SignWelcome(Welcome{Protocol: Version, Signature: "discard-me"}, key)
		}},
		{"desired-state", DesiredState{Protocol: Version}, func() (string, error) {
			return SignDesiredState(DesiredState{Protocol: Version, Signature: "discard-me"}, key)
		}},
		{"command", Command{Protocol: Version, Command: command}, func() (string, error) {
			return SignCommand(Command{Protocol: Version, Command: command, Signature: "discard-me"}, key)
		}},
		{"status", Status{Protocol: Version}, func() (string, error) {
			return SignStatus(Status{Protocol: Version, Signature: "discard-me"}, key)
		}},
		{"receipt", Receipt{Protocol: Version}, func() (string, error) {
			return SignReceipt(Receipt{Protocol: Version, Signature: "discard-me"}, key)
		}},
		{"display", Display{Protocol: Version}, func() (string, error) {
			return SignDisplay(Display{Protocol: Version, Signature: "discard-me"}, key)
		}},
	} {
		t.Run(test.domain, func(t *testing.T) {
			signature, err := test.sign()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte("neodse/protocol/v1\x00" + test.domain + "\x00"))
			_, _ = mac.Write(payload)
			if signature != hex.EncodeToString(mac.Sum(nil)) {
				t.Fatal("signature does not bind the specified domain and unsigned payload")
			}
		})
	}
}

// TestMalformedSignatureVerification rejects invalid tag lengths and encoding.
func TestMalformedSignatureVerification(t *testing.T) {
	for _, malformed := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 66)} {
		if Verify(malformed, strings.Repeat("a", 64)) {
			t.Fatalf("malformed signature %q was accepted", malformed)
		}
	}
}
