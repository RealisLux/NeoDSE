// File purpose: Verifies every durable state, transient command, and proxy-policy validation boundary.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package instruction

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/destination"
)

// TestDesiredStateValidation verifies desired state validation.
func TestDesiredStateValidation(t *testing.T) {
	valid := DesiredState{Content: ContentState{
		Mode: ContentPlaylist, URLs: []string{"https://example.net/a", "https://example.net/b"},
		ProxyAllow: []string{"https://Example.NET/path", "http://192.0.2.3/resource"},
		Interval:   30, StartAt: 1,
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("playlist state validation: %v", err)
	}
	targets, err := valid.Content.ProxyTargets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://192.0.2.3:80", "https://example.net:443"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("ProxyTargets = %#v, want %#v", targets, want)
	}
	single := DesiredState{Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net/a"}}}
	if err := single.Validate(); err != nil {
		t.Fatalf("single-page validation: %v", err)
	}
}

// TestDesiredStateValidationRejectsInvalidFields verifies desired state validation rejects invalid fields.
func TestDesiredStateValidationRejectsInvalidFields(t *testing.T) {
	tooManyURLs := make([]string, MaxPlaylistURLs+1)
	for index := range tooManyURLs {
		tooManyURLs[index] = "https://example.net"
	}
	tooManyProxyURLs := make([]string, MaxProxyAllowURLs+1)
	for index := range tooManyProxyURLs {
		tooManyProxyURLs[index] = "https://example.net"
	}
	tests := map[string]DesiredState{
		"content mode":         {Content: ContentState{Mode: "invalid"}},
		"default fields":       {Content: ContentState{Mode: ContentDefault, URLs: []string{"https://example.net"}}},
		"empty playlist":       {Content: ContentState{Mode: ContentPlaylist}},
		"bad URL":              {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"file:///tmp/a"}}},
		"bad proxy":            {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net"}, ProxyAllow: []string{"https://bad_host/"}}},
		"single-page interval": {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net"}, Interval: MinPlaylistInterval}},
		"missing interval":     {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net/a", "https://example.net/b"}}},
		"short interval":       {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net/a", "https://example.net/b"}, Interval: MinPlaylistInterval - 1}},
		"long interval":        {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net/a", "https://example.net/b"}, Interval: MaxPlaylistInterval + 1}},
		"start":                {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net"}, StartAt: -1}},
		"late start":           {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net"}, StartAt: 4102444801}},
		"URL count":            {Content: ContentState{Mode: ContentPlaylist, URLs: tooManyURLs}},
		"proxy count":          {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net"}, ProxyAllow: tooManyProxyURLs}},
		"credentials":          {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://user:secret@example.net"}}},
		"URL length":           {Content: ContentState{Mode: ContentPlaylist, URLs: []string{"https://example.net/" + strings.Repeat("a", 8192)}}},
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			if err := state.Validate(); err == nil {
				t.Fatal("invalid state was accepted")
			}
		})
	}
}

// TestPlaylistAcceptsMaximumPageCount keeps the documented page ceiling usable.
func TestPlaylistAcceptsMaximumPageCount(t *testing.T) {
	urls := make([]string, MaxPlaylistURLs)
	for index := range urls {
		urls[index] = fmt.Sprintf("https://example.net/page-%d", index)
	}
	state := DesiredState{Content: ContentState{Mode: ContentPlaylist, URLs: urls, Interval: MinPlaylistInterval}}
	if err := state.Validate(); err != nil {
		t.Fatalf("maximum playlist rejected: %v", err)
	}
}

// TestCommandValidation verifies command validation.
func TestCommandValidation(t *testing.T) {
	valid := []Command{
		NewCommand(DisplayCommand{Operation: DisplayOn}), NewCommand(DisplayCommand{Operation: DisplayOff}), NewCommand(DisplayCommand{Operation: DisplayActive}),
		NewCommand(DisplayCommand{Operation: DisplayMute}), NewCommand(DisplayCommand{Operation: DisplayVolumeUp}), NewCommand(DisplayCommand{Operation: DisplayVolumeDown}),
		NewCommand(DisplayVolumeCommand{Level: 0}), NewCommand(DisplayVolumeCommand{Level: 100}),
		NewCommand(SoundCommand{Profile: "info"}), NewCommand(SoundCommand{Profile: "warning"}), NewCommand(SoundCommand{Profile: "critical"}),
		NewCommand(SerialCommand{Command: SerialBeacon, State: PeripheralBlink, PeriodMS: 500}),
		NewCommand(BannerCommand{Message: "Maintenance soon", Severity: BannerWarning, DurationSeconds: 30}),
		NewCommand(ReloadCommand{}), NewCommand(RestartCommand{}), NewCommand(RebootCommand{}), NewCommand(ShutdownCommand{}),
	}
	for _, command := range valid {
		if err := command.Validate(); err != nil {
			t.Errorf("%#v validation: %v", command, err)
		}
	}
	invalid := []Command{
		{}, NewCommand(DisplayCommand{}), NewCommand(DisplayCommand{Operation: "unchanged"}), NewCommand(DisplayVolumeCommand{Level: 101}), NewCommand(SoundCommand{}),
		NewCommand(SerialCommand{}),
		NewCommand(SerialCommand{Command: SerialBeacon, State: PeripheralBlink, PeriodMS: 99}),
		NewCommand(SerialCommand{Command: SerialRelay, State: PeripheralOn, RelayID: 33}),
		NewCommand(BannerCommand{Message: " ", Severity: BannerInfo, DurationSeconds: 10}),
		NewCommand(BannerCommand{Message: "message", Severity: "unknown", DurationSeconds: 10}),
		NewCommand(BannerCommand{Message: "message", Severity: BannerInfo, DurationSeconds: 301}),
	}
	for _, command := range invalid {
		if err := command.Validate(); err == nil {
			t.Errorf("invalid command accepted: %#v", command)
		}
	}
}

// TestBannerMessageLength enforces character boundaries for ASCII and Unicode messages.
func TestBannerMessageLength(t *testing.T) {
	for _, character := range []string{"a", "é", "界", "😀"} {
		for _, length := range []int{256, 257} {
			message := strings.Repeat(character, length)
			command := NewCommand(BannerCommand{Message: BannerMessage(message), Severity: BannerInfo, DurationSeconds: 10})
			if err := command.Validate(); (err == nil) != (length == 256) {
				t.Errorf("character=%q length=%d: %v", character, length, err)
			}
		}
	}
	command := NewCommand(BannerCommand{Message: BannerMessage("invalid\xff"), Severity: BannerInfo, DurationSeconds: 10})
	if err := command.Validate(); err == nil {
		t.Fatal("invalid UTF-8 banner was accepted")
	}
}

// TestCommandJSONCodec verifies strict typed command encoding and decoding.
func TestCommandJSONCodec(t *testing.T) {
	want := NewCommand(BannerCommand{Message: "Maintenance soon", Severity: BannerWarning, DurationSeconds: 30})
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(encoded); got != `{"type":"banner","payload":{"message":"Maintenance soon","severity":"warning","duration_seconds":30}}` {
		t.Fatalf("canonical command JSON = %s", got)
	}
	var decoded Command
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != want {
		t.Fatalf("decoded command = %#v, want %#v", decoded, want)
	}
	for _, input := range []string{
		`{"type":"banner","message":"Maintenance soon","severity":"warning","duration_seconds":30}`,
		`{"type":"banner","payload":{"message":"hello","severity":"info","duration_seconds":10,"unknown":true}}`,
		`{"type":"banner","payload":null}`,
		`{"type":"unknown","payload":{}}`,
	} {
		var decoded Command
		if err := json.Unmarshal([]byte(input), &decoded); err == nil {
			t.Fatalf("invalid command accepted: %s", input)
		}
	}
}

// TestCommandCodecCoversEveryCommandType verifies that each permitted command
// retains its concrete payload through the strict wire boundary.
func TestCommandCodecCoversEveryCommandType(t *testing.T) {
	commands := []Command{
		NewCommand(DisplayCommand{Operation: DisplayMute}),
		NewCommand(DisplayVolumeCommand{Level: 42}),
		NewCommand(SoundCommand{Profile: "info"}),
		NewCommand(SerialCommand{Command: SerialStatus}),
		NewCommand(BannerCommand{Message: "notice", Severity: BannerInfo, DurationSeconds: 1}),
		NewCommand(ReloadCommand{}),
		NewCommand(RestartCommand{}),
		NewCommand(RebootCommand{}),
		NewCommand(ShutdownCommand{}),
	}
	for _, want := range commands {
		t.Run(string(want.Type()), func(t *testing.T) {
			if want.Payload() == nil {
				t.Fatal("command payload is missing")
			}
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got Command
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if got.Type() != want.Type() || !reflect.DeepEqual(got.Payload(), want.Payload()) {
				t.Fatalf("round trip = %#v (%s), want %#v (%s)", got.Payload(), got.Type(), want.Payload(), want.Type())
			}
		})
	}
	if (Command{}).Type() != "" {
		t.Fatal("empty command has a type")
	}
	if _, err := json.Marshal(Command{}); err == nil {
		t.Fatal("empty command was encoded")
	}
	var command *Command
	if err := command.UnmarshalJSON([]byte(`{"type":"display","payload":{"operation":"mute"}}`)); err == nil {
		t.Fatal("nil command destination was accepted")
	}
}

// TestURLValidationBoundaries verifies rejection paths used before proxy policy installation.
func TestURLValidationBoundaries(t *testing.T) {
	for _, rawURL := range []string{
		"relative/path", "ftp://example.net/resource", "https://example.net:0/",
		"https://example.net:70000/", "https://bad_host/", "https://-bad.example/",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := destination.FromURL(rawURL); err == nil {
				t.Fatalf("invalid URL accepted: %q", rawURL)
			}
		})
	}
	if targets, err := (ContentState{Mode: ContentDefault}).ProxyTargets(); err != nil || len(targets) != 0 {
		t.Fatalf("default targets = %#v, %v", targets, err)
	}
	for _, host := range []string{"", strings.Repeat("a", 254), "a..example", "bad_.example", "example.-bad"} {
		if destination.ValidDNSName(host) {
			t.Fatalf("invalid DNS name accepted: %q", host)
		}
	}
}

// TestProxyTargetsCanonicalizeAndDeduplicate verifies proxy targets canonicalize and deduplicate.
func TestProxyTargetsCanonicalizeAndDeduplicate(t *testing.T) {
	content := ContentState{
		Mode: ContentPlaylist, URLs: []string{"https://example.net/display"},
		ProxyAllow: []string{"https://assets.example.net/a", "HTTPS://Example.NET/b"},
	}
	targets, err := content.ProxyTargets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://assets.example.net:443", "https://example.net:443"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("ProxyTargets()=%#v, want %#v", targets, want)
	}
	content.ProxyAllow = []string{"http://[2001:db8::1]/"}
	if _, err := content.ProxyTargets(); err == nil {
		t.Fatal("IPv6 proxy target was accepted")
	}
}

// FuzzDesiredStateValidation exercises desired state validation with generated inputs.
func FuzzDesiredStateValidation(f *testing.F) {
	f.Add(`{"content":{"mode":"default"}}`)
	f.Add(`{"content":{"mode":"playlist","urls":["https://example.net"]}}`)
	f.Add(`{"content":[]}`)
	f.Fuzz(func(t *testing.T, input string) {
		var state DesiredState
		if json.Unmarshal([]byte(input), &state) != nil {
			return
		}
		if state.Validate() == nil {
			if _, err := json.Marshal(state); err != nil {
				t.Fatalf("validated state cannot be encoded: %v", err)
			}
		}
	})
}
