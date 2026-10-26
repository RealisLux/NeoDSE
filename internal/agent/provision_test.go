// File purpose: Verifies Go-owned agent provisioning defaults and strict configuration decoding.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/provisioning"
	"go.yaml.in/yaml/v3"
)

// TestUsageListsProvisionCommands keeps every documented root command
// discoverable from neodse-agent --help.
func TestUsageListsProvisionCommands(t *testing.T) {
	var output strings.Builder
	flags := flag.NewFlagSet("neodse-agent", flag.ContinueOnError)
	flags.SetOutput(&output)
	writeAgentUsage(flags)
	for _, name := range []string{"bootstrap", "provision", "remove-config"} {
		if !isProvisionCommand(name) || !strings.Contains(output.String(), "\n  "+name+" ") {
			t.Errorf("command %s is not dispatched or not listed in:\n%s", name, output.String())
		}
	}
	if isProvisionCommand("--config") {
		t.Fatal("a service flag was treated as a provisioning command")
	}
}

// TestCanceledProvisionCommandDoesNotAcquireAuthority verifies canceled CLI
// work cannot create or lock its privileged provisioning directory.
func TestCanceledProvisionCommandDoesNotAcquireAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	directory := filepath.Join(t.TempDir(), "wireguard")
	if err := runLockedProvisionCommand(ctx, []string{"provision"}, directory); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled provisioning error=%v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled provisioning created authority directory: %v", err)
	}
}

// TestAgentBootstrapConfig verifies clean and forced bootstraps use only Go-owned defaults.
func TestAgentBootstrapConfig(t *testing.T) {
	want := config.Agent{
		Agent: config.AgentSettings{
			ID:                 "display-01",
			WireGuardInterface: "neodse",
			UISocket:           "/run/neodse/ui.sock",
			LogLevel:           "info",
		},
		Serial: config.SerialSettings{Port: "/dev/ttyUSB0", Baudrate: 9600, ResponseTimeoutMS: 5000},
		Sound: config.SoundSettings{
			Info:     "/usr/share/neodse/info.wav",
			Warning:  "/usr/share/neodse/warning.wav",
			Critical: "/usr/share/neodse/critical.wav",
		},
		CEC: config.CECSettings{Enabled: false, Device: "/dev/cec0"},
	}
	if got := agentBootstrapConfig("display-01", "neodse", ""); !reflect.DeepEqual(got, want) {
		t.Fatalf("agent bootstrap configuration = %#v, want %#v", got, want)
	}
}

// TestBootstrapRejectsCollidingConfiguration checks the guard runs before key
// generation or either configuration write, even when replacement is requested.
func TestBootstrapRejectsCollidingConfiguration(t *testing.T) {
	err := bootstrapAgent([]string{"--agent-id", "display-01", "--config", "/etc/wireguard/neodse.conf", "--force"})
	if err == nil || !strings.Contains(err.Error(), "must use different files") {
		t.Fatalf("colliding bootstrap outputs: error=%v", err)
	}
}

// TestBootstrapPathAliases rejects parent-directory aliases without forbidding
// distinct names or files that an operator intentionally puts in one directory.
func TestBootstrapPathAliases(t *testing.T) {
	directory := t.TempDir()
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "neodse.conf")
	for _, test := range []struct {
		name, configuration string
		wantError           bool
	}{
		{"same path", target, true},
		{"cleaned path", directory + "/unused/../neodse.conf", true},
		{"directory alias", filepath.Join(alias, "neodse.conf"), true},
		{"different filename", filepath.Join(directory, "agent.yaml"), false},
		{"different directory", filepath.Join(directory, "other", "neodse.conf"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateBootstrapPaths(test.configuration, target); (err != nil) != test.wantError {
				t.Fatalf("validateBootstrapPaths(): error=%v, want error=%t", err, test.wantError)
			}
		})
	}
}

// TestProvisionCommandsRejectConcurrentChanges ensures every agent mutation shares one lock.
func TestProvisionCommandsRejectConcurrentChanges(t *testing.T) {
	directory := t.TempDir()
	lock, err := provisioning.LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for _, args := range [][]string{
		{"bootstrap", "--agent-id", "invalid!"},
		{"provision", "--instance", "../invalid"},
		{"remove-config", "--instance", "../invalid"},
	} {
		err := runLockedProvisionCommand(context.Background(), args, directory)
		if err == nil || !strings.Contains(err.Error(), "lock provisioning directory") {
			t.Fatalf("%s: got %v, want concurrency rejection before command execution", args[0], err)
		}
	}
}

// TestProvisionCommandFailureReleasesLock verifies a rejected command cannot block the next operator.
func TestProvisionCommandFailureReleasesLock(t *testing.T) {
	directory := t.TempDir()
	err := runLockedProvisionCommand(context.Background(), []string{"bootstrap", "--agent-id", "invalid!"}, directory)
	if err == nil || !strings.Contains(err.Error(), "--agent-id") {
		t.Fatalf("invalid bootstrap: got %v, want argument validation error", err)
	}
	lock, err := provisioning.LockDirectory(directory)
	if err != nil {
		t.Fatalf("failed command retained the provisioning lock: %v", err)
	}
	defer lock.Close()
}

// TestDecodeAgentConfigStrict verifies enrollment rejects unknown fields and extra documents.
func TestDecodeAgentConfigStrict(t *testing.T) {
	for name, contents := range map[string]string{
		"unknown field":      "agent:\n  id: display-01\n  unexpected: true\n",
		"multiple documents": "agent:\n  id: display-01\n---\nagent:\n  id: display-02\n",
	} {
		t.Run(name, func(t *testing.T) {
			var cfg config.Agent
			if err := config.DecodeYAML([]byte(contents), &cfg); err == nil {
				t.Fatal("invalid agent configuration was accepted")
			}
		})
	}
}

// TestBootstrapFriendlyNameRejectsInvalid verifies invalid labels fail before provisioning.
func TestBootstrapFriendlyNameRejectsInvalid(t *testing.T) {
	for _, name := range []string{strings.Repeat("é", 33), string([]byte{0xff})} {
		err := bootstrapAgent([]string{"--agent-id", "display-01", "--friendly-name", name})
		if err == nil || !strings.Contains(err.Error(), "--friendly-name") {
			t.Fatalf("bootstrap error = %v, want friendly-name validation error", err)
		}
	}
}

// TestBootstrapFriendlyNameYAML verifies optional labels survive configuration serialization.
func TestBootstrapFriendlyNameYAML(t *testing.T) {
	for _, name := range []string{"", "Écran accueil", strings.Repeat("é", 32)} {
		cfg := agentBootstrapConfig("display-01", "neodse", name)
		contents, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var decoded config.Agent
		if err := config.DecodeYAML(contents, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Agent.FriendlyName != name {
			t.Fatalf("friendly_name = %q, want %q", decoded.Agent.FriendlyName, name)
		}
	}
}

// TestBootstrapRejectsDisplayFlags keeps display customization outside enrollment.
func TestBootstrapRejectsDisplayFlags(t *testing.T) {
	for _, args := range [][]string{{"--scale", "2"}, {"--orientation", "90"}} {
		t.Run(strings.TrimPrefix(args[0], "--"), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "agent.yaml")
			displayPath := filepath.Join(dir, "display.env")
			displaySettings := []byte("NEODSE_WESTON_SCALE=2\nNEODSE_UI_CLOCK=hide\n")
			if err := os.WriteFile(displayPath, displaySettings, 0o600); err != nil {
				t.Fatal(err)
			}
			flags := append([]string{"--agent-id", "display-01", "--config", path, "--force"}, args...)
			err := bootstrapAgent(flags)
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("bootstrap %v error = %v, want unsupported flag error", args, err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsupported flags changed agent configuration: %v", err)
			}
			contents, err := os.ReadFile(displayPath)
			if err != nil || string(contents) != string(displaySettings) {
				t.Fatalf("unsupported flags changed display settings: %q, %v", contents, err)
			}
		})
	}
}
