// File purpose: Checks compositor configuration and renderer session startup.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRendererSessionEnvironment checks the pre-start helper publishes the user
// runtime directory and bus together without accepting a failed activation update.
func TestRendererSessionEnvironment(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts/neodse-session-environment.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name                     string
		activationExit, wantExit int
	}{
		{"fresh environment", 0, 0},
		{"stale environment", 0, 0},
		{"unsafe file permissions", 0, 0},
		{"activation failure", 71, 71},
		{"write failure", 0, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			updater := filepath.Join(directory, "update-environment")
			renderer := filepath.Join(directory, "renderer")
			for path, program := range map[string]string{
				updater:  "#!/bin/sh\nprintf 'activation runtime=%s bus=%s args=%s\\n' \"$XDG_RUNTIME_DIR\" \"$DBUS_SESSION_BUS_ADDRESS\" \"$*\"\nexit \"$ACTIVATION_EXIT\"\n",
				renderer: "#!/bin/sh\nprintf 'unexpected renderer launch\\n'\nexit 99\n",
			} {
				if err := os.WriteFile(path, []byte(program), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			environment := filepath.Join(directory, "session.env")
			const stale = "XDG_RUNTIME_DIR=/stale/runtime\nDBUS_SESSION_BUS_ADDRESS=unix:path=/stale/bus\n"
			if scenario.name == "stale environment" || scenario.name == "activation failure" || scenario.name == "unsafe file permissions" {
				if err := os.WriteFile(environment, []byte(stale), 0o600); err != nil {
					t.Fatal(err)
				}
				if scenario.name == "unsafe file permissions" {
					if err := os.Chmod(environment, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			} else if scenario.name == "write failure" {
				if err := os.Mkdir(environment, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			helper := filepath.Join(directory, "prepare.sh")
			program := strings.NewReplacer("/usr/bin/dbus-update-activation-environment", updater, "/usr/bin/neodse-ui", renderer).Replace(string(source))
			if err := os.WriteFile(helper, []byte(program), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", helper)
			command.Env = append(os.Environ(), "RUNTIME_DIRECTORY="+directory, "XDG_RUNTIME_DIR=/unexpected/runtime",
				"DBUS_SESSION_BUS_ADDRESS=unix:path=/unexpected/bus", fmt.Sprintf("ACTIVATION_EXIT=%d", scenario.activationExit))
			output, err := command.CombinedOutput()
			if command.ProcessState == nil || command.ProcessState.ExitCode() != scenario.wantExit {
				t.Fatalf("exit=%v, want=%d: %v\n%s", command.ProcessState, scenario.wantExit, err, output)
			}
			bus := fmt.Sprintf("unix:path=/run/user/%d/bus", os.Getuid())
			wantOutput := fmt.Sprintf("activation runtime=/run/user/%d bus=%s args=--systemd WAYLAND_DISPLAY=wayland-0 XDG_SESSION_TYPE=wayland\n", os.Getuid(), bus)
			if !strings.HasPrefix(string(output), wantOutput) || strings.Contains(string(output), "unexpected renderer launch") {
				t.Fatalf("unexpected pre-start behavior: %s", output)
			}
			leftovers, err := filepath.Glob(environment + ".*")
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("temporary environment files were not cleaned up: %v, %v", leftovers, err)
			}
			if scenario.name == "write failure" {
				return
			}
			contents, err := os.ReadFile(environment)
			if err != nil {
				t.Fatal(err)
			}
			wantEnvironment := fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d\nDBUS_SESSION_BUS_ADDRESS=%s\n", os.Getuid(), bus)
			if scenario.activationExit != 0 {
				wantEnvironment = stale
			}
			if string(contents) != wantEnvironment {
				t.Fatalf("environment=%q, want=%q", contents, wantEnvironment)
			}
			info, err := os.Stat(environment)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("session environment must remain private: %v, %v", info, err)
			}
		})
	}
}

// TestWestonConfigFollowsConnectedOutput checks that each start selects a
// connected connector without requiring EDID or fixing a video mode.
func TestWestonConfigFollowsConnectedOutput(t *testing.T) {
	root := repositoryRoot(t)
	dir := t.TempDir()
	connector := filepath.Join(dir, "drm", "card0-HDMI-A-1")
	if err := os.MkdirAll(connector, 0o755); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(connector, "status")
	if err := os.WriteFile(status, []byte("connected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "weston.ini")
	generate := func() ([]byte, error) {
		command := exec.Command("bash", filepath.Join(root, "scripts/neodse-weston-config.sh"))
		command.Env = append(os.Environ(), "NEODSE_DRM_SYSFS_ROOT="+filepath.Join(dir, "drm"), "NEODSE_WESTON_CONFIG_PATH="+config, "NEODSE_WESTON_SCALE=1", "NEODSE_WESTON_TRANSFORM=normal")
		return command.CombinedOutput()
	}
	connected := func() bool {
		command := exec.Command("bash", filepath.Join(root, "scripts/neodse-drm-connected.sh"))
		command.Env = append(os.Environ(), "NEODSE_DRM_SYSFS_ROOT="+filepath.Join(dir, "drm"))
		return command.Run() == nil
	}
	if !connected() {
		t.Fatal("connected display was not detected")
	}
	if output, err := generate(); err != nil {
		t.Fatalf("generate Weston config: %v: %s", err, output)
	}
	content, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"name=HDMI-A-1\nforce-on=true\n",
		"scale=1\ntransform=normal\n",
		"name=vnc\nmirror-of=HDMI-A-1\n",
	} {
		if !strings.Contains(string(content), expected) {
			t.Fatalf("missing %q in generated config:\n%s", expected, content)
		}
	}
	if strings.Contains(string(content), "mode=") {
		t.Fatalf("unexpected fixed mode in generated config:\n%s", content)
	}
	if err := os.WriteFile(status, []byte("disconnected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if connected() {
		t.Fatal("disconnected display was reported ready")
	}
	if output, err := generate(); err == nil || !strings.Contains(string(output), "No connected DRM output") {
		t.Fatalf("expected clear failure without a connected output, got %v: %s", err, output)
	}
	other := filepath.Join(dir, "drm", "card0-HDMI-A-2")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "status"), []byte("connected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !connected() {
		t.Fatal("newly connected display was not detected")
	}
	if output, err := generate(); err != nil {
		t.Fatalf("select newly connected output on restart: %v: %s", err, output)
	}
	switched, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(switched), "name=HDMI-A-2\nforce-on=true\n") || !strings.Contains(string(switched), "mirror-of=HDMI-A-2\n") {
		t.Fatalf("mirror did not follow newly connected output on restart:\n%s", switched)
	}
}

// TestWestonConfigDisplaySettings checks operator settings reach the physical output.
func TestWestonConfigDisplaySettings(t *testing.T) {
	root := repositoryRoot(t)
	dir := t.TempDir()
	connector := filepath.Join(dir, "drm", "card0-HDMI-A-1")
	if err := os.MkdirAll(connector, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(connector, "status"), []byte("connected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "weston.ini")
	generate := func(settings ...string) ([]byte, error) {
		command := exec.Command("bash", filepath.Join(root, "scripts/neodse-weston-config.sh"))
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "NEODSE_WESTON_SCALE=") && !strings.HasPrefix(value, "NEODSE_WESTON_TRANSFORM=") {
				command.Env = append(command.Env, value)
			}
		}
		command.Env = append(command.Env, "NEODSE_DRM_SYSFS_ROOT="+filepath.Join(dir, "drm"), "NEODSE_WESTON_CONFIG_PATH="+path)
		command.Env = append(command.Env, settings...)
		return command.CombinedOutput()
	}
	if output, err := generate(); err != nil {
		t.Fatalf("generate defaults: %v: %s", err, output)
	}
	defaults, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(defaults), "scale=1\ntransform=normal\n") {
		t.Fatalf("missing defaults: %v: %s", err, defaults)
	}
	for _, orientation := range []string{"normal", "rotate-90", "rotate-180", "rotate-270"} {
		if output, err := generate("NEODSE_WESTON_SCALE=2", "NEODSE_WESTON_TRANSFORM="+orientation); err != nil {
			t.Fatalf("generate scaled output: %v: %s", err, output)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "name=HDMI-A-1\nforce-on=true\nscale=2\ntransform=" + orientation + "\n[output]\nname=vnc\nmirror-of=HDMI-A-1\nresizeable=false\n"
		if !strings.Contains(string(contents), want) || strings.Contains(string(contents), "mode=") {
			t.Fatalf("unexpected generated output:\n%s", contents)
		}
		if output, err := generate("NEODSE_WESTON_SCALE=2", "NEODSE_WESTON_TRANSFORM="+orientation); err != nil {
			t.Fatalf("regenerate output: %v: %s", err, output)
		}
		regenerated, err := os.ReadFile(path)
		if err != nil || string(regenerated) != string(contents) {
			t.Fatalf("restart changed output configuration: %v: %s", err, regenerated)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{
		"NEODSE_WESTON_SCALE=0", "NEODSE_WESTON_SCALE=-1", "NEODSE_WESTON_SCALE=1.5", "NEODSE_WESTON_SCALE=02",
		"NEODSE_WESTON_SCALE=2147483648", "NEODSE_WESTON_SCALE=999999999999999999999", "NEODSE_WESTON_SCALE=", "NEODSE_WESTON_SCALE=1+1",
		"NEODSE_WESTON_TRANSFORM=90", "NEODSE_WESTON_TRANSFORM=", "NEODSE_WESTON_TRANSFORM=normal\nmode=off",
		"NEODSE_WESTON_TRANSFORM=flipped", "NEODSE_WESTON_TRANSFORM=flipped-rotate-90",
		"NEODSE_WESTON_TRANSFORM=flipped-rotate-180", "NEODSE_WESTON_TRANSFORM=flipped-rotate-270",
	} {
		if output, err := generate(setting); err == nil {
			t.Fatalf("accepted invalid setting %q: %s", setting, output)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(before) {
			t.Fatalf("invalid setting replaced working configuration: %v: %s", err, after)
		}
	}
	requireFileText(t, root, "systemd/neodse-weston.service", "EnvironmentFile=-/etc/neodse/display.env")
}
