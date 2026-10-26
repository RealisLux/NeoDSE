// File purpose: Verifies publication targets, workflow pins and fleet evidence as structured contracts.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestReleaseMatrixMatchesAssetValidator rejects missing, duplicated or unsupported targets despite valid YAML formatting.
func TestReleaseMatrixMatchesAssetValidator(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []struct{ Component, Target, Arch, Format string }
				}
			}
		}
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	var matrix []string
	for _, target := range workflow.Jobs["packages"].Strategy.Matrix.Include {
		matrix = append(matrix, fmt.Sprintf("NeoDSE-%s_%s_%s_%s.%s", target.Component, releaseFixtureVersion, target.Target, target.Arch, target.Format))
	}
	expected := append([]string(nil), releaseFixturePackages...)
	sort.Strings(expected)
	sort.Strings(matrix)
	if !reflect.DeepEqual(matrix, expected) {
		t.Fatalf("release matrix=%v, want %v", matrix, expected)
	}
	output, err := exec.Command("python3", filepath.Join(root, "scripts", "check-release-assets.py"), "--list-packages", "--version", releaseFixtureVersion).CombinedOutput()
	if err != nil {
		t.Fatalf("asset validator: %v: %s", err, output)
	}
	if names := strings.Fields(string(output)); !reflect.DeepEqual(names, expected) {
		t.Fatalf("publication matrix=%v, want %v", names, expected)
	}
}

// TestReleaseAssetVersions accepts stable/prerelease/build versions and rejects unsafe or ambiguous names.
func TestReleaseAssetVersions(t *testing.T) {
	validator := filepath.Join(repositoryRoot(t), "scripts", "check-release-assets.py")
	for _, version := range []string{"1.0.0", releaseFixtureVersion, "1.0.0+build.7", "1.0.0-rc.1+build.7"} {
		t.Run(version, func(t *testing.T) {
			directory := t.TempDir()
			writeReleaseFixture(t, directory, "draft", version)
			output, err := exec.Command("python3", validator, directory, "--version", version, "--manifest").CombinedOutput()
			if err != nil {
				t.Fatalf("versioned evidence rejected: %v: %s", err, output)
			}
			output, err = exec.Command("python3", validator, directory, "--version", "9.9.9", "--manifest").CombinedOutput()
			if err == nil {
				t.Fatalf("evidence from another release accepted: %s", output)
			}
		})
	}
	for _, version := range []string{"v1.0.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+", "../1.0.0", "1.0.0/other", "1.0.0\nother"} {
		if output, err := exec.Command("python3", validator, "--list-packages", "--version", version).CombinedOutput(); err == nil {
			t.Errorf("invalid version %q accepted: %s", version, output)
		}
	}
}

// TestReleaseWorkflowAssetNames runs the workflow selection script against tag and manual-build identities.
func TestReleaseWorkflowAssetNames(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct{ Steps []struct{ Name, Run string } }
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range workflow.Jobs["packages"].Steps {
		if step.Name == "Select version and asset name" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("package version selection is missing")
	}
	for _, component := range []string{"client", "server"} {
		for _, format := range []string{"deb", "rpm"} {
			selected := strings.NewReplacer("${{ matrix.component }}", component, "${{ matrix.format }}", format,
				"${{ matrix.target }}", "target", "${{ matrix.arch }}", "amd64").Replace(script)
			for _, version := range []string{"1.0.0", releaseFixtureVersion, "1.0.0+build.7", "0.0.42"} {
				t.Run(component+"/"+format+"/"+version, func(t *testing.T) {
					refType := "tag"
					if version == "0.0.42" {
						refType = "branch"
					}
					outputPath := filepath.Join(t.TempDir(), "outputs")
					command := exec.Command("bash", "-euo", "pipefail", "-c", selected)
					command.Env = append(os.Environ(), "GITHUB_REF_TYPE="+refType, "GITHUB_REF_NAME=v"+version,
						"GITHUB_RUN_NUMBER=42", "GITHUB_OUTPUT="+outputPath)
					if output, err := command.CombinedOutput(); err != nil {
						t.Fatalf("workflow selection: %v: %s", err, output)
					}
					output, err := os.ReadFile(outputPath)
					want := fmt.Sprintf("version=%s\nname=NeoDSE-%s_%s_target_amd64.%s\n", version, component, version, format)
					if err != nil || string(output) != want {
						t.Fatalf("workflow outputs=%q, want=%q: %v", output, want, err)
					}
				})
			}
		}
	}
}

// TestClientRequiresWebKitRuntime checks that the client uses the distribution's runtime package.
func TestClientRequiresWebKitRuntime(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "packaging", "nfpm-client.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Depends []string }
	if err := yaml.Unmarshal(source, &manifest); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(manifest.Depends, "libwebkitgtk-6.0-4") {
		return
	}
	t.Fatalf("client must require the distribution WebKitGTK runtime without a version floor: %v", manifest.Depends)
}

// TestCodeQLBuildsEveryGoCommand prevents partial manual extraction from silently
// omitting a separately packaged executable such as the PAM helper.
func TestCodeQLBuildsEveryGoCommand(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct{ Steps []struct{ If, Run string } }
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	commands := make(map[string]bool)
	for _, step := range workflow.Jobs["analyze"].Steps {
		if step.If != "matrix.language == 'go'" || step.Run == "" {
			continue
		}
		arguments := strings.Fields(step.Run)
		if len(arguments) == 0 || arguments[0] != "make" {
			t.Fatalf("inspect the CodeQL Go build command: %q", step.Run)
		}
		command := exec.Command("make", append([]string{"--dry-run"}, arguments[1:]...)...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("CodeQL build plan: %v: %s", err, output)
		}
		for argument := range strings.FieldsSeq(string(output)) {
			if strings.HasPrefix(argument, "./cmd/") {
				commands[filepath.Clean(argument)] = true
			}
		}
	}
	entrypoints, err := filepath.Glob(filepath.Join(root, "cmd", "*", "main.go"))
	if err != nil || len(entrypoints) == 0 {
		t.Fatalf("find command entrypoints: %v", err)
	}
	for _, entrypoint := range entrypoints {
		path, err := filepath.Rel(root, filepath.Dir(entrypoint))
		if err != nil {
			t.Fatal(err)
		}
		if !commands[path] {
			t.Errorf("CodeQL manual build omits %s", path)
		}
	}
}

// TestPackagesDeclareRequiredHostDependencies prevents clean-host installations
// from relying on undeclared CA roots, routing tools or account-creation tools.
func TestPackagesDeclareRequiredHostDependencies(t *testing.T) {
	for _, target := range []struct{ manifest, routing, accounts string }{
		{"nfpm-client.yaml", "iproute2", "passwd"},
		{"nfpm-server-deb.yaml", "iproute2", "passwd"},
		{"nfpm-server-rpm.yaml", "iproute", "shadow-utils"},
	} {
		t.Run(target.manifest, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "packaging", target.manifest))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Depends []string
				Deb     struct{ Predepends []string }
			}
			if err := yaml.Unmarshal(source, &manifest); err != nil {
				t.Fatal(err)
			}
			for _, dependency := range []string{"ca-certificates", target.routing, "systemd", "wireguard-tools"} {
				if !slices.Contains(manifest.Depends, dependency) {
					t.Errorf("package must require host runtime dependency %q", dependency)
				}
			}
			accounts := manifest.Depends
			if strings.HasSuffix(target.manifest, "deb.yaml") || target.manifest == "nfpm-client.yaml" {
				// Debian preinst can assume only Essential and Pre-Depends packages.
				accounts = manifest.Deb.Predepends
			}
			if !slices.Contains(accounts, target.accounts) {
				t.Errorf("package must declare account-creation dependency %q before preinstall", target.accounts)
			}
		})
	}
}

// TestQualityGateRetainsBothFleetModes protects production memory checks and independent race evidence.
func TestQualityGateRetainsBothFleetModes(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "quality.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses, Run, If   string
				ContinueOnError bool `yaml:"continue-on-error"`
				Env             map[string]string
				With            map[string]any
			}
		}
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	evidence := make(map[string]bool)
	type fleetEvidence struct{ results, log string }
	modes := make(map[string]fleetEvidence)
	for _, step := range workflow.Jobs["go-security"].Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.If == "always()" {
			paths, _ := step.With["path"].(string)
			for path := range strings.FieldsSeq(paths) {
				evidence[path] = true
			}
		}
		fields := strings.Fields(step.Run)
		if len(fields) < 2 || fields[0] != "make" || fields[1] != "integration" {
			continue
		}
		if step.If != "" || step.ContinueOnError {
			t.Fatal("both fleet phases must be unconditional required checks")
		}
		arguments := make(map[string]string)
		var logPath string
		for index := 2; index < len(fields); index++ {
			field := fields[index]
			if field == "|" {
				if index+2 < len(fields) && fields[index+1] == "tee" {
					logPath = fields[index+2]
				}
				break
			}
			if key, value, ok := strings.Cut(field, "="); ok {
				arguments[key] = value
			}
		}
		mode := arguments["INTEGRATION_RACE"]
		if (mode != "true" && mode != "false") || modes[mode].results != "" {
			t.Fatalf("fleet phases must explicitly select each race mode once: %q", mode)
		}
		if arguments["INTEGRATION_DURATION"] != "10m" || arguments["INTEGRATION_TIMEOUT"] != "15m" {
			t.Fatal("both fleet phases must complete the ten-minute workload within fifteen minutes")
		}
		buildDirectory := arguments["BUILD_DIR"]
		if buildDirectory == "" {
			buildDirectory = "build"
		}
		if mode == "false" && (step.Env["CGO_ENABLED"] != "0" || buildDirectory != "build/fleet-production") {
			t.Fatal("production fleet phase must disable CGO and retain its own build directory")
		}
		if logPath == "" {
			t.Fatal("each fleet phase must retain its console log")
		}
		modes[mode] = fleetEvidence{results: buildDirectory + "/fleet-tests.jsonl", log: logPath}
	}
	if modes["true"].results == "" || modes["false"].results == "" || modes["true"].results == modes["false"].results || modes["true"].log == modes["false"].log {
		t.Fatalf("race and production fleet phases must retain separate evidence: %v", modes)
	}
	for _, mode := range modes {
		for _, path := range []string{mode.results, mode.log} {
			if !evidence[path] {
				t.Errorf("fleet evidence must be uploaded even after failure: %s", path)
			}
		}
	}
}

// TestWorkflowReferencesArePinned checks parsed values, including quoted and flow-style YAML references.
func TestWorkflowReferencesArePinned(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(repositoryRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	commit := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	image := regexp.MustCompile(`^[^@]+@sha256:[0-9a-f]{64}$`)
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := yaml.Unmarshal(source, &document); err != nil {
			t.Fatal(err)
		}
		var walk func(any)
		walk = func(value any) {
			switch value := value.(type) {
			case map[string]any:
				for key, child := range value {
					if reference, ok := child.(string); ok {
						if key == "uses" && !strings.HasPrefix(reference, "./") && !commit.MatchString(reference) {
							t.Errorf("%s: unpinned action %s", filepath.Base(path), reference)
						}
						if key == "image" && !strings.Contains(reference, "${{") && !image.MatchString(reference) {
							t.Errorf("%s: unpinned image %s", filepath.Base(path), reference)
						}
					}
					walk(child)
				}
			case []any:
				for _, child := range value {
					walk(child)
				}
			}
		}
		walk(document)
	}
}
