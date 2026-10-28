// File purpose: Prevents native packages from using cross-compilation targets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativePackageRejectsCrossCompilation verifies effective Go settings are
// checked before building tools or creating mislabeled package payloads.
func TestNativePackageRejectsCrossCompilation(t *testing.T) {
	for _, scenario := range []struct{ name, host, goos, goarch, target string }{
		{"foreign operating system", "x86_64", "windows", "amd64", "linux/amd64"},
		{"foreign architecture on amd64", "x86_64", "linux", "arm64", "linux/amd64"},
		{"foreign architecture on arm64", "aarch64", "linux", "amd64", "linux/arm64"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			marker := filepath.Join(directory, "unexpected-build")
			for name, program := range map[string]string{
				"uname": `#!/bin/sh
case "$1" in
 -s) echo Linux ;;
 -m) echo "$PACKAGE_TEST_HOST" ;;
 *) exit 99 ;;
esac
`,
				"go": `#!/bin/sh
case "$*" in
 "env GOOS") echo "$PACKAGE_TEST_GOOS" ;;
 "env GOARCH") echo "$PACKAGE_TEST_GOARCH" ;;
 *) touch "$PACKAGE_TEST_MARKER"; exit 99 ;;
esac
`,
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(program), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", filepath.Join(repositoryRoot(t), "scripts", "build-local-packages.sh"), "--skip-tests")
			command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"),
				"PACKAGE_TEST_HOST="+scenario.host, "PACKAGE_TEST_GOOS="+scenario.goos,
				"PACKAGE_TEST_GOARCH="+scenario.goarch, "PACKAGE_TEST_MARKER="+marker)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "Go must target "+scenario.target) {
				t.Fatalf("expected actionable target rejection, got %v: %s", err, output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("cross-compilation started a build: %v", err)
			}
		})
	}
}

// TestNativePackageRebuildsManifestPayload verifies inherited build-directory
// overrides cannot cause a new package to contain stale default-directory binaries.
func TestNativePackageRebuildsManifestPayload(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "build-local-packages.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, override := range []string{"command line", "environment"} {
		t.Run(override, func(t *testing.T) {
			directory := t.TempDir()
			for _, name := range []string{"scripts", "bin", "build"} {
				if err := os.Mkdir(filepath.Join(directory, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// Use a supported fixture distribution independently of the test host.
			script := strings.ReplaceAll(string(source), "/etc/os-release", "os-release")
			files := map[string]string{
				"scripts/build-local-packages.sh": script,
				"os-release":                      "ID=debian\nVERSION_ID=13\n",
				"Makefile": `BUILD_DIR ?= build
.PHONY: package-local packaging-tools server transport proxy
package-local:
	bash scripts/build-local-packages.sh --skip-tests --version 1.2.3 --component server --format deb
packaging-tools:
	mkdir -p build/tools
	cp "$${PACKAGE_TEST_NFPM}" build/tools/nfpm
server transport proxy:
	mkdir -p "$(BUILD_DIR)"
	printf '%s\n' 'fresh 1.2.3' > "$(BUILD_DIR)/neodse-$@"
`,
				"bin/uname": `#!/bin/sh
case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 99 ;; esac
`,
				"bin/go": `#!/bin/sh
set -eu
case "$*" in
 "env GOOS") echo linux ;;
 "env GOARCH") echo amd64 ;;
 *) exit 99 ;;
esac
`,
				"bin/python3": `#!/bin/sh
set -eu
case "$1" in
 */check-release-assets.py) exit 0 ;;
 scripts/package-notices.py) printf 'fixture notices\n' > "$3" ;;
 *) exit 99 ;;
esac
`,
				"bin/dpkg-deb": "#!/bin/sh\nexit 0\n",
				"bin/nfpm-fixture": `#!/bin/sh
set -eu
target=
while [ "$#" -gt 0 ]; do
 if [ "$1" = --target ]; then shift; target=$1; fi
 shift
done
cat build/neodse-server build/neodse-transport build/neodse-proxy > "$target"
`,
			}
			for name, contents := range files {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"server", "transport", "proxy"} {
				if err := os.WriteFile(filepath.Join(directory, "build", "neodse-"+name), []byte("stale build\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			arguments := []string{"--no-print-directory", "package-local"}
			environment := append(os.Environ(),
				"PATH="+filepath.Join(directory, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
				"PACKAGE_TEST_NFPM="+filepath.Join(directory, "bin", "nfpm-fixture"))
			if override == "command line" {
				arguments = append(arguments, "BUILD_DIR=custom-output")
			} else {
				environment = append(environment, "BUILD_DIR=custom-output")
			}
			command := exec.Command(makePath, arguments...)
			command.Dir, command.Env = directory, environment
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("build package with inherited directory: %v\n%s", err, output)
			}
			payload, err := os.ReadFile(filepath.Join(directory, "dist", "NeoDSE-server_1.2.3_debian13_amd64.deb"))
			if err != nil || string(payload) != strings.Repeat("fresh 1.2.3\n", 3) {
				t.Fatalf("package used stale payload: %q, error=%v", payload, err)
			}
			if _, err := os.Stat(filepath.Join(directory, "custom-output")); !os.IsNotExist(err) {
				t.Fatalf("payload build used directory outside package manifests: %v", err)
			}
		})
	}
}
