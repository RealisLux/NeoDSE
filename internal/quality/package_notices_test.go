// File purpose: Verifies generated packages retain embedded third-party attributions and licenses.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageNoticesIncludeEmbeddedLicenses exercises notice generation with controlled Go build metadata.
func TestPackageNoticesIncludeEmbeddedLicenses(t *testing.T) {
	directory := t.TempDir()
	moduleDirectory := filepath.Join(directory, "dependency")
	toolchainDirectory := filepath.Join(directory, "goroot")
	for path, contents := range map[string]string{
		filepath.Join(moduleDirectory, "LICENSE"):    "Fixture dependency license\n",
		filepath.Join(toolchainDirectory, "LICENSE"): "Fixture Go toolchain license\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	module := map[string]string{"Path": "example.com/fixture", "Version": "v1.0.0", "Dir": moduleDirectory}
	moduleJSON, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	packageJSON, err := json.Marshal(map[string]any{"Module": module, "Dir": moduleDirectory})
	if err != nil {
		t.Fatal(err)
	}
	fakeGo := `#!/bin/sh
set -eu
case "$1 $2" in
 "version -m") printf '%s\n' 'fixture: go1.27.2' ' path example.com/program' ' dep example.com/fixture v1.0.0 h1:fixture' ;;
 "list -m") printf '%s\n' "$NOTICE_TEST_MODULE" ;;
 "list -deps") printf '%s\n' "$NOTICE_TEST_PACKAGE" ;;
 "env GOROOT") printf '%s\n' "$NOTICE_TEST_GOROOT" ;;
 *) exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(fakeGo), 0o700); err != nil {
		t.Fatal(err)
	}
	root := repositoryRoot(t)
	supplement, err := os.ReadFile(filepath.Join(root, "internal", "swagger", "vendor", "THIRD-PARTY-NOTICES"))
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{"client", "server"} {
		t.Run(component, func(t *testing.T) {
			outputPath := filepath.Join(directory, component+"-notices.txt")
			command := exec.Command("python3", filepath.Join(root, "scripts", "package-notices.py"), component, outputPath, "fixture")
			command.Dir = root
			command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"),
				"NOTICE_TEST_MODULE="+string(moduleJSON), "NOTICE_TEST_PACKAGE="+string(packageJSON), "NOTICE_TEST_GOROOT="+toolchainDirectory)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generate notices: %v: %s", err, output)
			}
			notices, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"Fixture dependency license", "Fixture Go toolchain license"} {
				if !strings.Contains(string(notices), required) {
					t.Errorf("package omits %s", required)
				}
			}
			if component == "server" {
				for _, required := range []string{string(supplement), "Apache License", "DOMPurify"} {
					if !strings.Contains(string(notices), required) {
						t.Errorf("server package omits embedded license material: %q", required)
					}
				}
			} else if strings.Contains(string(notices), string(supplement)) {
				t.Error("client package includes Swagger notices without embedding Swagger")
			}
		})
	}
}
