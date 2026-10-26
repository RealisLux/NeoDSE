// File purpose: Verifies project notices survive DEB and RPM package construction.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestPackagesRetainProjectNotice checks the actual notice payload without building runtime programs.
func TestPackagesRetainProjectNotice(t *testing.T) {
	root := repositoryRoot(t)
	nfpm := filepath.Join(root, "build", "tools", "nfpm")
	if _, err := os.Stat(nfpm); err != nil {
		t.Skip("build the pinned nFPM with make security-tools for package notice checks")
	}
	expected, err := os.ReadFile(filepath.Join(root, "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ manifest, format, destination string }{
		{"nfpm-client.yaml", "deb", "/usr/share/doc/neodse-client/NOTICE"},
		{"nfpm-server-deb.yaml", "deb", "/usr/share/doc/neodse-server/NOTICE"},
		{"nfpm-server-rpm.yaml", "rpm", "/usr/share/licenses/neodse-server/NOTICE"},
	} {
		t.Run(target.manifest, func(t *testing.T) {
			tool := "dpkg-deb"
			if target.format == "rpm" {
				tool = "bsdtar"
			}
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s is required for package notice checks", tool)
			}
			source, err := os.ReadFile(filepath.Join(root, "packaging", target.manifest))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct{ Contents []map[string]any }
			if err := yaml.Unmarshal(source, &manifest); err != nil {
				t.Fatal(err)
			}
			var entry map[string]any
			for _, candidate := range manifest.Contents {
				if candidate["dst"] == target.destination {
					if entry != nil {
						t.Fatal("package contains duplicate project notices")
					}
					entry = candidate
				}
			}
			if entry == nil || entry["src"] != "NOTICE" {
				t.Fatalf("package must include the root NOTICE at %s", target.destination)
			}
			fileInfo, _ := entry["file_info"].(map[string]any)
			if fileInfo["owner"] != "root" || fileInfo["group"] != "root" {
				t.Fatal("project notice must be owned by root:root")
			}
			entry["src"] = filepath.Join(root, "NOTICE")
			fixture := map[string]any{
				"name": "neodse-notice-test", "arch": "amd64", "platform": "linux", "version": "1.0.0",
				"maintainer": "NeoDSE maintainers", "contents": []map[string]any{entry},
			}
			data, err := yaml.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			config := filepath.Join(directory, "nfpm.yaml")
			if err := os.WriteFile(config, data, 0o600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(directory, "notice."+target.format)
			build := exec.Command(nfpm, "package", "--config", config, "--packager", target.format, "--target", archive)
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build notice fixture: %v: %s", err, output)
			}
			payload := filepath.Join(directory, "payload")
			if err := os.Mkdir(payload, 0o700); err != nil {
				t.Fatal(err)
			}
			extract := exec.Command("dpkg-deb", "--extract", archive, payload)
			if target.format == "rpm" {
				extract = exec.Command("bsdtar", "--extract", "--file", archive, "--directory", payload, "--no-same-owner")
			}
			if output, err := extract.CombinedOutput(); err != nil {
				t.Fatalf("extract notice fixture: %v: %s", err, output)
			}
			notice := filepath.Join(payload, target.destination)
			actual, err := os.ReadFile(notice)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("packaged project notice differs from root NOTICE: %v", err)
			}
			info, err := os.Lstat(notice)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
				t.Fatalf("project notice must be a regular file with mode 0644: %v, %v", info, err)
			}
		})
	}
}
