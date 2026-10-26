// File purpose: Verifies scanner SDK exceptions cannot hide daemon or unrelated vulnerabilities.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScannerSourceEvidenceScopedExceptions verifies scope, version and
// malformed-stream boundaries for the two reviewed Docker SDK attribution errors.
func TestScannerSourceEvidenceScopedExceptions(t *testing.T) {
	for _, scenario := range []string{
		"reviewed SDK", "module only", "unrelated advisory", "daemon package",
		"different scanner", "updated Grype", "missing Grype", "changed Docker", "scoped advisory",
		"empty package", "missing config", "conflicting advisory",
		"unknown record", "truncated stream", "symbol finding",
		"binary SDK", "binary helper", "binary daemon", "changed helper",
		"source helper", "binary unrelated", "second advisory", "identical advisory",
		"changed Docker SBOM", "binary malformed symbol",
	} {
		t.Run(scenario, func(t *testing.T) {
			frame := map[string]any{"module": "github.com/docker/docker", "version": "v28.5.2+incompatible", "package": "github.com/docker/docker/client"}
			affected := map[string]any{"package": map[string]any{"name": "github.com/docker/docker"}, "ecosystem_specific": map[string]any{}}
			advisory := map[string]any{"id": "GO-2026-4883", "affected": []any{affected}}
			grype := map[string]any{"path": "github.com/anchore/grype", "version": "v0.120.1"}
			docker := map[string]any{"path": "github.com/docker/docker", "version": "v28.5.2+incompatible"}
			finding := map[string]any{"osv": "GO-2026-4883", "trace": []any{frame}}
			records := []map[string]any{
				{"config": map[string]any{"scanner_name": "govulncheck", "scan_mode": "source", "scan_level": "package"}},
				{"SBOM": map[string]any{"modules": []any{grype, docker}}},
				{"osv": advisory}, {"finding": finding},
			}
			scanner, mode := "grype", "source"
			switch scenario {
			case "module only":
				delete(frame, "package")
			case "unrelated advisory":
				advisory["id"], finding["osv"] = "GO-2026-9999", "GO-2026-9999"
			case "daemon package":
				frame["package"] = "github.com/docker/docker/daemon"
			case "different scanner":
				scanner = "syft"
			case "updated Grype":
				grype["version"] = "v0.121.0"
			case "missing Grype":
				records[1]["SBOM"] = map[string]any{"modules": []any{docker}}
			case "changed Docker":
				frame["version"] = "v28.5.3+incompatible"
			case "scoped advisory":
				affected["ecosystem_specific"] = map[string]any{"packages": []any{map[string]any{"path": "github.com/docker/docker/client"}}}
			case "empty package":
				frame["package"] = ""
			case "missing config":
				records = records[1:]
			case "conflicting advisory":
				records = append(records, map[string]any{"osv": map[string]any{"id": "GO-2026-4883", "affected": []any{}}})
			case "unknown record":
				records = append(records, map[string]any{"unknown": map[string]any{}})
			case "symbol finding":
				frame["function"] = "Vulnerable"
			case "binary SDK", "binary daemon", "binary unrelated":
				mode = "binary"
				frame["function"] = "Client.ImageList"
				if scenario == "binary daemon" {
					frame["package"] = "github.com/docker/docker/daemon"
				}
				if scenario == "binary unrelated" {
					advisory["id"], finding["osv"] = "GO-2026-9999", "GO-2026-9999"
				}
			case "binary helper", "changed helper", "source helper":
				frame["module"], frame["version"] = "github.com/docker/docker-credential-helpers", "v0.9.8"
				frame["package"] = "github.com/docker/docker-credential-helpers/credentials"
				if scenario != "source helper" {
					mode = "binary"
					frame["function"] = "Get"
				}
				if scenario == "changed helper" {
					frame["version"] = "v0.9.9"
				}
			case "second advisory":
				advisory["id"], finding["osv"] = "GO-2026-4887", "GO-2026-4887"
			case "identical advisory":
				records = append(records, map[string]any{"osv": advisory})
			case "changed Docker SBOM":
				docker["version"] = "v28.5.3+incompatible"
			case "binary malformed symbol":
				mode = "binary"
				delete(frame, "package")
				frame["function"] = "Vulnerable"
			}
			if mode == "binary" {
				config := records[0]["config"].(map[string]any)
				config["scan_mode"], config["scan_level"] = "binary", "symbol"
			}
			var input bytes.Buffer
			for _, record := range records {
				if err := json.NewEncoder(&input).Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "truncated stream" {
				input.WriteString(`{"finding":`)
			}
			command := exec.Command("python3", filepath.Join(repositoryRoot(t), "scripts", "check-scanner-vulnerabilities.py"), "--scanner", scanner, "--mode", mode)
			command.Stdin = strings.NewReader(input.String())
			output, err := command.CombinedOutput()
			accepted := scenario == "reviewed SDK" || scenario == "module only" || scenario == "binary SDK" || scenario == "binary helper" ||
				scenario == "second advisory" || scenario == "identical advisory" || scenario == "updated Grype"
			if accepted != (err == nil) {
				t.Fatalf("accepted=%v, error=%v\n%s", accepted, err, output)
			}
		})
	}
}
