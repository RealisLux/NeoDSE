// File purpose: Verifies product checks stay independent and tool audits retain failures.
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

func TestProductChecksDoNotAuditToolDependencies(t *testing.T) {
	for _, target := range []string{"verify-security", "verify-go", "sbom-tools"} {
		t.Run(target, func(t *testing.T) {
			cmd := exec.Command("make", "--no-print-directory", "-n", target)
			cmd.Dir = repositoryRoot(t)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make plan: %v: %s", err, output)
			}
			for _, forbidden := range []string{"check-tool-vulnerabilities.sh", "check-scanner-vulnerabilities.py", "go mod verify && go mod tidy"} {
				if strings.Contains(string(output), forbidden) {
					t.Errorf("product target %s depends on tool maintenance: %s", target, forbidden)
				}
			}
			if target == "verify-security" {
				for _, binary := range []string{"neodse-agent", "neodse-server", "neodse-transport", "neodse-proxy", "neodse-vnc-auth"} {
					if !strings.Contains(string(output), binary) {
						t.Errorf("runtime binary scan missing %s", binary)
					}
				}
				if !strings.Contains(string(output), `" -mode=binary `) || !strings.Contains(string(output), `" ./...`) {
					t.Fatal("runtime source and binary vulnerability gates must remain")
				}
			}
		})
	}
}

func TestToolAuditRetainsFailuresAndContinues(t *testing.T) {
	for _, scenario := range []string{"clean", "source finding", "scanner failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			checker := filepath.Join(dir, "govulncheck")
			// JSON mode intentionally emits valid, clean evidence before failing:
			// pipefail must still preserve the producer's error.
			fake := `#!/usr/bin/env bash
set -eu
case " $* " in
  *' -format=json '*)
    mode=source; level=package
    if [[ " $* " == *' -mode=binary '* ]]; then mode=binary; level=symbol; fi
    printf '{"config":{"scanner_name":"govulncheck","scan_mode":"%s","scan_level":"%s"}}\n{"SBOM":{"modules":[]}}\n' "$mode" "$level"
    if [[ "${AUDIT_SCENARIO}" == 'scanner failure' ]]; then exit 2; fi
    ;;
  *)
    echo 'checked command'
    if [[ "${AUDIT_SCENARIO}" == 'source finding' && " $* " == *' tools/analysis '* ]]; then exit 3; fi
    ;;
esac
`
			if err := os.WriteFile(checker, []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}
			reports := filepath.Join(dir, "reports")
			cmd := exec.Command("bash", "scripts/check-tool-vulnerabilities.sh", checker, reports)
			cmd.Dir = repositoryRoot(t)
			cmd.Env = append(os.Environ(), "AUDIT_SCENARIO="+scenario)
			output, err := cmd.CombinedOutput()
			if (err == nil) != (scenario == "clean") {
				t.Fatalf("audit result: %v: %s", err, output)
			}
			logs, err := filepath.Glob(filepath.Join(reports, "*.log"))
			if err != nil || len(logs) != 12 {
				t.Fatalf("all 12 scans must retain logs after a failure: %v, %v", logs, err)
			}
			for _, name := range []string{"syft-source.json", "syft-binary.json", "grype-source.json", "grype-binary.json"} {
				if data, err := os.ReadFile(filepath.Join(reports, name)); err != nil || len(data) == 0 {
					t.Fatalf("raw scanner evidence %s missing: %v", name, err)
				}
			}
		})
	}
}
