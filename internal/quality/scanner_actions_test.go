// File purpose: Protects package evidence and required security checks when using publisher Actions.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type securityWorkflowStep struct {
	Name, Uses, Run, If string
	ContinueOnError     bool `yaml:"continue-on-error"`
	With                map[string]any
	Env                 map[string]string
}

func securitySteps(t *testing.T, file, job string) []securityWorkflowStep {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct{ Steps []securityWorkflowStep }
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	steps := workflow.Jobs[job].Steps
	if len(steps) == 0 {
		t.Fatalf("missing steps in %s/%s", file, job)
	}
	return steps
}

// TestReleaseScannerActionsPreserveEvidence ensures Actions cannot silently
// publish incomplete evidence or replace the high-severity gate with warnings.
func TestReleaseScannerActionsPreserveEvidence(t *testing.T) {
	const sbom = "dist/${{ steps.asset.outputs.name }}.spdx.json"
	const report = "dist/${{ steps.asset.outputs.name }}.vulnerabilities.json"
	generated, covered, scanned := false, false, false
	for _, step := range securitySteps(t, "release.yml", "packages") {
		switch {
		case strings.HasPrefix(step.Uses, "anchore/sbom-action@"):
			if step.If != "" || step.ContinueOnError || generated {
				t.Fatal("package SBOM generation must run once and fail on errors")
			}
			if step.With["path"] != "build/package-sbom" || step.With["format"] != "spdx-json" || step.With["output-file"] != sbom || step.Env["SYFT_SOURCE_NAME"] != "${{ steps.scan.outputs.identity }}" {
				t.Fatal("SBOM must retain the staged payload, source identity and SPDX evidence path")
			}
			for _, key := range []string{"upload-artifact", "upload-release-assets", "dependency-snapshot"} {
				if step.With[key] != false {
					t.Fatalf("%s must stay disabled until package evidence is verified", key)
				}
			}
			generated = true
		case strings.Contains(step.Run, "scripts/check-package-sbom.py"):
			if !generated || step.If != "" || step.ContinueOnError {
				t.Fatal("embedded dependency coverage must be required after SBOM generation")
			}
			covered = true
		case strings.HasPrefix(step.Uses, "anchore/scan-action@"):
			if !covered || scanned || step.If != "" || step.ContinueOnError {
				t.Fatal("vulnerability scan must be required after SBOM coverage")
			}
			if step.With["sbom"] != sbom || step.With["output-file"] != report || step.With["output-format"] != "json" || step.Env["GRYPE_DISTRO"] != "${{ steps.scan.outputs.distro }}" {
				t.Fatal("scan must use the covered SBOM, target distro and retained JSON report")
			}
			if step.With["fail-build"] != true || step.With["severity-cutoff"] != "high" || step.With["only-fixed"] != false {
				t.Fatal("high/critical findings must block for every fix state")
			}
			scanned = true
		}
	}
	if !generated || !covered || !scanned {
		t.Fatal("package generation, coverage and vulnerability checks are all required")
	}
}

// TestQualityActionsPreserveSourceAndBinaryChecks rejects replacing runtime
// vulnerability checks with a source-only action or a non-blocking linter.
func TestQualityActionsPreserveSourceAndBinaryChecks(t *testing.T) {
	lint, source, binary := false, false, false
	for _, step := range securitySteps(t, "quality.yml", "go-security") {
		switch {
		case strings.HasPrefix(step.Uses, "golangci/golangci-lint-action@"):
			lint = true
		case strings.HasPrefix(step.Uses, "golang/govulncheck-action@"):
			if step.With["output-format"] != nil && step.With["output-format"] != "text" {
				t.Fatal("govulncheck JSON output alone does not fail on reachable vulnerabilities")
			}
			source = true
		case strings.Contains(step.Run, "make verify-binaries"):
			binary = true
		default:
			continue
		}
		if step.If != "" || step.ContinueOnError {
			t.Fatal("lint, source scans and binary scans must remain required checks")
		}
	}
	if !lint || !source || !binary {
		t.Fatal("lint, source scans and binary scans must all run in the quality gate")
	}
}
