// File purpose: Exercises package removal and helper dependency evidence without host changes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// releaseFixtureVersion is the version bound to the publication fixture tag.
const releaseFixtureVersion = "1.0.0-rc.1"

// releaseFixturePackages independently enumerates the supported publication matrix.
var releaseFixturePackages = []string{
	"NeoDSE-client_1.0.0-rc.1_debian13_amd64.deb", "NeoDSE-client_1.0.0-rc.1_debian13_arm64.deb",
	"NeoDSE-server_1.0.0-rc.1_debian13_amd64.deb", "NeoDSE-server_1.0.0-rc.1_debian13_arm64.deb",
	"NeoDSE-client_1.0.0-rc.1_ubuntu26.04_amd64.deb", "NeoDSE-client_1.0.0-rc.1_ubuntu26.04_arm64.deb",
	"NeoDSE-server_1.0.0-rc.1_ubuntu26.04_amd64.deb", "NeoDSE-server_1.0.0-rc.1_ubuntu26.04_arm64.deb",
	"NeoDSE-server_1.0.0-rc.1_el9_amd64.rpm", "NeoDSE-server_1.0.0-rc.1_el10_amd64.rpm",
}

// TestReleasePublicationFailsClosed exercises publication with a local GitHub CLI fixture.
func TestReleasePublicationFailsClosed(t *testing.T) {
	for _, scenario := range []string{
		"draft", "create", "published", "lookup failure", "upload failure",
		"missing evidence", "corrupt evidence", "wrong target", "partial manifest",
		"manifest includes reports", "duplicate manifest", "wrong package checksum",
		"invalid sbom", "unbound sbom", "wrong sbom checksum", "wrong sbom component",
		"high vulnerability", "ignored high vulnerability", "ignored critical vulnerability",
		"invalid ignored matches", "invalid ignored severity", "placeholder scan",
		"stale scan", "future scan", "invalid database", "unfixed excluded",
		"fixed excluded", "fix states excluded", "packages excluded", "missing exclusion evidence",
		"wrong scan distribution", "missing scan distribution", "unversioned package",
		"mixed package versions", "wrong release version", "wrong sbom source",
		"swapped scan reports", "wrong scan source", "wrong scan source type", "missing scan source",
		"remote extra asset", "remote missing asset", "remote duplicate asset", "remote unfinished asset",
		"remote malformed assets", "remote asset lookup failure",
	} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			assets := filepath.Join(directory, "release-assets")
			if err := os.Mkdir(assets, 0o700); err != nil {
				t.Fatal(err)
			}
			writeReleaseFixture(t, assets, scenario, releaseFixtureVersion)
			var remoteAssets []map[string]string
			for _, name := range releaseFixturePackages {
				for _, suffix := range []string{"", ".sha256"} {
					remoteAssets = append(remoteAssets, map[string]string{"name": name + suffix, "state": "uploaded"})
				}
			}
			remoteAssets = append(remoteAssets, map[string]string{"name": "SHA256SUMS", "state": "uploaded"})
			switch scenario {
			case "remote extra asset":
				remoteAssets = append(remoteAssets, map[string]string{"name": "obsolete-package.deb", "state": "uploaded"})
			case "remote missing asset":
				remoteAssets = remoteAssets[:len(remoteAssets)-1]
			case "remote duplicate asset":
				remoteAssets = append(remoteAssets[:len(remoteAssets)-1], remoteAssets[0])
			case "remote unfinished asset":
				remoteAssets[0]["state"] = "starter"
			}
			remoteJSON, err := json.Marshal(map[string]any{"assets": remoteAssets})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "remote malformed assets" {
				remoteJSON = []byte(`{"assets":null}`)
			}
			if err := os.WriteFile(filepath.Join(directory, "remote-assets.json"), remoteJSON, 0o600); err != nil {
				t.Fatal(err)
			}
			fakeGH := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> calls
case "$1 $2" in
 "release view")
  if [[ "$*" == *"--json assets"* ]]; then
   [[ "$GH_TEST_CASE" != "remote asset lookup failure" ]] || exit 1
   cat remote-assets.json
   exit 0
  fi
  [[ "$GH_TEST_CASE" != "lookup failure" ]] || exit 1
  [[ "$GH_TEST_CASE" != create || -f created ]] || exit 1
  if [[ "$GH_TEST_CASE" == published ]]; then echo false; else echo true; fi
  ;;
 "release create")
  [[ "$GH_TEST_CASE" != "lookup failure" ]] || exit 1
  touch created
  ;;
 "release upload") [[ "$GH_TEST_CASE" != "upload failure" ]] ;;
 "release edit") ;;
 *) exit 99 ;;
esac
`
			if err := os.WriteFile(filepath.Join(directory, "gh"), []byte(fakeGH), 0o700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", filepath.Join(repositoryRoot(t), "scripts", "publish-release.sh"))
			command.Dir = directory
			command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"), "GITHUB_REF_NAME=v"+releaseFixtureVersion, "GH_TEST_CASE="+scenario)
			output, err := command.CombinedOutput()
			wantSuccess := scenario == "draft" || scenario == "create"
			if (err == nil) != wantSuccess {
				t.Fatalf("publication success=%t, want=%t: %s", err == nil, wantSuccess, output)
			}
			calls, _ := os.ReadFile(filepath.Join(directory, "calls"))
			if !wantSuccess && scenario != "published" && scenario != "lookup failure" && scenario != "upload failure" && !strings.HasPrefix(scenario, "remote ") && len(calls) != 0 {
				t.Fatalf("invalid release evidence triggered GitHub calls: %s", calls)
			}
			if strings.Contains(string(calls), "release edit") != wantSuccess {
				t.Fatalf("unexpected publication calls: %s", calls)
			}
			if strings.Contains(string(calls), ".spdx.json") || strings.Contains(string(calls), ".vulnerabilities.json") {
				t.Fatalf("release evidence must stay in CI artifacts: %s", calls)
			}
			if wantSuccess {
				for line := range strings.SplitSeq(string(calls), "\n") {
					if !strings.HasPrefix(line, "release upload ") {
						continue
					}
					arguments := strings.Fields(line)
					if len(arguments) != 4+2*len(releaseFixturePackages)+1 {
						t.Fatalf("unexpected published asset count: %s", line)
					}
					for _, name := range releaseFixturePackages {
						for _, suffix := range []string{"", ".sha256"} {
							if !strings.Contains(line, "release-assets/"+name+suffix+" ") {
								t.Fatalf("published package or checksum missing: %s%s", name, suffix)
							}
						}
					}
					if !strings.HasSuffix(line, "release-assets/SHA256SUMS") {
						t.Fatalf("published manifest missing: %s", line)
					}
				}
			}
			if scenario == "create" && !strings.Contains(string(calls), "--prerelease") {
				t.Fatal("release candidate was not created as a prerelease")
			}
			if (scenario == "published" || scenario == "lookup failure") && strings.Contains(string(calls), "release upload") {
				t.Fatalf("unsafe upload: %s", calls)
			}
		})
	}
}

// writeReleaseFixture builds a complete checksummed set and corrupts one independent publication invariant.
func writeReleaseFixture(t *testing.T, directory, scenario, version string) {
	t.Helper()
	files := make(map[string][]byte)
	packages := make([]string, len(releaseFixturePackages))
	for index, name := range releaseFixturePackages {
		packages[index] = strings.Replace(name, releaseFixtureVersion, version, 1)
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	newReport := func(identity string) string {
		return fmt.Sprintf(`{"source":{"type":"directory","target":%q},"descriptor":{"name":"grype","version":"0.117.0","timestamp":%q,"configuration":{"only-fixed":false,"only-notfixed":false,"ignore-wontfix":"","exclude":[]},"db":{"status":{"valid":true,"built":%q}}},"distro":{"name":"debian","version":"13"},"matches":[]}`, identity, stamp, stamp)
	}
	for _, name := range packages {
		payload := []byte("fixture " + name + "\n")
		identity := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
		files[name] = payload
		files[name+".sha256"] = fmt.Appendf(nil, "%x  %s\n", sha256.Sum256(payload), name)
		component := strings.Split(strings.Split(name, "_")[0], "-")[1]
		files[name+".spdx.json"] = fmt.Appendf(nil, `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":%q,"packages":[{"name":"neodse-%s","versionInfo":%q}],"files":[{"fileName":%q,"checksums":[{"algorithm":"SHA256","checksumValue":"%x"}]}]}`, identity, component, version, name+"/"+name, sha256.Sum256(payload))
		packageReport := newReport(identity)
		if strings.Contains(name, "_ubuntu26.04_") {
			packageReport = strings.Replace(packageReport, `"name":"debian","version":"13"`, `"name":"ubuntu","version":"26.04"`, 1)
		} else if strings.Contains(name, "_el9_") {
			packageReport = strings.Replace(packageReport, `"name":"debian","version":"13"`, `"name":"rockylinux","version":"9"`, 1)
		} else if strings.Contains(name, "_el10_") {
			packageReport = strings.Replace(packageReport, `"name":"debian","version":"13"`, `"name":"rockylinux","version":"10"`, 1)
		}
		files[name+".vulnerabilities.json"] = []byte(packageReport)
	}
	first := packages[0]
	report := string(files[first+".vulnerabilities.json"])
	switch scenario {
	case "unversioned package", "mixed package versions", "wrong release version":
		selected := []string{first}
		if scenario == "wrong release version" {
			selected = packages
		}
		for _, name := range selected {
			stem, target, _ := strings.Cut(name, "_")
			replacement := stem + "_9.9.9_" + strings.TrimPrefix(target, version+"_")
			if scenario == "unversioned package" {
				replacement = stem + "_" + strings.TrimPrefix(target, version+"_")
			}
			for _, suffix := range []string{"", ".sha256", ".spdx.json", ".vulnerabilities.json"} {
				files[replacement+suffix] = files[name+suffix]
				delete(files, name+suffix)
			}
		}
	case "wrong target":
		for _, suffix := range []string{"", ".sha256", ".spdx.json", ".vulnerabilities.json"} {
			files["NeoDSE-client_"+version+"_unknown_amd64.deb"+suffix] = files[first+suffix]
			delete(files, first+suffix)
		}
	case "missing evidence":
		files["orphan.spdx.json"] = files[first+".spdx.json"]
		delete(files, first+".spdx.json")
	case "wrong package checksum":
		files[first+".sha256"] = []byte(strings.Repeat("0", 64) + "  " + first + "\n")
	case "invalid sbom":
		files[first+".spdx.json"] = []byte(`{}`)
	case "unbound sbom":
		files[first+".spdx.json"] = fmt.Appendf(nil, `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"neodse-client","versionInfo":%q}]}`, version)
	case "wrong sbom checksum":
		files[first+".spdx.json"] = []byte(strings.Replace(string(files[first+".spdx.json"]), fmt.Sprintf(`"checksumValue":"%x"`, sha256.Sum256(files[first])), `"checksumValue":"`+strings.Repeat("0", 64)+`"`, 1))
	case "high vulnerability":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"matches":[]`, `"matches":[{"vulnerability":{"severity":"High"}}]`, 1))
	case "ignored high vulnerability", "ignored critical vulnerability", "invalid ignored severity":
		severity := "High"
		if scenario == "ignored critical vulnerability" {
			severity = "Critical"
		} else if scenario == "invalid ignored severity" {
			severity = "unexpected"
		}
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"matches":[]`, fmt.Sprintf(`"matches":[],"ignoredMatches":[{"vulnerability":{"severity":%q},"appliedIgnoreRules":[{"vulnerability":"fixture"}]}]`, severity), 1))
	case "invalid ignored matches":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"matches":[]`, `"matches":[],"ignoredMatches":{}`, 1))
	case "placeholder scan":
		files[first+".vulnerabilities.json"] = fmt.Appendf(nil, `{"source":{"type":"directory","target":"sha256:%x"},"descriptor":{"name":"grype"},"matches":[]}`, sha256.Sum256(files[first]))
	case "stale scan":
		files[first+".vulnerabilities.json"] = []byte(strings.ReplaceAll(report, stamp, time.Now().UTC().Add(-6*24*time.Hour).Format(time.RFC3339)))
	case "future scan":
		files[first+".vulnerabilities.json"] = []byte(strings.ReplaceAll(report, stamp, time.Now().UTC().Add(6*time.Hour).Format(time.RFC3339)))
	case "invalid database":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"valid":true`, `"valid":false`, 1))
	case "unfixed excluded":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"only-fixed":false`, `"only-fixed":true`, 1))
	case "fixed excluded":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"only-notfixed":false`, `"only-notfixed":true`, 1))
	case "fix states excluded":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"ignore-wontfix":""`, `"ignore-wontfix":"unknown"`, 1))
	case "packages excluded":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"exclude":[]`, `"exclude":["**"]`, 1))
	case "missing exclusion evidence":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `,"exclude":[]`, ``, 1))
	case "wrong scan distribution":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"name":"debian","version":"13"`, `"name":"ubuntu","version":"26.04"`, 1))
	case "missing scan distribution":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `,"distro":{"name":"debian","version":"13"}`, ``, 1))
	case "wrong sbom component":
		files[first+".spdx.json"] = files["NeoDSE-server_"+version+"_debian13_amd64.deb.spdx.json"]
	case "wrong sbom source":
		files[first+".spdx.json"] = []byte(strings.Replace(string(files[first+".spdx.json"]), `"name":"sha256:`, `"name":"other:`, 1))
	case "wrong scan source":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"target":"sha256:`, `"target":"other:`, 1))
	case "wrong scan source type":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, `"type":"directory"`, `"type":"file"`, 1))
	case "missing scan source":
		files[first+".vulnerabilities.json"] = []byte(strings.Replace(report, fmt.Sprintf(`"source":{"type":"directory","target":"sha256:%x"},`, sha256.Sum256(files[first])), ``, 1))
	case "swapped scan reports":
		files[first+".vulnerabilities.json"] = files["NeoDSE-server_"+version+"_debian13_amd64.deb.vulnerabilities.json"]
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(directory, name), files[name], 0o600); err != nil {
			t.Fatal(err)
		}
		if (strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".rpm") || strings.HasSuffix(name, ".sha256")) &&
			(scenario != "partial manifest" || name != first) {
			fmt.Fprintf(&manifest, "%x  ./%s\n", sha256.Sum256(files[name]), name)
		}
	}
	if scenario == "manifest includes reports" {
		fmt.Fprintf(&manifest, "%x  ./%s\n", sha256.Sum256(files[first+".spdx.json"]), first+".spdx.json")
	}
	if scenario == "duplicate manifest" {
		fmt.Fprintf(&manifest, "%x  ./%s\n", sha256.Sum256(files[names[0]]), names[0])
	}
	if err := os.WriteFile(filepath.Join(directory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if scenario == "corrupt evidence" {
		if err := os.WriteFile(filepath.Join(directory, first+".spdx.json"), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestClientRemoveThenPurgePreservesWestonPAM protects the restored distribution policy.
func TestClientRemoveThenPurgePreservesWestonPAM(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "postremove-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	policy := filepath.Join(directory, "weston-remote-access")
	script := filepath.Join(directory, "postremove.sh")
	if err := os.WriteFile(policy, []byte("NeoDSE replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy+".distrib", []byte("Weston original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte(strings.ReplaceAll(string(source), "/etc/pam.d/weston-remote-access", policy)), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `
owner=neodse-client
policy=$2
dpkg-divert() {
 case "$1" in
  --listpackage) printf '%s\n' "$owner" ;;
  --package)
   [[ "$*" == "--package neodse-client --remove --rename --divert $policy.distrib $policy" ]] || return 99
   command mv "$policy.distrib" "$policy"
   owner=
   ;;
  *) return 99 ;;
 esac
}
systemctl() { return 0; }
source "$1" remove
source "$1" purge
`, "postremove-test", script, policy)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("remove/purge: %v\n%s", err, output)
	}
	contents, err := os.ReadFile(policy)
	if err != nil || string(contents) != "Weston original" {
		t.Fatalf("distribution policy lost: %q, %v", contents, err)
	}
}

// TestClientUpgradeFailurePreservesWestonPAM keeps the installed client's policy and diversion intact.
func TestClientUpgradeFailurePreservesWestonPAM(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "postremove-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"upgrade", "failed-upgrade", "abort-upgrade"} {
		t.Run(action, func(t *testing.T) {
			directory := t.TempDir()
			policy := filepath.Join(directory, "weston-remote-access")
			for path, value := range map[string]string{policy: "NeoDSE replacement", policy + ".distrib": "Weston original"} {
				if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := filepath.Join(directory, "postremove.sh")
			if err := os.WriteFile(script, []byte(strings.ReplaceAll(string(source), "/etc/pam.d/weston-remote-access", policy)), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", "-c", `
dpkg-divert() { echo 'upgrade touched the PAM diversion' >&2; return 99; }
systemctl() { echo 'upgrade ran removal actions' >&2; return 99; }
source "$1" "$2" 1.0.0 1.0.1
`, "postremove-test", script, action)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", action, err, output)
			}
			for path, want := range map[string]string{policy: "NeoDSE replacement", policy + ".distrib": "Weston original"} {
				if value, err := os.ReadFile(path); err != nil || string(value) != want {
					t.Errorf("upgrade changed %s: %q, %v", path, value, err)
				}
			}
		})
	}
}

// TestServerPreinstallLeavesStateDirectoryToPackage keeps /etc/skel login
// files out of the controller state directory that the package creates.
func TestServerPreinstallLeavesStateDirectoryToPackage(t *testing.T) {
	command := exec.Command("bash", "-c", `
declare -A groups=() users=()
getent() {
    case "$1" in
        group) [[ -n ${groups[$2]:-} ]] && printf '%s:x:%s:\n' "$2" "${groups[$2]}" ;;
        passwd) [[ -n ${users[$2]:-} ]] && printf '%s\n' "${users[$2]}" ;;
        *) return 2 ;;
    esac
}
groupadd() { groups[$2]=$((900 + ${#groups[@]})); }
# Account creation must never reach the host during this fixture.
useradd() {
    local name=${*: -1} home= arguments=("$@")
    printf 'useradd %s\n' "$*"
    for index in "${!arguments[@]}"; do
        [[ ${arguments[index]} != --home-dir ]] || home=${arguments[index + 1]}
    done
    users[$name]="$name:x:${groups[$name]}:${groups[$name]}::$home:/usr/sbin/nologin"
}
id() { printf '%s\n' "$2"; }
source "$1"
`, "preinstall-test", filepath.Join(repositoryRoot(t), "scripts", "preinstall-server.sh"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("preinstall: %v\n%s", err, output)
	}
	var calls []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		if strings.HasPrefix(line, "useradd ") {
			calls = append(calls, line)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("expected three service accounts:\n%s", output)
	}
	for _, call := range calls {
		fields := strings.Fields(call)
		if !slices.Contains(fields, "--no-create-home") || slices.Contains(fields, "--create-home") || slices.Contains(fields, "-m") {
			t.Errorf("account creation must leave home directories to the package: %s", call)
		}
	}
	if !strings.Contains(string(output), "--home-dir /var/lib/neodse --no-create-home --shell /usr/sbin/nologin neodse-server") {
		t.Errorf("controller account lost its state-directory home:\n%s", output)
	}
}

// TestServerFinalErasureUnloadsSELinuxPolicy removes the policy module only
// when RPM erases the last installed version.
func TestServerFinalErasureUnloadsSELinuxPolicy(t *testing.T) {
	unload := "semodule -r neodse\nrestorecon -iRF /etc/neodse /var/lib/neodse\n"
	for _, scenario := range []struct {
		name, argument, selinux, modules, want string
		fails                                  bool
	}{
		{name: "rpm-erase", argument: "0", selinux: "on", modules: "abrt\nneodse\nsssd", want: unload},
		{name: "rpm-erase-versioned-listing", argument: "0", selinux: "on", modules: "neodse\t1.0", want: unload},
		{name: "rpm-upgrade", argument: "1", selinux: "on", modules: "neodse"},
		{name: "deb-remove", argument: "remove", selinux: "on", modules: "neodse"},
		{name: "deb-purge", argument: "purge", selinux: "on", modules: "neodse"},
		{name: "selinux-disabled", argument: "0", selinux: "off", modules: "neodse"},
		{name: "module-absent", argument: "0", selinux: "on", modules: "neodse_other"},
		{name: "unload-fails", argument: "0", selinux: "on", modules: "neodse", want: "semodule -r neodse\n", fails: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
selinuxenabled() { [[ $SELINUX == on ]]; }
semodule() {
    case "$1" in
        -l) printf '%b\n' "$MODULES" ;;
        -r) printf 'semodule %s\n' "$*"; [[ $SCENARIO != unload-fails ]] ;;
        *) return 99 ;;
    esac
}
restorecon() { printf 'restorecon %s\n' "$*"; }
systemctl() { return 0; }
source "$1" "$2"
`, "postremove-test", filepath.Join(repositoryRoot(t), "scripts", "postremove-server.sh"), scenario.argument)
			command.Env = append(os.Environ(), "SCENARIO="+scenario.name, "SELINUX="+scenario.selinux, "MODULES="+scenario.modules)
			output, err := command.CombinedOutput()
			if (err != nil) != scenario.fails {
				t.Fatalf("postremove %s: %v\n%s", scenario.argument, err, output)
			}
			var policy strings.Builder
			for _, line := range strings.SplitAfter(string(output), "\n") {
				if strings.HasPrefix(line, "semodule ") || strings.HasPrefix(line, "restorecon ") {
					policy.WriteString(line)
				}
			}
			if policy.String() != scenario.want {
				t.Fatalf("policy actions = %q, want %q", policy.String(), scenario.want)
			}
		})
	}
}

// TestDisplayHotplugRuleStartsOnlyEnabledCompositor runs the packaged udev
// program: a disabled compositor is skipped without a failure for udev to log,
// while a failed start is still reported.
func TestDisplayHotplugRuleStartsOnlyEnabledCompositor(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "udev", "71-neodse-display-hotplug.rules"))
	if err != nil {
		t.Fatal(err)
	}
	var programs []string
	for line := range strings.SplitSeq(string(source), "\n") {
		if _, program, found := strings.Cut(line, `RUN+="`); found {
			programs = append(programs, strings.TrimSuffix(program, `"`))
		}
	}
	if len(programs) != 1 || !strings.HasPrefix(programs[0], "/bin/sh -c '") {
		t.Fatalf("udev rule must run one shell program, found %q", programs)
	}
	directory := t.TempDir()
	stub := filepath.Join(directory, "systemctl")
	if err := os.WriteFile(stub, []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$LOG"
case "$*" in
    "--quiet is-enabled neodse-weston.service") exit "$ENABLED" ;;
    "--no-block start neodse-weston.service") exit "$START" ;;
esac
exit 99
`), 0o700); err != nil {
		t.Fatal(err)
	}
	program := strings.ReplaceAll(programs[0], "/usr/bin/systemctl", stub)
	start := "--no-block start neodse-weston.service\n"
	for _, scenario := range []struct {
		name, enabled, start string
		started, fails       bool
	}{
		{name: "enabled", enabled: "0", start: "0", started: true},
		{name: "disabled", enabled: "1", start: "0"},
		{name: "not-found", enabled: "4", start: "0"},
		{name: "start-fails", enabled: "0", start: "1", started: true, fails: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			log := filepath.Join(directory, scenario.name+".log")
			command := exec.Command("/bin/sh", "-c", program)
			command.Env = append(os.Environ(), "LOG="+log, "ENABLED="+scenario.enabled, "START="+scenario.start)
			output, err := command.CombinedOutput()
			if (err != nil) != scenario.fails {
				t.Fatalf("udev program error = %v, want failure %t\n%s", err, scenario.fails, output)
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(string(calls), start) != scenario.started {
				t.Fatalf("systemctl calls = %q, want start %t", calls, scenario.started)
			}
		})
	}
}

// TestSBOMChecksPrivateHelper verifies dependencies in libexec-style package paths are checked.
func TestSBOMChecksPrivateHelper(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for SBOM checks")
	}
	directory := t.TempDir()
	staging := filepath.Join(directory, "staging")
	helper := filepath.Join(staging, "client", "payload", "usr", "lib", "neodse", "neodse-vnc-auth")
	if err := os.MkdirAll(filepath.Dir(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fakeGo := filepath.Join(directory, "go")
	if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nprintf '%s: go1.27.1\\n\\tdep example.com/helper v1.0.0 h1:test\\n' \"$3\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(directory, "sbom.json")
	for _, complete := range []bool{false, true} {
		data := `{"packages":[{"name":"stdlib","versionInfo":"go1.27.1"}`
		if complete {
			data += `,{"name":"example.com/helper","versionInfo":"v1.0.0"}`
		}
		data += `]}`
		if err := os.WriteFile(report, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(python, filepath.Join(repositoryRoot(t), "scripts", "check-package-sbom.py"), staging, report)
		command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"))
		output, err := command.CombinedOutput()
		if complete && err != nil {
			t.Fatalf("complete helper SBOM rejected: %v\n%s", err, output)
		}
		if !complete && (err == nil || !strings.Contains(string(output), "example.com/helper")) {
			t.Fatalf("missing helper dependency not detected: %v\n%s", err, output)
		}
	}
}
