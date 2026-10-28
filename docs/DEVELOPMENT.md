# Development

For an overview, read the [README](../README.md).

[Prerequisites](#prerequisites) · [Build and test](#build-and-test) ·
[Build packages](#build-packages) · [Dependencies](#dependencies) ·
[Make changes](#make-changes) · [Security review](#security-review)

## Prerequisites

Install **Go 1.27.3** from [Go downloads](https://go.dev/dl/) and verify the archive
checksum. Put its `bin` directory first on `PATH`, then check both `go version`
and `GOTOOLCHAIN=local go version`. Make and CI disable automatic toolchain
switching: a plain `go version` can report a downloaded toolchain even when the
executable on `PATH` is older. Distribution Go packages may also be older.

Go programs use `CGO_ENABLED=0`. The C17 renderer uses distribution packages for
GTK 4, the `webkitgtk-6.0` API and JSON-GLib. Enable security/updates repositories
before installing development packages; `make verify-native-dependencies` checks
the required libraries through `pkg-config`.

On Debian 13 or Ubuntu 26.04:

```bash
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  ca-certificates curl git make gcc clang libclang-rt-dev clang-format-19 \
  clang-tidy cppcheck nodejs python3 python3-gi weston iproute2 util-linux \
  libpam-modules openssl pkg-config shellcheck dpkg libarchive-tools \
  libgtk-4-dev libwebkitgtk-6.0-dev libjson-glib-dev
```

## Build and test

From the repository root:

```bash
make all
make verify
make verify-security
make verify-release-tests
make fuzz-smoke FUZZ_TIME=15s
make security-coverage
make verify-native
make verify-native-sanitize BUILD_DIR=build/sanitized
```

| Gate | Coverage |
| --- | --- |
| `make verify` | Module integrity, formatting, vet, Go/race, shell/workflow/package/OpenAPI contracts and JavaScript tests |
| `make verify-release-tests` | Go JSON evidence; rejects missing prerequisites, truncated results and unexpected skips |
| `make verify-security` | Staticcheck, gosec and source/binary vulnerability scans for NeoDSE runtime programs |
| `make verify-tool-vulnerabilities` | Independent maintenance audit of pinned tool sources and binaries; reports in `build/tool-audit/` |
| `make security-coverage` / `make fuzz-smoke` | Security coverage floors and parser/validation fuzz targets |
| Native checks | GCC/Clang warnings, C formatting, parser, IPC and playlist tests, and ASan/UBSan |

Release unit checks defer browser, Weston/PAM and fleet tests to separate
mandatory gates. Contract tests bypass Go's result cache so workflow, packaging
and script changes are included.

Browser and fleet gates require their named test to pass. They save Go JSON
results to `build/dashboard-browser-tests.jsonl` and `build/fleet-tests.jsonl`
(or the selected `BUILD_DIR`). The production fleet phase below writes to
`build/fleet-production/fleet-tests.jsonl`, keeping race results intact.
On failure, the result checker prints the package's retained test output,
including assertions, race reports and panic stacks. CI uploads unit/fleet JSON
and `fleet.log` in `go-coverage`; browser JSON and diagnostics are in
`renderer-lifecycle-gcc` and `renderer-lifecycle-clang`, even when a gate fails.
Inspect the first rejection or assertion before the subsequent connection errors.

Outputs go to `build/`. Go uses `gofmt`; C uses clang-format 19:

```bash
clang-format-19 -i ui/*.c ui/*.h ui/tests/*.c
```

### Integration checks

On an isolated Linux test host with the prerequisites above:

```bash
make verify-dashboard-browser
make verify-weston-vnc
make verify-wireguard-sockets WIREGUARD_TEST_RUNNER=sudo
make integration INTEGRATION_RACE=true INTEGRATION_DURATION=10m INTEGRATION_TIMEOUT=15m
CGO_ENABLED=0 make integration INTEGRATION_RACE=false INTEGRATION_DURATION=10m \
  INTEGRATION_TIMEOUT=15m BUILD_DIR=build/fleet-production
sudo python3 scripts/check-renderer-lifecycle.py --output build/renderer-lifecycle \
  build/neodse-ui build/sanitized/neodse-ui-sanitize
```

The browser check decodes real JPEG frames under the production CSP and tests
scope changes, stale requests and logout cleanup. Weston/PAM tests run in isolated
namespaces: they cover certificate creation/renewal, unsafe trust files, untrusted
servers, and valid, invalid, replayed and unavailable-authority cases. Where
unprivileged namespaces are restricted, use
`make verify-weston-vnc WESTON_TEST_RUNNER=sudo`. Never invoke its internal
`--isolated` entry point directly. Test physical DRM mirroring separately.

The WireGuard check tests listener/connection binding, alternate routes and
interface removal. It creates a private network namespace as root, then runs
socket operations as an unprivileged user with no capabilities. Normal services
need no added capabilities. Do not invoke the runner's internal `--isolated`
entry point directly.

The fleet has 100 simulated displays, including one slow peer. It disconnects
agents every five cycles, rotates credentials every 18 and replaces the controller
link every 24 after cycle zero. Connection-close logs at those points are expected;
reconciliation must still pass. Each workload round includes 99 one-frame 720p
JPEG viewers. This does not measure continuous high-motion video capacity.
Viewers check exact fixture bytes and JPEG dimensions without decoding every
pixel buffer in the same process as the controller and transport.

CI runs both ten-minute fleet phases. The race phase checks heap, workers and
descriptors; its resident memory includes race detector allocations. The non-race
phase disables CGO, matching packaged Go programs, and checks resident growth
against the initial baseline plus 256 MiB. These samples measure neither peak
memory nor long-term capacity.

Use a longer soak when lifecycle, timer or retention changes carry a risk that
needs more time to appear, when resource growth is unexplained, or when a
deployment needs endurance evidence. Choose a duration that covers the relevant
timers and workload. [RELEASE.md](RELEASE.md#evidence) gives an example and
installed-target acceptance criteria.

## Build packages

Build on the target distribution, major version and architecture:

- Debian 13 / Ubuntu 26.04: client/server DEBs for amd64 and arm64.
- EL9 / EL10: server RPMs for amd64.

The client uses the distribution's Weston packages. Local builds run tests unless
`--skip-tests` is supplied, then write packages and per-package checksums to
`dist/`. Release CI also checks and retains SPDX SBOMs and vulnerability reports,
and adds build provenance attestations for public releases. Downloads contain
packages and checksums only.

```bash
make package-local VERSION=1.0.0 COMPONENT=all FORMAT=deb
```

Replace `1.0.0` with your version. Run `bash scripts/build-local-packages.sh --help`
for options. Filenames include the version, such as
`NeoDSE-client_1.0.0_debian13_amd64.deb`. Sidecars append `.sha256`, `.spdx.json`
or `.vulnerabilities.json` to the full package filename.

To produce local SBOM and vulnerability evidence for a Debian 13 client package:

```bash
make sbom-tools
package=dist/NeoDSE-client_1.0.0_debian13_amd64.deb
bash scripts/stage-package-sbom.sh build/package-sbom "${package}"
read -r package_sha256 _ < <(sha256sum "${package}")
build/tools/syft scan dir:build/package-sbom --source-name "sha256:${package_sha256}" \
  -o "spdx-json=${package}.spdx.json"
python3 scripts/check-package-sbom.py build/package-sbom "${package}.spdx.json"
build/tools/grype "sbom:${package}.spdx.json" --distro debian:13 \
  --fail-on high --output json --file "${package}.vulnerabilities.json"
```

For other targets, change the package path and Grype distribution as in the
[release workflow](../.github/workflows/release.yml). The SBOM name and Grype
source must both contain the package archive's SHA-256. Keep evidence from the
same build and scan; [RELEASE.md](RELEASE.md) lists the matrix and publication checks.

Check only the artifacts you built:

```bash
(cd dist && sha256sum --check NeoDSE-client_*.deb.sha256)
(cd dist && sha256sum --check NeoDSE-server_*.deb.sha256)
```

### Server RPMs

Use an amd64 EL9/EL10 host matching the target, with the exact Go toolchain.
RHEL, Rocky Linux, AlmaLinux and CentOS Stream are supported build bases.
SELinux policies are compiled against the target's development files.

```bash
sudo dnf install -y git-core ca-certificates make curl python3 tar gzip \
  selinux-policy-devel policycoreutils-devel
go env GOARCH  # must report amd64
make package-local VERSION=1.0.0 COMPONENT=server FORMAT=rpm
(cd dist && sha256sum --check NeoDSE-server_*.rpm.sha256)
rpm -qpl dist/NeoDSE-server_*.rpm
```

Set `SELINUX_DEVEL=/path/to/selinux/devel` for a nonstandard policy directory.
Install on a disposable matching host with SELinux enforcing, verify the module
and package, and review AVC denials. Never accept generated `audit2allow` rules
without inspecting each requested access. See [deployment](DEPLOYMENT.md#install)
and the [release checklist](RELEASE.md).

## Demo animation

The README GIF is a silent illustration built from the shipped logo animations
and the SVG scene in [render-demo.py](../scripts/render-demo.py). To regenerate
it, install FFmpeg with its `librsvg` decoder, then run:

```bash
python3 scripts/render-demo.py --preview-dir build/demo
```

The preview directory contains selected SVG/PNG frames. Keep the timeline aligned
with the waiting screen, playlist and overlay code in `ui/`. Banners, sound and
serial lights are separate per-display commands; light-off is explicit.

## Dependencies

| Runtime Go module | Purpose |
| --- | --- |
| `github.com/ncruces/go-sqlite3` | SQLite translated to pure Go, with the AES-XTS VFS that encrypts the controller database |
| `github.com/gorilla/websocket` | Bounded controller/agent WebSocket framing |
| `go.yaml.in/yaml/v3` | Strict local configuration |
| `golang.org/x/crypto` | XTS mode for the database and Argon2id for its passphrase |
| `golang.org/x/sys` | Linux CEC system calls, deadline-bound serial configuration and terminal control |

The SQLite driver is a v0 module: a minor release may change its API or its
encryption VFS. Deployed databases depend on the on-disk format, which
`TestDatabaseFormatIsAES256XTS` decrypts independently of the driver. Never
relax that test to accept an update; a format change would leave every existing
database unreadable.

The store wraps the driver's public XTS VFS in
[vfs.go](../internal/store/vfs.go) to reject symbolic-link resolution before
its no-follow file opens. Keep `TestOpenRefusesSymlinks` passing when updating
the driver: root maintenance commands also open this service-owned database.

The wrapper also synchronizes the parent directory when it creates a WAL or
journal, and after the initial database reservation. The driver does not:
`(*vfsFile).Sync` in `go-sqlite3 v0.35.6`'s `vfs/file.go` opens the parent
directory but syncs the file again, and ignores a failed directory open. Without
the wrapper, a new journal name may not survive power loss despite
`synchronous=FULL`. `TestJournalDirectorySyncPrecedesWrites` checks real
encrypted writes and fails when directory synchronization fails. On driver
updates, keep it passing, and remove the workaround only after upstream syncs new
directory entries and reports failures.

GTK, WebKitGTK, JSON-GLib, Weston, ALSA, WireGuard, systemd and SELinux are
distribution dependencies. HDMI-CEC uses the kernel ABI directly.
`tools/analysis` pins Actionlint, Staticcheck and govulncheck; `tools/security`
pins gosec; `tools/packaging` pins nFPM; `tools/sbom` pins Syft and Grype.
These tool graphs stay out of runtime programs and installed packages. Gosec's
optional AI autofix is disabled.

Release scanners are built from their pinned modules with the reviewed Go
toolchain; no precompiled binaries are downloaded. `make sbom-tools` builds them
without coupling publication to advisories in their dependency graphs. Scanner
execution, SBOM coverage and high/critical package-payload findings remain
mandatory release gates. Scanner and runtime binaries keep their symbol tables
(runtime builds strip only DWARF data), so binary scans report precise symbols.

The independent **Tooling maintenance** workflow runs on pull requests, tool
changes on main/dev, a weekly schedule and manual dispatch. It checks tool module
integrity and runs `make verify-tool-vulnerabilities`, retaining separate source
and binary reports for 90 days even when findings fail the audit. Scanner source
scans remain strict at package level, including the scoped Docker SDK assessment
in [SECURITY_EXCEPTIONS.md](SECURITY_EXCEPTIONS.md). `make verify-sbom-tools`
remains available for a scanner-only audit. No new exception is needed merely
to unblock a product release.

`make verify-go` verifies the runtime module. `make verify-tool-modules` verifies
the four isolated tool modules; `make verify-modules` checks all five. Product
checks still fail if a required validator cannot build or execute.

Configure branch rules to require the CI product jobs, not `tool-audit` or
`dependency-review` from Tooling maintenance. Release publication does not depend
on that workflow. Its failures still need assessment: a build-tool vulnerability
can affect CI or release integrity even when absent from installed packages.
This policy accepts that risk separately from product vulnerability gates.

Tool downloads, build caches and the Grype database need several gigabytes beyond
runtime outputs. If the filesystem fills up, free space and rerun the affected
gate; a partial test or scan does not count as a pass. `go clean -cache` removes
regenerable Go build data.

Swagger UI 5.33.3 is vendored with licenses, provenance and checksums in
[its vendor record](../internal/swagger/vendor/README.md).
Before adding a dependency, check its maintenance, license, vulnerabilities and
transitive modules, and explain why existing code or libraries are insufficient.
Record analyzer exceptions and accepted advisories for build tools or vendored
components in [SECURITY_EXCEPTIONS.md](SECURITY_EXCEPTIONS.md).

### Update Go dependencies

Work on a maintenance branch. Update direct dependencies to their latest stable
releases without `-u`; leave unrelated indirect dependencies unchanged. Review
any indirect changes required by a direct update. For the runtime module,
Dependabot continues weekly updates. For the tools, monthly grouped updates
allow only the seven owning tool modules by name (Go may mark these `indirect`
even though they are explicit `tool` commands). Update their transitive graphs
through the owning tool; avoid `go get -u` and blanket overrides of indirect
versions. Resolve tool findings through a tested upstream upgrade where possible.
CI and release builds use the committed versions.

1. **Update the five runtime modules**, from the repository root. Like Make and
   CI, set `GOTOOLCHAIN=local`: an update that needs a newer Go release then
   stops with `requires go >= ...` instead of downloading another toolchain and
   raising the `go` line. In that case, [update Go](#update-go) first.

   ```bash
   export GOTOOLCHAIN=local
   go get github.com/gorilla/websocket@latest github.com/ncruces/go-sqlite3@latest \
     go.yaml.in/yaml/v3@latest golang.org/x/crypto@latest golang.org/x/sys@latest
   ```

2. **Tidy, review and validate:**

   ```bash
   go mod tidy
   git diff -- go.mod go.sum
   make verify-modules
   make all verify verify-security verify-release-tests
   ```

Check that the selected versions are stable and review their release notes,
licenses and module changes. Keep major-version migrations separate: `@latest`
uses the existing module path. Never force an incompatible dependency with
`replace`. If validation fails, fix the update or retain the previous module
files. Commit matching `go.mod` and `go.sum` files; `go.sum` checks contents,
not version selection.

Run affected native/integration checks and [rebuild packages](#build-packages)
before merging; dependency changes also affect notices, SBOMs and vulnerability
evidence. An update may require a newer Go compiler or source changes.

### Update development tools

From the repository root, update all seven tools in their own modules, then tidy
and review the module files. `GOTOOLCHAIN=local` has the same purpose as above:

```bash
export GOTOOLCHAIN=local
go -C tools/analysis get github.com/rhysd/actionlint@latest \
  golang.org/x/vuln@latest honnef.co/go/tools@latest
go -C tools/analysis mod tidy
go -C tools/security get github.com/securego/gosec/v2@latest
go -C tools/security mod tidy
go -C tools/packaging get github.com/goreleaser/nfpm/v2@latest
go -C tools/packaging mod tidy
go -C tools/sbom get github.com/anchore/syft@latest github.com/anchore/grype@latest
go -C tools/sbom mod tidy
git diff -- tools/*/go.mod tools/*/go.sum
make verify-modules
make verify-tool-vulnerabilities
```

These are the tool modules listed below. Their entry modules may be marked
`// indirect` because Go records the executable packages with `tool`
directives; these are still the tools the project explicitly uses.

| Directory | Modules to update |
| --- | --- |
| `tools/analysis` | `github.com/rhysd/actionlint`, `golang.org/x/vuln`, `honnef.co/go/tools` |
| `tools/security` | `github.com/securego/gosec/v2` |
| `tools/packaging` | `github.com/goreleaser/nfpm/v2` |
| `tools/sbom` | `github.com/anchore/syft`, `github.com/anchore/grype` |

Apply the same stable-release, indirect-dependency and validation rules as above.
Do not update dependencies during release jobs.

The reviewed Docker SDK exception applies only to the exact Docker and
credential-helper versions it names, so a Grype update that keeps them passes
unchanged. If an update changes them or adds findings, the independent
`make verify-tool-vulnerabilities` and `make verify-sbom-tools` audits stop with
`Affected scanner package`. Review the new
findings against [the exception](SECURITY_EXCEPTIONS.md#go-2026-4883); if it
still holds, update the versions together in that register,
`scripts/check-scanner-vulnerabilities.py` and
`internal/quality/scanner_evidence_test.go`. Otherwise, keep the previous tool
versions or document a separately reviewed tooling risk assessment.

Dependabot update configuration does not disable dependency-graph alerts.
The tool allow lists also restrict automatic security-update PRs to the named
tools; transitive findings still appear as alerts and in the tooling audit.
[GitHub documents these options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).
Do not disable repository-wide alerts or dismiss everything under `tools/`.
For each alert, inspect its manifest path, the affected package and the actual
command usage; a Docker daemon advisory in an optional scanner SDK is distinct
from a vulnerability shipped in NeoDSE. Record scoped dismissals with the owning
tool, evidence and a review trigger. Go module alerts cannot reliably distinguish
development dependencies using `scope:development`, so use manifest paths.
The all-manifest dependency review also lives in Tooling maintenance; its
vulnerability and license findings are maintenance signals. Product vulnerability
scans remain mandatory, and product license changes require manual review.

### Update Go

Install the reviewed stable Go release and confirm `GOTOOLCHAIN=local go version`.
Set that version in all five module files:

```bash
version=1.27.3 # replace with the reviewed release
go mod edit -go="${version}"
go -C tools/analysis mod edit -go="${version}"
go -C tools/security mod edit -go="${version}"
go -C tools/packaging mod edit -go="${version}"
go -C tools/sbom mod edit -go="${version}"
```

Update the version in this guide and every exact `go-version` passed to
`actions/setup-go` in the CI, quality, CodeQL and release workflows;
`git grep -n "go-version: '" .github/workflows` lists them. Then run the
validation gates above. Leave the forward-compatibility job on `stable`: it
tests committed dependencies with current stable Go, without upgrading them or
qualifying native libraries.

Pin Actions to full commits and release containers to reviewed multi-architecture
digests. Dependabot proposes Action updates but not the container digests in
`.github/workflows/release.yml`. To refresh one, read the digest of the image's
multi-architecture index and confirm it lists every required architecture
(`amd64` and `arm64` for Debian and Ubuntu, `amd64` for Rocky Linux), for example
with `docker buildx imagetools inspect debian:13`. Replace every occurrence of
the old digest, then run `go test ./internal/quality`. Review distribution
library/security updates on real targets, and update clang-format's major
version in Makefile and CI together.

## Make changes

Keep each change focused. Add regression tests for changed behavior, including
denial and dependency failure at security boundaries. Update OpenAPI and the
relevant administrator or operator guides when changing the API, configuration,
provisioning or upgrade behavior.

Run `make verify` for every change. Add `make verify-security` for Go or
dependency changes and `make verify-native verify-native-sanitize` for C changes.
Run the browser, Weston or fleet checks when those paths change. Changes to
authentication, authorization, protocol, proxy, provisioning, schema, workflows
or privilege policy also need a [security review](#security-review).

Text uses UTF-8 and LF; JavaScript and Python use two and four spaces
respectively. Keep binaries, packages, logs, credentials and deployment databases
out of commits.

Shell and Python scripts owned by the project start with their shebang, then
`File purpose:`, `Copyright`, `SPDX-License-Identifier:` and `Project:` comment
lines in that order, then a blank line. Keep Python module docstrings after this
header. Preserve upstream headers in third-party files.

Follow the [release checklist](RELEASE.md) before tagging.

## Maintain contracts

Some `internal/quality` tests check exact source strings, such as a socket dial
or a systemd directive. A harmless refactor can therefore fail a contract check.
Read the failing test and verify that the underlying security behavior still
holds, including its behavioral regression tests, before updating the expected
string. Do not remove or weaken a guard just to make the check pass.

- **Database:** add contiguous immutable migrations for schema changes; never edit
  an applied migration. Keep queries in `internal/store`, use STRICT tables,
  constraints and prepared parameters, and test migration/rollback/retention
  behavior. Commit state before delivery; store transient commands in canonical
  `command_json`.
- **Protocol:** a breaking change increments the version and replaces the contract
  across controller, agent, tests and architecture documentation. Authenticate
  session/sequence fields; never persist session data or signatures as desired state.
- **Network admission:** keep `internal/netlimit` below HTTP and TLS parsing.
  Count hijacked WebSocket/CONNECT sockets until close, use only the actual
  network source for pre-authentication quotas, and keep management API and
  loopback authorization budgets separate. Preserve raw listeners for WireGuard
  supervision. Regression tests must cover incomplete headers, source isolation,
  concurrent close and admission recovery after upgraded connections finish.
- **API:** change handlers and OpenAPI together. Keep bounded object-only JSON,
  content types, unknown-field rejection, method limits, scoped RBAC and
  `{code,message,request_id}` errors. Test denial and dependency failure.
- **Swagger:** follow the vendor provenance record, preserve bundled notices and
  update `MANIFEST.sha256`. Retain `validatorUrl: null`,
  `persistAuthorization: false` and CSP/header tests.
- **Packages:** keep client runtime state in the documented volatile `/run`
  directories and server state under `/var/lib/neodse`. Keep upgrades/removals
  safe and sudoers narrow. Compile each EL policy on its target and inspect
  actual service sandboxes and SELinux denials.

## Security review

Request an in-depth review when changing authentication, authorization, protocol,
proxy, provisioning, schema, workflows or privilege policy. In the change
description, explain the trust boundary, input limits, failure behavior and regression tests.

Never log bodies, tokens, PSKs, session identifiers, signatures, nonces or
provisioning blocks. Install `internal/logging` before application code. Keep
proxy request summaries at `verbose`/`debug`, and test single-summary behavior,
control-character neutralization and secret/source/path/query exclusion.

Coverage floors catch regressions but cannot prove every decision outcome.
Test denials and dependency failures, and review package floors when extending
security-sensitive code. Each analyzer suppression needs a unique `EXC-*` entry
with owner, scope, rationale and evidence in
[SECURITY_EXCEPTIONS.md](SECURITY_EXCEPTIONS.md).

Review source and history for credentials before publication; rotate any exposed
secrets. See [SECURITY.md](../SECURITY.md) for reporting/response and
[RELEASE.md](RELEASE.md) for publication gates.
