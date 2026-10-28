# Security analyzer exceptions

This register is the authority for source-level security analyzer suppressions. A
suppression is accepted only when its identifier appears exactly once in production Go
or C source and once in this file. The quality test rejects missing, duplicated, or
stale entries. The register also records accepted advisories in build tools and
vendored components. Re-evaluate entries when the cited data flow, dependencies or
advisory scope changes.

## Active exceptions

### EXC-VNC-AUTH-SOCKET-GROUP

- Rule: gosec `G302`
- Scope: `internal/agent/vnc_auth.go`, local authentication socket mode
- Rationale: the socket is intentionally `0660`, owned by `neodse-agent:neodse-ipc`; Weston invokes the unprivileged PAM helper as `neodse-ui`, which requires group write access. The agent additionally authenticates every peer with Linux `SO_PEERCRED`, accepts only the exact `neodse-ui` UID, bounds requests, and consumes random stream-bound credentials once.
- Regression evidence: `TestVNCAuthConnectionRejectsWrongUIDAndConsumesCredential` verifies kernel-credential enforcement and one-use consumption; package quality tests verify the dedicated group membership and PAM helper path.

### EXC-CEC-LINUX-ABI

- Rule: gosec `G103`
- Scope: `internal/cec/device_linux.go`, Linux CEC ioctl binding
- Rationale: the Linux CEC userspace ABI requires pointers to fixed-layout values. NeoDSE passes only its own bounded `cec_caps`, `cec_log_addrs`, `cec_msg`, and `uint16` storage to fixed CEC ioctl numbers; no request-controlled pointer or size is used.
- Regression evidence: `TestLinuxABILayout` verifies every ABI structure size and ioctl number on supported architectures; protocol tests inspect the exact bounded messages.

### EXC-AGENT-SYSTEM-COMMAND

- Rule: gosec `G204`
- Scope: `internal/agent/commands.go`, `runFixedSystemctl`
- Rationale: the process is the fixed `/usr/bin/sudo`; a closed switch selects one of two fixed `systemctl` host-power argument lists, and UI restart uses a fixed service name. No request value reaches the executable or arguments.
- Regression evidence: `TestRunSystemCommandRejectsArbitraryInput`; exact sudoers commands are checked during package validation.

### EXC-AGENT-AUDIO-COMMAND

- Rule: gosec `G204`
- Scope: `internal/agent/hardware.go`, `playSound`
- Rationale: the executable is fixed to `/usr/bin/aplay`; the configured absolute media path is one argument placed after `--`, with no shell interpretation.
- Regression evidence: `TestHardwareHelpersRejectUnknownCommandsBeforeExecution`; configuration tests reject relative sound paths.

### EXC-AGENT-SERIAL-DEVICE

- Rule: gosec `G304`
- Scope: `internal/agent/serial_linux.go`, `openSerialPort`
- Rationale: the normalized absolute device path comes from local configuration whose ownership and permissions are checked by the configuration loader; API requests cannot supply it. The nonblocking open does not create or truncate files. Fixed termios ioctls reject non-tty targets before command data is read or written, and the Go runtime bounds tty I/O by deadlines and shutdown cancellation. Device symlinks remain supported for stable `/dev/serial/by-id` configuration.
- Regression evidence: `TestSerialPortRejectsInvalidConfigurationAndNonTTY` rejects ordinary files and verifies failed opens release descriptors; real-tty tests verify command framing, write/read deadlines, shutdown cancellation, and exclusive-access cleanup.

### EXC-PROVISIONING-COMMAND

- Rule: gosec `G204`
- Scope: `internal/provisioning/system.go`, `Run`
- Rationale: the executable path comes only from a four-entry in-process allowlist of absolute paths; unknown names are rejected before process creation.
- Regression evidence: `TestRunRejectsUnlistedExecutable`; provisioning parsers validate every value before it becomes an argument.

### EXC-PROXY-AUTHORIZED-DIAL

- Rule: gosec `G704`
- Scope: `internal/proxy/handler.go`, `forwardHTTP`
- Rationale: SQLite policy authorization occurs before forwarding. The custom transport resolves once, rejects every prohibited address, and dials the approved IP directly, preventing DNS rebinding between validation and connection.
- Regression evidence: `TestSafeDialRejectsLocalAndMalformedDestinations`, `TestAuthorizeFailsClosedOnInvalidBackendResponses`, and `TestHTTPRedirectIsReturnedToClient`.

## Build-tool advisories

### GO-2026-5932

- Advisory: [Go vulnerability database](https://pkg.go.dev/vuln/GO-2026-5932).
- Scope: the isolated `tools/security`, `tools/packaging` and `tools/sbom` graphs require `golang.org/x/crypto v0.57.0`. The runtime module requires `golang.org/x/crypto v0.58.0` for the `xts` and `argon2` packages of database encryption. The deprecated `openpgp` package has no fixed version.
- Reachability evidence: source `govulncheck` scans of the root module and of the pinned `gosec`, `nfpm`, `syft` and `grype` commands report zero affected imported packages for this advisory. Binary symbol scans also report no affected symbols. The affected `openpgp` package is not linked into any NeoDSE runtime binary or installed package; runtime binaries keep their symbol table so binary scans can show this.
- Decision: retain the dependency while the advisory remains module-only and unreachable. A reachable runtime finding blocks publication; a tool finding fails the independent tooling audit.
- Review triggers: changes to `gosec`, `nfpm`, `syft`, `grype`, `github.com/ncruces/go-sqlite3`, `golang.org/x/crypto`, runtime linker flags or the advisory's affected-package scope.
- Removal condition: remove this entry when neither the tool graphs nor the runtime module require the affected module, or a maintained replacement eliminates the advisory.

### GO-2026-4883

Shared assessment of Docker daemon advisories in Grype's SDK dependency.

- Advisories: [GO-2026-4883](https://pkg.go.dev/vuln/GO-2026-4883), [GO-2026-4887](https://pkg.go.dev/vuln/GO-2026-4887), [GO-2026-5617](https://pkg.go.dev/vuln/GO-2026-5617), [GO-2026-5668](https://pkg.go.dev/vuln/GO-2026-5668), and [GO-2026-5746](https://pkg.go.dev/vuln/GO-2026-5746).
- Scope: Grype in `tools/sbom` imports the legacy Docker `v28.5.2+incompatible` client and API types for optional local-image completion, plus Docker credential helpers `v0.9.8`. It does not import Docker daemon or plugin-execution code.
- Rationale: the first two unreviewed Go records omit affected-package metadata and attribute daemon plugin flaws to every SDK package. The upstream advisories describe [daemon plugin privilege validation](https://github.com/moby/moby/security/advisories/GHSA-pxq6-2prw-chj9) and [daemon authorization plugins](https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2). The other three findings concern daemon archive/copy code and remain module-only. No Docker dependency enters NeoDSE runtime packages.
- Decision: the validator accepts only the first two IDs, only in Grype scans, only for this exact Docker version, only for `client`, `api`, `api/types` and its children, and only while the advisory's affected-package metadata remains empty. Binary mode additionally accepts their attribution to the exact credential-helper version's `client` and `credentials` packages. Daemon packages, changed Docker or helper versions, changed scope and unrelated findings all fail closed in both source-package and binary-symbol scans. The assessment concerns the Docker SDK, so a Grype update that keeps these versions and this scope needs no change here. Scanner builds retain symbols so binary scans do not fall back to module-only attribution. These exceptions do not apply to package-payload Grype reports or any NeoDSE runtime scan.
- Regression evidence: scanner-evidence tests exercise unexpected advisories, daemon imports, version/scope changes and malformed evidence. Actual source-package and binary scans run in the independent tooling audit and via `make verify-sbom-tools`; they do not gate publication.
- Review triggers: changes to Grype's Docker dependency, Docker, Docker credential helpers, govulncheck or the advisory's affected-package scope.
- Removal condition: remove these exceptions when Grype migrates completion to the maintained Moby SDK or the Go advisory records gain accurate package scope.

## Vendored component advisories

### GHSA-cg2g-xh64-v4q7

Shared assessment of DOMPurify advisories in the vendored Swagger UI bundle.

- Advisories: [GHSA-cg2g-xh64-v4q7](https://github.com/advisories/GHSA-cg2g-xh64-v4q7) (critical), [GHSA-mrv2-3pqr-j5jr](https://github.com/advisories/GHSA-mrv2-3pqr-j5jr) (high) and [GHSA-c6gr-qvv4-5v3f](https://github.com/advisories/GHSA-c6gr-qvv4-5v3f) (low). Each affects DOMPurify 3.4.16 and earlier and is fixed in 3.4.17.
- Scope: `internal/swagger/vendor/swagger-ui-bundle.js` from Swagger UI 5.33.3 bundles DOMPurify 3.4.16, and the server serves it at `/docs/`. No Swagger UI release bundles DOMPurify 3.4.17 yet; 5.34.0, the latest on 2026-10-23, still requires `^3.4.16`. Package SBOM scans do not identify components inside the minified bundle, so this entry is the only record.
- Rationale: each advisory requires a sanitizer mode that Swagger UI does not use: `SAFE_FOR_TEMPLATES` with DOM output (critical), live-node `IN_PLACE` sanitization with a hook that removes nodes (high), or XHTML parsing through `PARSER_MEDIA_TYPE` (low).
- Reachability evidence: the bundle's only `sanitize` call passes rendered Markdown as a string to the default HTML parser and returns a string; it sets only `ADD_ATTR`, `FORBID_TAGS`, `ALLOW_DATA_ATTR` and `FORBID_ATTR`. Its only hook adds `rel="noopener noreferrer"` to links and removes nothing. NeoDSE loads only the embedded `/openapi.yaml`, leaves `queryConfigEnabled` at its `false` default and serves the page with `connect-src 'self'`.
- Decision: keep the unmodified, checksummed bundle; never patch distribution files.
- Review triggers: a Swagger UI update, changes to `swagger-init.js`, the specification source, query configuration or Content-Security-Policy, and new DOMPurify advisories.
- Removal condition: remove this entry after updating to an official Swagger UI release that bundles DOMPurify 3.4.17 or newer.
