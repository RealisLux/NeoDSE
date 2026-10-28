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

## Runtime module advisories

### GO-2026-5932

- Advisory: [Go vulnerability database](https://pkg.go.dev/vuln/GO-2026-5932).
- Scope: NeoDSE requires `golang.org/x/crypto v0.58.0` for database encryption's `xts` and `argon2` packages. The advisory concerns the deprecated `openpgp` package, which has no fixed version.
- Reachability evidence: source and runtime binary scans report no affected imported packages or symbols; NeoDSE does not import or link `openpgp`.
- Decision: retain the dependency while the advisory remains module-only. A reachable runtime finding blocks publication. This adds no scanner suppression.
- Review triggers: changes to `github.com/ncruces/go-sqlite3`, `golang.org/x/crypto`, runtime linker flags or the advisory's affected-package scope.
- Removal condition: remove this entry when the runtime module no longer requires an affected module version or a maintained replacement eliminates the advisory.

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
