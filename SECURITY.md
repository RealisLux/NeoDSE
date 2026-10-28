# NeoDSE security

## Reporting and support

Report vulnerabilities through [GitHub private vulnerability
reporting](https://github.com/RealisLux/NeoDSE/security/advisories/new). Include the
release or commit, setup and assumptions, reproduction steps and impact. Security
fixes cover the latest production release only.

## Security model

NeoDSE runs on Linux hosts managed by an administrator and connected through
WireGuard. The controller holds credentials, accounts, desired state, schedules
and proxy policy. Displays retain enrollment configuration and a local VNC TLS
identity. Browser state is temporary, under `/run/neodse-ui`.

| Boundary | Controls |
| --- | --- |
| Operator API | HTTPS, scoped bearer tokens, optional expiry, hashed token storage and redacted mutation/denial auditing |
| Administrator | Global account-management authority, including access grants to any agent; use other roles for scoped delegation. An administrator cannot remove its own access; root on the controller can restore one with `neodse-server recover-admin` |
| Database at rest | AES-256-XTS encrypts the SQLite file, WAL and journal with a random key; only an AES-256-GCM copy sealed under an Argon2id key from the administrator passphrase is stored. The controller starts locked; root unlocks it over a Unix socket that checks the peer UID |
| Agent messages | Unique 256-bit pre-shared keys (PSKs), purpose-separated session keys, session IDs, sequences and expiry |
| Network | Plain `ws://` requires loopback or an effective IPv4 WireGuard route; nonloopback plaintext sockets bind to that interface; agent connections from other hosts must come from the enrolled tunnel address; never expose port 8081 publicly |
| Connection admission | TCP socket limits apply before HTTP/TLS parsing, use the actual source address, and count upgraded connections until close. Management API traffic has a separate budget from local proxy authorization; per-display proxy quotas apply only after authentication |
| Web content | WebKit uses a loopback relay; the proxy checks each destination, resolves IPv4 and rejects prohibited address classes |
| Local control | Restricted Unix sockets, peer credentials, fixed executables/arguments and narrow sudo rules |
| Local live capture | Certificate-verified VeNCrypt TLS before one-use PAM authentication; root-controlled trust and private key delivered only to Weston |
| Services | Separate Unix identities, systemd confinement and Enterprise Linux SELinux policy |

Live views check the token, account, expiry and agent scope before streaming,
after capture starts and every five seconds. Revocation or a failed authorization
lookup ends the stream. A frame write can delay a periodic check by up to its
15-second deadline; authorization lookups time out after six seconds.

The transport is stateless and never receives agent PSKs. A disconnected display
can continue its in-memory content; after restart it waits for authenticated
reconciliation.

Clients use the distribution's WebKitGTK runtime. Apply distribution security
updates; package SBOMs do not cover host libraries. Releases include packages and
checksums; public releases also provide build provenance attestations. SPDX SBOMs
and build-time vulnerability reports are checked before publication and kept as
GitHub Actions artifacts for 90 days; access follows repository permissions.

Generic analysis uses maintained GitHub Actions; NeoDSE does not maintain the
analyzers' dependency graphs. Dependabot follows NeoDSE dependencies and the
Actions. Runtime source/binary scans, package SBOM coverage and high/critical
package findings remain publication gates. See the
[tooling policy](docs/DEVELOPMENT.md#dependencies) for configuration and updates.

## Secrets and rotation

Configuration loading rejects symlinks, unexpected ownership, overly broad
permissions and unknown fields. Keep tokens, PSKs, signatures, nonces and
provisioning blocks out of source code, command arguments, logs and support records.
NeoDSE's Go services, maintenance commands and VNC authentication helper disable
process core dumps before loading secrets. Host swap protection remains
necessary for maintenance commands, as described under
[residual risks](#residual-risks).

- Rotate service-account tokens through the API.
- Re-enroll an agent with server-side `provision-agent --force`.
- Rotate internal service PSKs during a maintenance window and restart both peers.
- Rotate the local VNC TLS identity using the [display configuration procedure](docs/CONFIGURATION.md#weston-drm-and-vnc-outputs); protect its private key in backups.
- The bootstrap certificate is valid for three years. Renew it before expiry with `neodse-server renew-certificate` as described in [certificate renewal](docs/OPERATIONS.md#certificate-renewal), then redistribute trust. Prefer an organizational CA in production.
- If every administrator token is lost or disabled, run `neodse-server recover-admin` on the controller; it issues a new token and invalidates the earlier tokens of that account.
- Change the database passphrase with `neodse-server change-passphrase`, as described in [unlocking the controller](docs/OPERATIONS.md#unlocking-the-controller). The database key stays the same, so an older keyslot backup still opens with its old passphrase.

## Operations

For [backups and restoration](docs/OPERATIONS.md#upgrades), stop database writers,
encrypt saved state and configuration, and test restoration on an isolated host.
Restored credentials regain their authority; rotate them if custody is uncertain.

If you suspect a compromise, isolate the peer, disable affected accounts, preserve
the database and journals read-only, verify the release checksum and rotate
credentials at the affected boundaries. Rebuild hosts whose integrity is uncertain.

To decommission a display, run `neodse-server remove-agent`, which also deletes its
web policy, then `neodse-agent remove-config` locally.

## Residual risks

- A compromised controller, root account or release path can control the fleet.
- Endpoint compromise and traffic analysis remain possible despite WireGuard.
- Public WireGuard UDP remains exposed to packet-rate and bandwidth flooding. Application socket limits do not protect an upstream link from saturation; use suitable upstream protection or explicitly accept that availability risk.
- Browser, graphics-driver and displayed-content vulnerabilities remain possible.
- HTTPS CONNECT allows an approved host and port. The proxy does not inspect TLS SNI or the encrypted HTTP Host header, so it cannot separate virtual hosts sharing that endpoint. Use dedicated trusted upstreams when you need this separation, and never approve an endpoint that provides an unrestricted relay.
- A copied database and keyslot are only as strong as the passphrase. The running controller holds the database key in memory, so root or memory access on that host exposes the data. Its unit disables swap and core dumps for that reason; do not override them. Root maintenance commands handle the same secrets outside the service's swap limit, so keep controller swap disabled or encrypted. NeoDSE does not encrypt the configuration secrets, TLS key or WireGuard keys under `/etc`; protect them with disk encryption.
- XTS encryption hides contents but does not detect tampering, and copies taken at different times reveal which 512-byte sectors changed. Restoring an older database and keyslot can bring back revoked authority.
- CEC, serial, audio, DNS and upstream content extend the trust boundary.

Review logs, backups, firewall rules and proxy grants regularly. Further guidance:
[operations](docs/OPERATIONS.md), [security review for code changes](docs/DEVELOPMENT.md#security-review)
and [release checks](docs/RELEASE.md).
