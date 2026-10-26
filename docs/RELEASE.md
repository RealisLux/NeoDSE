# Release checklist

Use this checklist for stable and prerelease tags. See
[DEVELOPMENT.md](DEVELOPMENT.md) for build/test commands,
[DEPLOYMENT.md](DEPLOYMENT.md) for installation, and
[OPERATIONS.md](OPERATIONS.md#upgrades) for rollout.

## Repository controls

- Protect `main`, `dev` and `v*` tags and require CI.
- Configure production release with permitted deployment tags. Enable immutable releases.
- Enable Dependabot, dependency review, secret scanning/push protection and
  private vulnerability reporting. Keep default workflow permissions read-only
  and credentials out of build jobs.

Configure these protections in GitHub; workflow YAML does not create them.
Check [environment availability](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
and [immutable release protections](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
before enabling publication.

## Evidence

On the exact release commit:

- Pass formatting, vet, unit/race/fuzz tests, security coverage, Staticcheck,
  gosec, source/binary/tool govulncheck, actionlint, ShellCheck, C analysis and
  sanitizers, OpenAPI and package lifecycle checks.
- Pass `make verify-wireguard-sockets WIREGUARD_TEST_RUNNER=sudo` to verify
  unprivileged interface binding and rejection of plaintext fallback after
  WireGuard removal.
- Run `make verify-release-tests` with all unit-test prerequisites installed.
  Retain its JSON evidence and run all three deferred integrations separately;
  unexpected skips fail validation.
- Resolve reachable vulnerabilities and high/critical findings. Record accepted
  exceptions with owner, rationale, scope and evidence in
  [SECURITY_EXCEPTIONS.md](SECURITY_EXCEPTIONS.md). Publication rejects
  high/critical package findings in both Grype's active and ignored lists.
  Scans must include all fix states, including won't-fix, and all package paths.
  Ignore rules and VEX cannot bypass the gate; a package exception needs a
  separately reviewed policy change.
- Review dependencies, action/image pins, Swagger assets, licenses, notices,
  package contents and SBOMs. Check that docs, provisioning, configuration,
  OpenAPI, service units and SELinux policy agree.
- Build Syft and Grype from `tools/sbom` with the pinned Go toolchain and pass
  `make verify-sbom-tools`. Upstream release labels alone cannot verify their
  Go runtime or transitive dependencies. Set Grype's target distribution
  explicitly: extracted payloads lack OS-release metadata. Set Syft's
  `--source-name` to `sha256:` plus the package archive's SHA-256, then scan that
  SBOM directly with Grype. Publication checks both reports for the same package
  identity to reject mixed evidence. This metadata relies on trusted CI; it
  neither signs the SBOM nor proves its bytes stayed unchanged after scanning.
- Check host-library advisories and record exact installed versions. Package
  SBOMs do not cover the host's GTK/WebKit, Weston, PAM, graphics stack or kernel.
  Apply distribution security updates and repeat native/browser qualification
  after library updates.

Run and retain both fleet tests:

```bash
make integration INTEGRATION_RACE=true INTEGRATION_DURATION=10m INTEGRATION_TIMEOUT=15m
CGO_ENABLED=0 make integration INTEGRATION_RACE=false INTEGRATION_DURATION=10m \
  INTEGRATION_TIMEOUT=15m BUILD_DIR=build/fleet-production
```

The first checks race stress. The second matches packaged Go programs by disabling
CGO and checks resident-memory growth across 100 simulated displays. CI runs both
and keeps separate results. Ten-minute tests cannot establish long-term capacity
or detect growth that takes hours to appear.

Run a longer soak when lifecycle, timer or retention changes could fail only over
time, resource growth is unexplained, or the deployment requires endurance evidence.
Cover the relevant timers and workload; for example, this runs for 24 hours with
less frequent bursts:

```bash
CGO_ENABLED=0 make integration INTEGRATION_RACE=false INTEGRATION_DURATION=24h \
  INTEGRATION_TIMEOUT=25h INTEGRATION_INTERVAL=30s BUILD_DIR=build/fleet-extended
```

Record the duration, reason and completed results. An interrupted run helps
diagnosis but does not count as a pass. For installed-target checks,
record commit, checksums, host/architecture, commands, results and reviewer:

| Target | Required checks |
| --- | --- |
| Debian 13 / Ubuntu 26.04, amd64/arm64 | Client/server install, fresh initialization, upgrade/removal, sandbox, journald, Weston/WebKit/proxy and hardware smoke tests |
| EL9 / EL10, amd64 | Server install, fresh initialization, upgrade/removal, native policy build, enforcing SELinux operation, denial review and package verification |

On installed clients, check that runtime writes stay in the documented volatile
`/run` directories and browser cookies/cache/state disappear after restart. Test
GPU rendering, physical DRM mirroring, configured peripherals and representative
stream load.

## Publish

Public builds and publication require CodeQL for Go, C, JavaScript, Python and
Actions on the exact commit. Require it in public branch protections. For private
personal repositories, the workflow skips this gate and attestations.

1. Merge the reviewed commit and wait for required checks. Stable tags must point
   directly to current `main`; SemVer prereleases to current `dev`.
2. Prepare release notes with security actions and limitations. Create and push
   an annotated, signed tag; GitHub must verify its signature:

   ```bash
   git tag --sign --file /path/to/release-notes.md v1.0.0 RELEASE_COMMIT
   git push origin v1.0.0
   ```

   Replace the example version and `RELEASE_COMMIT` with the reviewed values.
3. Approve the protected environment only after attaching source/target evidence.
4. Verify CI evidence: ten packages, each with `.sha256`, `.spdx.json` and
   `.vulnerabilities.json` sidecars, plus `SHA256SUMS`. Reports stay in GitHub
   Actions artifacts for 90 days under repository permissions. Published releases
   contain ten packages, ten `.sha256` sidecars and `SHA256SUMS` (21 assets).
   The manifest covers only packages and checksum sidecars; there are no SBOM
   attestations. Every filename must match the application version in the tag.

   ```bash
   python3 scripts/check-release-assets.py release-assets --version 1.0.0 --manifest
   ```

   The validator checks exact targets, regular files, complete nonduplicate
   checksums, and SPDX evidence with the expected component and archive SHA-256.
   The SBOM name and Grype source must be `sha256:<archive SHA-256>`. Grype reports
   must identify the target distribution, include all fix states and package
   paths, and have valid database metadata and scan/database timestamps within
   five days. High/critical findings block publication. Refresh scans if approval
   takes longer.
5. From a clean host, verify the downloaded set and public build provenance attestations:

   ```bash
   sha256sum --check SHA256SUMS
   gh attestation verify NeoDSE-server_1.0.0_ubuntu26.04_amd64.deb --repo RealisLux/NeoDSE
   ```

6. Install verified packages on clean hosts and repeat readiness, enrollment,
   display, proxy and removal smoke tests.

The workflow creates or resumes a draft, verifies and uploads assets, then checks
that it contains exactly the 21 expected, fully uploaded assets before publishing.
Lookup/API failures stop uploads, and existing published releases are rejected.
If a release fails, keep the draft and fix it through normal review. After
publication, use a new version; never replace assets or disable immutability to
rerun it.

## Retain evidence

The reusable quality gate runs both ten-minute fleet phases. Logs, packages and
native diagnostics stay in CI for 90 days, subject to repository limits. Before
they expire, export evidence to durable, access-controlled storage and keep it
throughout the release's support lifetime.
