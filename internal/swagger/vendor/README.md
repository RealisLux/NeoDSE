# Vendored Swagger UI

Upstream: [swagger-ui-dist 5.35.0](https://www.npmjs.com/package/swagger-ui-dist/v/5.35.0).
Archive: https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-5.35.0.tgz

npm archive integrity: `sha512-U06rpMtW9V3XPGOBeamTUSr0Z09jMX4IJuANpE/EZbAhw0G8CgwrzU4YmXkn/h0wCDNsXdGarTNNHC3sU8yVUQ==`.

The JavaScript, CSS, upstream LICENSE and extracted bundle license notices are
unmodified distribution files. `MANIFEST.sha256` verifies their local contents.
`THIRD-PARTY-NOTICES` is a NeoDSE-maintained supplement containing the exact
upstream `NOTICE` attribution and the full BSD-3-Clause license for bundled
ieee754 1.2.1. Their archive sources and checksums are recorded in that file;
the [upstream lockfile](https://github.com/swagger-api/swagger-ui/blob/v5.35.0/package-lock.json)
and bundle source map establish the ieee754 version. The extracted license
comments alone omit these required notices.

The server embeds the upstream Apache license and both notice files, and serves
their combined contents at `/docs/swagger-ui-bundle.js.LICENSE.txt`. Server package
third-party notices include the same license and notice texts.

The bundle includes DOMPurify 3.4.17, which fixes the three DOMPurify advisories
previously recorded as exceptions for the 3.4.16 bundle. The published bundle and
upstream lockfile both identify version 3.4.17.

When updating, choose an explicit reviewed release, verify its archive integrity,
copy the four distribution files together, review the upstream `NOTICE` and
bundled dependency licenses, and refresh the supplemental notices. Review the
bundled dependencies for advisories and record any applicable exceptions in the
[advisory register](../../../docs/SECURITY_EXCEPTIONS.md). Update this provenance
record and the manifest, and run the Swagger tests, `make verify-contracts` and
browser acceptance checks.
Do not fetch `latest` during builds or releases.
