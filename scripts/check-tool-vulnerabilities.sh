#!/usr/bin/env bash
# File purpose: Scans every pinned trusted build command for known Go vulnerabilities.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

readonly GOVULNCHECK="${1:-}"

if [[ -z "${GOVULNCHECK}" || ! -x "${GOVULNCHECK}" ]]; then
    printf 'Usage: %s /path/to/govulncheck\n' "${0##*/}" >&2
    exit 2
fi

printf '%s\n' 'Scanning analysis commands'
"${GOVULNCHECK}" -C tools/analysis \
    github.com/rhysd/actionlint/cmd/actionlint \
    golang.org/x/vuln/cmd/govulncheck \
    honnef.co/go/tools/cmd/staticcheck

printf '%s\n' 'Scanning security command'
"${GOVULNCHECK}" -C tools/security \
    github.com/securego/gosec/v2/cmd/gosec

printf '%s\n' 'Scanning packaging command'
"${GOVULNCHECK}" -C tools/packaging \
    github.com/goreleaser/nfpm/v2/cmd/nfpm

printf '%s\n' 'Scanning SBOM and vulnerability commands'
# Reject every imported affected package in the large scanner graphs. Binary
# symbol checks in Makefile additionally inspect the exact built commands.
"${GOVULNCHECK}" -scan=package -format=json -C tools/sbom github.com/anchore/syft/cmd/syft |
    python3 scripts/check-scanner-vulnerabilities.py --scanner syft
"${GOVULNCHECK}" -scan=package -format=json -C tools/sbom github.com/anchore/grype/cmd/grype |
    python3 scripts/check-scanner-vulnerabilities.py --scanner grype
