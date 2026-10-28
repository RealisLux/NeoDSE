#!/usr/bin/env bash
# File purpose: Scans every pinned trusted build command for known Go vulnerabilities.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

readonly GOVULNCHECK="${1:-}"
readonly REPORT_DIR="${2:-build/tool-audit}"

if [[ -z "${GOVULNCHECK}" || ! -x "${GOVULNCHECK}" ]]; then
    printf 'Usage: %s /path/to/govulncheck [report-directory]\n' "${0##*/}" >&2
    exit 2
fi

TOOL_DIR="$(dirname -- "${GOVULNCHECK}")"
readonly TOOL_DIR
mkdir -p -- "${REPORT_DIR}"
status=0

# Finish independent scans even after a finding; retain each result and return
# failure overall. This workflow must never turn a failed audit into success.
scan() {
    local name="$1"
    shift
    printf 'Scanning %s\n' "${name}"
    if "$@" > "${REPORT_DIR}/${name}.log" 2>&1; then
        printf '%s: PASS\n' "${name}"
    else
        printf '%s: FAIL\n' "${name}" >&2
        status=1
    fi
    cat -- "${REPORT_DIR}/${name}.log"
}

# Called through scan's command argument.
# shellcheck disable=SC2317
scanner_scan() {
    local scanner="$1" mode="$2"
    shift 2
    "${GOVULNCHECK}" "$@" | tee "${REPORT_DIR}/${scanner}-${mode}.json" |
        python3 scripts/check-scanner-vulnerabilities.py --scanner "${scanner}" --mode "${mode}"
}

scan analysis-source "${GOVULNCHECK}" -C tools/analysis \
    github.com/rhysd/actionlint/cmd/actionlint \
    golang.org/x/vuln/cmd/govulncheck \
    honnef.co/go/tools/cmd/staticcheck

scan security-source "${GOVULNCHECK}" -C tools/security \
    github.com/securego/gosec/v2/cmd/gosec

scan packaging-source "${GOVULNCHECK}" -C tools/packaging \
    github.com/goreleaser/nfpm/v2/cmd/nfpm

# Reject every imported affected package in the large scanner graphs. Binary
# checks additionally inspect the exact built commands.
for scanner in syft grype; do
    scan "${scanner}-source" scanner_scan "${scanner}" source \
        -scan=package -format=json -C tools/sbom "github.com/anchore/${scanner}/cmd/${scanner}"
    scan "${scanner}-binary" scanner_scan "${scanner}" binary \
        -mode=binary -format=json "${TOOL_DIR}/${scanner}"
done

for binary in actionlint staticcheck govulncheck gosec nfpm; do
    scan "${binary}-binary" "${GOVULNCHECK}" -mode=binary "${TOOL_DIR}/${binary}"
done

exit "${status}"
