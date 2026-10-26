#!/usr/bin/env bash
# File purpose: Enforces statement-coverage floors for security decisions.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -euo pipefail

coverage_dir=$(mktemp -d)
trap 'rm -rf -- "${coverage_dir}"' EXIT

require_total() {
    local package_name=$1
    local minimum=$2
    local profile="${coverage_dir}/${package_name}.cover"
    local report="${coverage_dir}/${package_name}.txt"
    local test_log="${coverage_dir}/${package_name}.test.log"
    if ! go test "./internal/${package_name}" -count=1 -coverprofile="${profile}" >"${test_log}" 2>&1; then
        printf 'security coverage: tests failed for internal/%s\n' "${package_name}" >&2
        cat "${test_log}" >&2
        return 1
    fi
    go tool cover -func="${profile}" >"${report}"
    local measured
    measured=$(awk '$1 == "total:" { value=$NF; sub(/%$/, "", value); print value; exit }' "${report}")
    if [[ -z ${measured} ]] || ! awk -v measured="${measured}" -v minimum="${minimum}" 'BEGIN { exit !(measured + 0 >= minimum + 0) }'; then
        printf 'security coverage: %s package total is %s%%; require at least %s%%\n' \
            "${package_name}" "${measured:-missing}" "${minimum}" >&2
        return 1
    fi
    printf 'security coverage: %-18s %-30s %6s%%\n' "${package_name}" "package total" "${measured}"
}

# Package totals are deliberately independent of function names so routine
# decomposition does not weaken or break the gate. Core decision packages have
# an 80% or higher floor; application packages include privileged CLI and
# hardware seams that are additionally covered by integration/package gates.
require_total instruction 85
require_total protocol 95
require_total store 80
require_total storekey 85
require_total config 80
require_total keyderivation 95
require_total proxyauth 90
require_total replay 95
require_total netlimit 90
require_total provisioning 65
require_total proxy 74
require_total transport 65
require_total agent 30
require_total server 50
