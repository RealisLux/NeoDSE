#!/usr/bin/env bash
# File purpose: Publishes complete draft releases while preserving published releases.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -euo pipefail

: "${GITHUB_REF_NAME:?release tag required}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
release_version="${GITHUB_REF_NAME#v}"
python3 "${SCRIPT_DIR}/check-release-assets.py" release-assets --version "${release_version}" --manifest
mapfile -t assets < <(find release-assets -maxdepth 1 -type f \( \
    -name '*.deb' -o -name '*.rpm' -o -name '*.sha256' -o \
    -name 'SHA256SUMS' \) -printf '%p\n' | sort)

prerelease_flag=()
release_core="${release_version%%+*}"
if [[ "${release_core}" == *-* ]]; then
    prerelease_flag=(--prerelease)
fi

# A lookup failure cannot authorize an upload. Creation must succeed, followed
# by an independent draft check. API/network errors therefore fail closed.
if ! gh release view "${GITHUB_REF_NAME}" --json isDraft >/dev/null; then
    gh release create "${GITHUB_REF_NAME}" --draft --verify-tag --notes-from-tag \
        --title "NeoDSE ${GITHUB_REF_NAME}" "${prerelease_flag[@]}"
fi
if [[ $(gh release view "${GITHUB_REF_NAME}" --json isDraft --jq '.isDraft') != true ]]; then
    echo 'Refusing to modify an already published release.' >&2
    exit 1
fi
# Immutable releases must also be enabled in repository settings, protecting
# against concurrent publication between the draft check and this upload.
gh release upload "${GITHUB_REF_NAME}" --clobber "${assets[@]}"
# A resumed draft can contain assets from an earlier attempt or manual upload.
# Verify the complete remote set before making any of it public.
gh release view "${GITHUB_REF_NAME}" --json assets | \
    python3 "${SCRIPT_DIR}/check-release-assets.py" --version "${release_version}" --published-assets
gh release edit "${GITHUB_REF_NAME}" --draft=false
