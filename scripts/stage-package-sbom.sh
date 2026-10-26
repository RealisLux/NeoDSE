#!/usr/bin/env bash
# File purpose: Exposes built package payloads to binary SBOM catalogers.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

if (( $# < 2 )); then
    echo 'Usage: stage-package-sbom.sh NEW_DIRECTORY PACKAGE...' >&2
    exit 1
fi
destination="$1"
shift
# Only use locally built or checksum-verified release packages. No maintainer
# scripts run here. Refuse reuse so old binaries cannot contaminate the SBOM.
mkdir -- "$destination"
for package in "$@"; do
    package="$(realpath -- "$package")"
    name="$(basename -- "$package")"
    root="${destination}/${name}/payload"
    mkdir -p -- "$root"
    # Keep the archive alongside its payload for OS package metadata and hashes.
    cp -- "$package" "${destination}/${name}/"
    case "$package" in
        *.deb) dpkg-deb --extract "$package" "$root" ;;
        *.rpm)
            # Read the RPM payload directly: rpm2cpio versions that compare the
            # archive size with nFPM's installed-file-size metadata can fail.
            # Keep libarchive's default absolute-path/traversal protections.
            bsdtar --extract --file "$package" --directory "$root" --no-same-owner
            # Some libarchive versions accept a truncated RPM header as an
            # empty archive. NeoDSE packages must contain regular payload files.
            if [[ -z "$(find "$root" -type f -print -quit)" ]]; then
                echo "RPM payload is empty: ${name}" >&2
                exit 1
            fi
            ;;
        *) echo "Unsupported package: ${name}" >&2; exit 1 ;;
    esac
done
