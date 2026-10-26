#!/usr/bin/env bash
# File purpose: Builds native packages using the GitHub Actions package manifests.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPOSITORY_ROOT
readonly NFPM_BINARY="${REPOSITORY_ROOT}/build/tools/nfpm"

PACKAGE_VERSION="0.0.0-local"
COMPONENT="auto"
PACKAGE_FORMAT="auto"
TARGET_LABEL=""
RUN_TESTS=true

usage() {
    cat <<'EOF'
Usage: build-local-packages.sh [options]

Options:
  --version VERSION       Package and binary version (default: 0.0.0-local)
  --component COMPONENT   auto, client, server, or all (default: auto)
  --format FORMAT         auto, deb, or rpm; must match the host (default: auto)
  --target TARGET         Assert the native release label (debian13, ubuntu26.04, el9, el10)
  --skip-tests            Skip go test ./... before building
  -h, --help              Show this help

Native build support:
  Debian 13 or Ubuntu 26.04 amd64/arm64: client and server DEB packages
  Enterprise Linux 9 or 10 amd64: server RPM with a locally compiled SELinux policy
EOF
}

fatal() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fatal "Missing required command: $1"
}

validate_rpm_build_host() {
    local selinux_devel="${SELINUX_DEVEL:-/usr/share/selinux/devel}"

    require_command rpm
    require_command checkmodule
    require_command semodule_package
    [[ -f "${selinux_devel}/Makefile" ]] || fatal \
        "Missing ${selinux_devel}/Makefile. Install selinux-policy-devel for this Enterprise Linux release."
}

parse_arguments() {
    while (( $# > 0 )); do
        case "$1" in
            --version)
                (( $# >= 2 )) || fatal "Missing value for --version."
                PACKAGE_VERSION="${2#v}"
                shift 2
                ;;
            --component)
                (( $# >= 2 )) || fatal "Missing value for --component."
                COMPONENT="$2"
                shift 2
                ;;
            --format)
                (( $# >= 2 )) || fatal "Missing value for --format."
                PACKAGE_FORMAT="$2"
                shift 2
                ;;
            --target)
                (( $# >= 2 )) || fatal "Missing value for --target."
                TARGET_LABEL="$2"
                shift 2
                ;;
            --skip-tests)
                RUN_TESTS=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fatal "Unknown argument: $1"
                ;;
        esac
    done
}

detect_architecture() {
    case "$(uname -m)" in
        x86_64) printf 'amd64\n' ;;
        aarch64|arm64) printf 'arm64\n' ;;
        *) fatal "Unsupported native architecture: $(uname -m)" ;;
    esac
}

read_os_release_value() {
    local key="$1"

    awk -F= -v key="$key" '
        $1 == key {
            value = substr($0, index($0, "=") + 1)
            gsub(/^"|"$/, "", value)
            print value
            exit
        }
    ' /etc/os-release
}

detect_format() {
    local distro_id
    local distro_like

    distro_id="$(read_os_release_value ID)"
    distro_like="$(read_os_release_value ID_LIKE)"

    case " ${distro_id} ${distro_like} " in
        *debian*|*ubuntu*) printf 'deb\n' ;;
        *rhel*|*centos*) printf 'rpm\n' ;;
        *) fatal "The host distribution is not supported for native package builds." ;;
    esac
}

validate_supported_release() {
    local format="$1"
    local distro_id
    local distro_like
    local distro_version
    local major_version

    distro_id="$(read_os_release_value ID)"
    distro_like="$(read_os_release_value ID_LIKE)"
    distro_version="$(read_os_release_value VERSION_ID)"
    major_version="${distro_version%%.*}"

    if [[ "$format" == "deb" ]]; then
        case "${distro_id}:${distro_version}" in
            debian:13|ubuntu:26.04) return ;;
            *) fatal "DEB packages must be built natively on Debian 13 or Ubuntu 26.04; detected ${distro_id} ${distro_version}." ;;
        esac
    fi

    [[ " ${distro_id} ${distro_like} " == *rhel* || " ${distro_id} ${distro_like} " == *centos* ]] || \
        fatal "RPM packages must be built on an Enterprise Linux base; detected ${distro_id} ${distro_version}."
    [[ "$major_version" == "9" || "$major_version" == "10" ]] || \
        fatal "Server RPM packages support only Enterprise Linux 9 or 10; detected ${distro_id} ${distro_version}."
}

distro_label() {
    local distro_id
    local distro_version

    distro_id="$(read_os_release_value ID)"
    distro_version="$(read_os_release_value VERSION_ID)"
    if [[ "$(detect_format)" == rpm ]]; then
        printf 'el%s\n' "${distro_version%%.*}"
    else
        printf '%s%s\n' "$distro_id" "$distro_version" | tr -cd 'A-Za-z0-9._-'
    fi
}

validate_selection() {
    require_command python3
    python3 "${SCRIPT_DIR}/check-release-assets.py" --version "$PACKAGE_VERSION" --list-packages >/dev/null || \
        fatal "Package version must be a semantic version such as 1.0.0 or 1.0.0-rc.1."
    [[ "$COMPONENT" =~ ^(auto|client|server|all)$ ]] || fatal "Invalid component: ${COMPONENT}"
    [[ "$PACKAGE_FORMAT" =~ ^(auto|deb|rpm)$ ]] || fatal "Invalid package format: ${PACKAGE_FORMAT}"
}

write_checksum() {
    local artifact="$1"
    local directory
    local filename

    directory="$(dirname "$artifact")"
    filename="$(basename "$artifact")"
    (
        cd "$directory"
        sha256sum "$filename" > "${filename}.sha256"
    )
}

build_client_deb() {
    local arch="$1"
    local label="$2"
    local artifact="dist/NeoDSE-client_${PACKAGE_VERSION}_${label}_${arch}.deb"

    [[ "$PACKAGE_FORMAT" == "deb" ]] || fatal "The client is supported only as a Debian/Ubuntu package."
    require_command dpkg-deb
    require_command pkg-config
    require_command "${CC:-cc}"

    make agent ui vnc-auth-helper BUILD_DIR=build VERSION="$PACKAGE_VERSION"
    python3 scripts/package-notices.py client build/neodse-client-notices.txt build/neodse-agent build/neodse-vnc-auth
    ARCH="$arch" VERSION="$PACKAGE_VERSION" \
        "$NFPM_BINARY" package \
        --config packaging/nfpm-client.yaml --packager deb --target "$artifact"
    dpkg-deb --info "$artifact" >/dev/null
    dpkg-deb --contents "$artifact" >/dev/null
    write_checksum "$artifact"
    printf 'Built %s\n' "$artifact"
}

build_server_deb() {
    local arch="$1"
    local label="$2"
    local artifact="dist/NeoDSE-server_${PACKAGE_VERSION}_${label}_${arch}.deb"

    [[ "$PACKAGE_FORMAT" == "deb" ]] || fatal "Server DEB requested with a non-DEB format."
    require_command dpkg-deb

    make server transport proxy BUILD_DIR=build VERSION="$PACKAGE_VERSION"
    python3 scripts/package-notices.py server build/neodse-server-notices.txt build/neodse-server build/neodse-transport build/neodse-proxy
    ARCH="$arch" VERSION="$PACKAGE_VERSION" \
        "$NFPM_BINARY" package \
        --config packaging/nfpm-server-deb.yaml --packager deb --target "$artifact"
    dpkg-deb --info "$artifact" >/dev/null
    dpkg-deb --contents "$artifact" >/dev/null
    write_checksum "$artifact"
    printf 'Built %s\n' "$artifact"
}

build_server_rpm() {
    local label="$1"
    local artifact="dist/NeoDSE-server_${PACKAGE_VERSION}_${label}_amd64.rpm"

    [[ "$PACKAGE_FORMAT" == "rpm" ]] || fatal "Server RPM requested with a non-RPM format."

    make server transport proxy selinux-policy BUILD_DIR=build VERSION="$PACKAGE_VERSION"
    python3 scripts/package-notices.py server build/neodse-server-notices.txt build/neodse-server build/neodse-transport build/neodse-proxy
    ARCH=amd64 VERSION="$PACKAGE_VERSION" \
        "$NFPM_BINARY" package \
        --config packaging/nfpm-server-rpm.yaml --packager rpm --target "$artifact"
    rpm -qpl "$artifact" >/dev/null
    write_checksum "$artifact"
    printf 'Built %s\n' "$artifact"
}

main() {
    cd "$REPOSITORY_ROOT"
    parse_arguments "$@"
    validate_selection

    [[ "$(uname -s)" == "Linux" ]] || fatal "Local packages must be built natively on Linux."
    [[ -r /etc/os-release ]] || fatal "/etc/os-release is unavailable."

    require_command awk
    require_command go
    require_command python3
    require_command make
    require_command sha256sum

    local arch
    local label
    local native_format

    arch="$(detect_architecture)"
    # Effective values include both environment overrides and `go env -w`.
    # Cross-compiled helpers cannot run here, and package labels must describe
    # the binaries that will actually be installed on this native target.
    [[ "$(go env GOOS)" == linux && "$(go env GOARCH)" == "$arch" ]] || \
        fatal "Go must target linux/${arch} for this native build. Check go env GOOS GOARCH and remove cross-compilation overrides."

    label="$(distro_label)"
    native_format="$(detect_format)"
    validate_supported_release "$native_format"
    [[ -n "$label" ]] || fatal "Unable to determine a distribution label."
    [[ -z "$TARGET_LABEL" || "$TARGET_LABEL" == "$label" ]] || fatal "Requested target does not match native host: ${label}."

    if [[ "$PACKAGE_FORMAT" == "auto" ]]; then
        PACKAGE_FORMAT="$native_format"
    elif [[ "$PACKAGE_FORMAT" != "$native_format" ]]; then
        fatal "Requested ${PACKAGE_FORMAT} packaging does not match this ${native_format} host. Build RPMs inside the target Enterprise Linux release and DEBs on Debian/Ubuntu."
    fi

    if [[ "$COMPONENT" == "auto" ]]; then
        if [[ "$PACKAGE_FORMAT" == "deb" ]]; then
            COMPONENT="all"
        elif [[ "$PACKAGE_FORMAT" == "rpm" && "$arch" == "amd64" ]]; then
            COMPONENT="server"
        else
            fatal "No supported package set exists for ${PACKAGE_FORMAT}/${arch}."
        fi
    fi

    if [[ "$COMPONENT" =~ ^(server|all)$ && "$PACKAGE_FORMAT" == "rpm" && "$arch" != "amd64" ]]; then
        fatal "Server RPM packages are supported only on amd64."
    fi
    if [[ "$COMPONENT" =~ ^(client|all)$ && "$PACKAGE_FORMAT" != "deb" ]]; then
        fatal "Client packages are supported only on Debian/Ubuntu."
    fi
    if [[ "$COMPONENT" =~ ^(server|all)$ && "$PACKAGE_FORMAT" == "rpm" ]]; then
        validate_rpm_build_host
    fi

    mkdir -p "$(dirname "$NFPM_BINARY")"
    go -C tools/packaging build -o "$NFPM_BINARY" github.com/goreleaser/nfpm/v2/cmd/nfpm

    mkdir -p dist
    if [[ "$RUN_TESTS" == true ]]; then
        go test ./...
    fi

    if [[ "$COMPONENT" =~ ^(client|all)$ ]]; then
        build_client_deb "$arch" "$label"
    fi
    if [[ "$COMPONENT" =~ ^(server|all)$ ]]; then
        if [[ "$PACKAGE_FORMAT" == "deb" ]]; then
            build_server_deb "$arch" "$label"
        else
            build_server_rpm "$label"
        fi
    fi
}

main "$@"
