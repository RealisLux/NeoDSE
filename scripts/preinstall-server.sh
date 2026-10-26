#!/usr/bin/env bash
# File purpose: Prepares server accounts before package installation.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

SYSTEM_UID_MAX="$(awk '$1 == "SYS_UID_MAX" { value=$2 } END { print value == "" ? 999 : value }' /etc/login.defs)"
SYSTEM_GID_MAX="$(awk '$1 == "SYS_GID_MAX" { value=$2 } END { print value == "" ? 999 : value }' /etc/login.defs)"
readonly SYSTEM_UID_MAX SYSTEM_GID_MAX

fail() {
    printf 'NeoDSE package account validation failed: %s\n' "$*" >&2
    exit 1
}

validate_service_group() {
    local name=$1 record group_name gid
    record="$(getent group "$name")" || fail "required group ${name} is unavailable"
    IFS=: read -r group_name _ gid _ <<< "$record"
    [[ "$group_name" == "$name" && "$gid" =~ ^[0-9]+$ && "$gid" -gt 0 && "$gid" -le "$SYSTEM_GID_MAX" ]] ||
        fail "group ${name} must be a non-root system group"
}

validate_service_user() {
    local name=$1 expected_home=$2 record user_name uid gid home shell expected_gid group
    local -a current_groups
    record="$(getent passwd "$name")" || fail "required account ${name} is unavailable"
    IFS=: read -r user_name _ uid gid _ home shell <<< "$record"
    expected_gid="$(getent group "$name" | cut -d: -f3)"
    [[ "$user_name" == "$name" && "$uid" =~ ^[0-9]+$ && "$uid" -gt 0 && "$uid" -le "$SYSTEM_UID_MAX" ]] ||
        fail "account ${name} must be a non-root system account"
    [[ "$gid" == "$expected_gid" ]] || fail "account ${name} has an unexpected primary group"
    [[ "$home" == "$expected_home" ]] || fail "account ${name} has an unexpected home directory"
    [[ "$shell" == /usr/sbin/nologin ]] || fail "account ${name} has an unexpected login shell"
    read -r -a current_groups <<< "$(id -nG "$name")"
    for group in "${current_groups[@]}"; do
        [[ "$group" == "$name" ]] || fail "account ${name} belongs to unexpected group ${group}"
    done
}

for account in neodse-server neodse-proxy neodse-transport; do
    home=/nonexistent
    if [[ "$account" == neodse-server ]]; then
        # The package creates the state directory; useradd would copy login
        # files from /etc/skel into it.
        home=/var/lib/neodse
    fi
    getent group "$account" >/dev/null 2>&1 || groupadd --system "$account"
    validate_service_group "$account"
    if ! getent passwd "$account" >/dev/null 2>&1; then
        useradd --system --gid "$account" --home-dir "$home" \
            --no-create-home --shell /usr/sbin/nologin "$account"
    fi
    validate_service_user "$account" "$home"
done
