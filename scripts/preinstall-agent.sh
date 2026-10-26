#!/usr/bin/env bash
# File purpose: Prepares client accounts and PAM policy before package installation.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

# Weston owns the default PAM service. Divert it instead of creating a second
# package owner for the same path; the original is restored on removal.
dpkg-divert --package neodse-client --add --rename \
    --divert /etc/pam.d/weston-remote-access.distrib \
    /etc/pam.d/weston-remote-access

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
    local name=$1 primary_group=$2 expected_home=$3
    shift 3
    local record user_name uid gid home shell expected_gid group allowed expected_group
    local -a current_groups
    record="$(getent passwd "$name")" || fail "required account ${name} is unavailable"
    IFS=: read -r user_name _ uid gid _ home shell <<< "$record"
    expected_gid="$(getent group "$primary_group" | cut -d: -f3)"
    [[ "$user_name" == "$name" && "$uid" =~ ^[0-9]+$ && "$uid" -gt 0 && "$uid" -le "$SYSTEM_UID_MAX" ]] ||
        fail "account ${name} must be a non-root system account"
    [[ "$gid" == "$expected_gid" ]] || fail "account ${name} has an unexpected primary group"
    [[ "$home" == "$expected_home" ]] || fail "account ${name} has an unexpected home directory"
    [[ "$shell" == /usr/sbin/nologin ]] || fail "account ${name} has an unexpected login shell"
    read -r -a current_groups <<< "$(id -nG "$name")"
    for group in "${current_groups[@]}"; do
        allowed=false
        for expected_group in "$primary_group" "$@"; do
            if [[ "$group" == "$expected_group" ]]; then
                allowed=true
                break
            fi
        done
        [[ "$allowed" == true ]] || fail "account ${name} belongs to unexpected group ${group}"
    done
}

getent group neodse-ipc >/dev/null 2>&1 || groupadd --system neodse-ipc
getent group neodse-agent >/dev/null 2>&1 || groupadd --system neodse-agent
validate_service_group neodse-ipc
validate_service_group neodse-agent
if ! getent passwd neodse-agent >/dev/null 2>&1; then
    useradd --system --gid neodse-agent --home-dir /nonexistent \
        --no-create-home --shell /usr/sbin/nologin neodse-agent
fi
if ! getent passwd neodse-ui >/dev/null 2>&1; then
    useradd --system --gid neodse-ipc --home-dir /nonexistent \
        --no-create-home --shell /usr/sbin/nologin neodse-ui
fi
validate_service_user neodse-agent neodse-agent /nonexistent neodse-ipc video audio dialout
validate_service_user neodse-ui neodse-ipc /nonexistent video render
usermod -aG neodse-ipc neodse-agent
for group in video audio dialout; do
    if getent group "$group" >/dev/null 2>&1; then
        usermod -aG "$group" neodse-agent
    fi
done
for group in video render; do
    if getent group "$group" >/dev/null 2>&1; then
        usermod -aG "$group" neodse-ui
    fi
done
