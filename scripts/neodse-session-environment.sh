#!/usr/bin/env bash
# File purpose: Prepares the kiosk session environment before renderer startup.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

# Weston owns the PAM session and user manager. Publish its ready endpoint from
# the renderer's pre-start phase, which has no PAM/TTY setup of its own.
environment_file="${RUNTIME_DIRECTORY:?systemd runtime directory is required}/session.env"
session_runtime_dir="/run/user/$(id -u)"
session_bus_address="unix:path=${session_runtime_dir}/bus"
/usr/bin/env \
    XDG_RUNTIME_DIR="${session_runtime_dir}" \
    DBUS_SESSION_BUS_ADDRESS="${session_bus_address}" \
    /usr/bin/dbus-update-activation-environment --systemd \
    WAYLAND_DISPLAY=wayland-0 XDG_SESSION_TYPE=wayland

# systemd rereads this private EnvironmentFile before executing the renderer,
# which reuses Weston's PAM runtime directory without opening another session.
# Publish both variables together only after a successful activation update.
umask 0077
temporary=$(mktemp "${environment_file}.XXXXXX")
trap 'rm -f -- "${temporary}"' EXIT
printf 'XDG_RUNTIME_DIR=%s\nDBUS_SESSION_BUS_ADDRESS=%s\n' \
    "${session_runtime_dir}" "${session_bus_address}" >"${temporary}"
mv -fT -- "${temporary}" "${environment_file}"
