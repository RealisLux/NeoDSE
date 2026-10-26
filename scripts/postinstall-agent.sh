#!/usr/bin/env bash
# File purpose: Sets up the client after package installation.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

install -D -m 0644 -o root -g root \
    /usr/share/neodse/pam/weston-remote-access \
    /etc/pam.d/weston-remote-access

/usr/lib/neodse/neodse-vnc-tls

visudo -cf /etc/sudoers.d/neodse-agent
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/neodse.conf
fi
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    # Weston starts at boot; it pulls in the UI only when a display is ready.
    systemctl disable neodse-ui.service
    systemctl enable neodse-agent.service neodse-weston.service
    # ExecCondition skips Weston cleanly on a headless host.
    systemctl --no-block restart neodse-weston.service
    # Replace a running agent after its renderer and binary have been updated.
    # Fresh installations and deliberately stopped agents stay stopped.
    systemctl try-restart neodse-agent.service
fi
printf '%s\n' 'Run neodse-agent bootstrap, then neodse-agent provision before starting the service. Use neodse-agent remove-config to remove local enrollment.'
