#!/usr/bin/env bash
# File purpose: Sets up the server after package installation.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

if [[ -f /usr/share/selinux/packages/neodse.pp ]] && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    semodule -i /usr/share/selinux/packages/neodse.pp
    restorecon -RF /usr/bin/neodse-server /usr/bin/neodse-transport /usr/bin/neodse-proxy /etc/neodse /var/lib/neodse
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    if [[ -f /etc/neodse/server.yaml ]]; then
        systemctl enable neodse-transport.service neodse-server.service neodse-proxy.service
        systemctl restart neodse-transport.service neodse-server.service neodse-proxy.service
        printf '%s\n' 'The controller restarted with its database locked. Run sudo neodse-server unlock to start it.'
    else
        printf '%s\n' 'Run neodse-server bootstrap before enabling NeoDSE services.'
    fi
fi
