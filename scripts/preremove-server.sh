#!/usr/bin/env bash
# File purpose: Stops server services before package removal.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail
case "${1:-}" in upgrade|failed-upgrade|1) exit 0 ;; esac
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl disable --now neodse-proxy.service neodse-server.service neodse-transport.service
fi
