#!/usr/bin/env bash
# File purpose: Preserves client configuration and restores PAM policy after package removal.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail
case "${1:-}" in upgrade|failed-upgrade|abort-upgrade|1) exit 0 ;; esac
# dpkg runs postrm again on purge after removal. Only remove our replacement
# while we still own the diversion; otherwise this would delete Weston's
# already-restored authentication policy.
diversion_owner=$(dpkg-divert --listpackage /etc/pam.d/weston-remote-access)
if [[ ${diversion_owner} == neodse-client ]]; then
    rm -f /etc/pam.d/weston-remote-access
    dpkg-divert --package neodse-client --remove --rename \
        --divert /etc/pam.d/weston-remote-access.distrib \
        /etc/pam.d/weston-remote-access
fi
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
fi
printf '%s\n' 'NeoDSE configuration was preserved.'
