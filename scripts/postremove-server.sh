#!/usr/bin/env bash
# File purpose: Unloads the SELinux policy and preserves server credentials and state after package removal.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail
case "${1:-}" in upgrade|failed-upgrade|abort-upgrade|1) exit 0 ;; esac
# RPM passes 0 on final erase. Unload the policy module that postinstall
# installed, then give the preserved files their default labels.
if [[ ${1:-} == 0 ]] && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled &&
    semodule -l | awk '$1 == "neodse" { found = 1 } END { exit !found }'; then
    semodule -r neodse
    restorecon -iRF /etc/neodse /var/lib/neodse
fi
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
fi
printf '%s\n' 'NeoDSE configuration and state were preserved.'
