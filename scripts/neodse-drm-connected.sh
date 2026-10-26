#!/usr/bin/env bash
# File purpose: Reports whether a physical DRM connector is connected.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

drm_root=${NEODSE_DRM_SYSFS_ROOT:-/sys/class/drm}
for status in "${drm_root}"/card*-*/status; do
    [[ -r ${status} ]] || continue
    [[ $(<"${status}") == connected ]] && exit 0
done
exit 1
