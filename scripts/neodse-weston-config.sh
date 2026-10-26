#!/usr/bin/env bash
# File purpose: Generates the volatile Weston output configuration.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

drm_root=${NEODSE_DRM_SYSFS_ROOT:-/sys/class/drm}
config_path=${NEODSE_WESTON_CONFIG_PATH:-/run/neodse/weston.ini}
scale=${NEODSE_WESTON_SCALE-1}
transform=${NEODSE_WESTON_TRANSFORM-normal}
if [[ ! ${scale} =~ ^[1-9][0-9]{0,9}$ ]] || (( scale > 2147483647 )); then
    printf '%s\n' 'NEODSE_WESTON_SCALE must be a positive 32-bit integer.' >&2
    exit 1
fi
case ${transform} in
    normal|rotate-90|rotate-180|rotate-270) ;;
    *) printf '%s\n' 'NEODSE_WESTON_TRANSFORM must be normal, rotate-90, rotate-180 or rotate-270.' >&2; exit 1 ;;
esac
output=
for status in "${drm_root}"/card*-*/status; do
    [[ -r ${status} ]] || continue
    [[ $(<"${status}") == connected ]] || continue
    output=${status%/status}
    output=${output##*/}
    output=${output#card*-}
    break
done
if [[ -z ${output} || ! ${output} =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    printf '%s\n' 'No connected DRM output was found for the VNC mirror.' >&2
    exit 1
fi

umask 0077
temporary=${config_path}.tmp
{
    printf '%s\n' '[vnc]'
    printf 'refresh-rate=%s\n' '10'
    printf '%s\n' '[output]'
    printf 'name=%s\n' "${output}"
    printf 'force-on=%s\n' 'true'
    printf 'scale=%s\n' "${scale}"
    printf 'transform=%s\n' "${transform}"
    printf '%s\n' '[output]'
    printf 'name=%s\n' 'vnc'
    printf 'mirror-of=%s\n' "${output}"
    printf 'resizeable=%s\n' 'false'
} >"${temporary}"
mv -f -- "${temporary}" "${config_path}"
