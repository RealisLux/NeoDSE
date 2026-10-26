#!/usr/bin/env bash
# File purpose: Provisions and renews the root-controlled local VNC TLS identity.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

[[ ${EUID} == 0 ]] || { printf '%s\n' 'VNC TLS provisioning requires root.' >&2; exit 1; }
identity=/var/lib/neodse-vnc
key=${identity}/server.key
certificate=${identity}/server.crt

fail() { printf 'VNC TLS identity: %s\n' "$*" >&2; exit 1; }
trusted_file() {
    local path=$1 maximum_mode=$2 mode
    [[ -f ${path} && ! -L ${path} && $(stat -c %u -- "${path}") == 0 ]] || fail "untrusted file ${path}"
    mode=$(stat -c %a -- "${path}")
    (( (8#${mode} & ~maximum_mode) == 0 )) || fail "unsafe permissions on ${path}"
}

if [[ ! -e ${identity} && ! -L ${identity} ]]; then
    install -d -m 0755 -o root -g root "${identity}"
fi
[[ -d ${identity} && ! -L ${identity} && $(stat -c %u -- "${identity}") == 0 ]] || fail 'untrusted identity directory'
mode=$(stat -c %a -- "${identity}")
(( (8#${mode} & 8#022) == 0 )) || fail 'identity directory is group/world writable'

umask 0077
# Serialize package/manual invocations without replacing the lock inode.
exec 9>"${identity}/.lock"
flock --exclusive 9
staging=$(mktemp -d "${identity}/.new.XXXXXX")
trap 'rm -rf -- "${staging}"' EXIT

if [[ -e ${key} || -L ${key} ]]; then
    trusted_file "${key}" $((8#600))
    openssl pkey -in "${key}" -check -noout >/dev/null
else
    [[ ! -e ${certificate} && ! -L ${certificate} ]] || fail 'certificate exists without its private key; operator recovery is required'
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${staging}/server.key"
    chmod 0600 "${staging}/server.key"
    mv -- "${staging}/server.key" "${key}"
    sync -f "${key}"
fi

if [[ -e ${certificate} || -L ${certificate} ]]; then
    trusted_file "${certificate}" $((8#644))
    openssl x509 -in "${certificate}" -noout -pubkey >"${staging}/certificate.pub"
    openssl pkey -in "${key}" -pubout >"${staging}/key.pub"
    cmp --silent "${staging}/certificate.pub" "${staging}/key.pub" || fail 'certificate does not match its private key'
    openssl verify -no_check_time -trusted "${certificate}" -partial_chain -purpose sslserver -verify_ip 127.0.0.1 "${certificate}" >/dev/null
    # Reuse identity on upgrades; renew on package installation within 30 days of expiry.
    if openssl x509 -in "${certificate}" -noout -checkend 2592000 >/dev/null; then
        exit 0
    fi
fi

openssl req -new -x509 -key "${key}" -sha256 -days 3650 \
    -subj '/CN=NeoDSE local VNC' -addext 'subjectAltName=IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' -out "${staging}/server.crt"
chmod 0644 "${staging}/server.crt"
mv -f -- "${staging}/server.crt" "${certificate}"
sync -f "${certificate}"
