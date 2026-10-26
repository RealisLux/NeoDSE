#!/usr/bin/env bash
# File purpose: Tests stock Weston and the production PAM helper in private mount/network namespaces.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

if [[ ${1:-} != --isolated ]]; then
    if [[ $# != 2 || ! -f $1 || ! -x $1 || ! -f $2 || ! -x $2 ]]; then
        printf 'Usage: %s PATH_TO_AGENT_TEST_BINARY PATH_TO_VNC_AUTH_HELPER\n' "$0" >&2
        exit 2
    fi
    export NEODSE_TEST_NAMESPACE_PARENT
    NEODSE_TEST_NAMESPACE_PARENT=$(readlink /proc/self/ns/mnt)
    project_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
    staged=$(mktemp -d /tmp/neodse-weston-vnc-runner.XXXXXX)
    trap 'rm -rf -- "${staged}"' EXIT
    install -m 0755 "$0" "${staged}/runner.sh"
    install -m 0755 "$1" "${staged}/weston-vnc.test"
    install -m 0755 "$2" "${staged}/neodse-vnc-auth"
    install -m 0755 "${project_root}/scripts/neodse-vnc-tls.sh" "${staged}/neodse-vnc-tls"
    install -m 0644 "${project_root}/pam/weston-remote-access" "${staged}/weston-remote-access"
    unshare --user --map-root-user --mount --net -- bash "${staged}/runner.sh" --isolated \
        "${staged}/weston-vnc.test" "${staged}/neodse-vnc-auth" "${staged}/weston-remote-access" "${staged}/neodse-vnc-tls"
    exit
fi
shift
if [[ -z ${NEODSE_TEST_NAMESPACE_PARENT:-} || ${NEODSE_TEST_NAMESPACE_PARENT} == "$(readlink /proc/self/ns/mnt)" ]]; then
    printf '%s\n' 'The internal entry point requires a private mount namespace.' >&2
    exit 1
fi
agent_test=$(realpath "$1")
auth_helper=$(realpath "$2")
pam_service=$(realpath "$3")
tls_setup=$(realpath "$4")
test_name=TestStockWestonVNC
listed_tests=$("${agent_test}" -test.list "^${test_name}$")
if [[ ${listed_tests} != "${test_name}" ]]; then
    printf 'The test binary does not contain %s.\n' "${test_name}" >&2
    exit 1
fi
fixture=$(mktemp -d /tmp/neodse-weston-vnc.XXXXXX)
trap 'rm -rf -- "${fixture}"' EXIT

# Changes below affect only this mount namespace; host accounts and PAM stay intact.
mount --make-rprivate /
ip link set lo up
cp /etc/passwd "${fixture}/passwd"
cp /etc/group "${fixture}/group"
printf '%s\n' 'neodse-ui:x:0:0:VNC test:/nonexistent:/usr/sbin/nologin' 'neodse-agent:x:0:0:Agent test:/nonexistent:/usr/sbin/nologin' >>"${fixture}/passwd"
printf '%s\n' 'neodse-ipc:x:0:' >>"${fixture}/group"
mount --bind "${fixture}/passwd" /etc/passwd
mount --bind "${fixture}/group" /etc/group
mkdir "${fixture}/pam"
cp -R /etc/pam.d/. "${fixture}/pam/"
sed "s|/usr/lib/neodse/neodse-vnc-auth|${auth_helper}|g" "${pam_service}" >"${fixture}/pam/weston-remote-access"
mount --bind "${fixture}/pam" /etc/pam.d
mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=755 tmpfs /var/lib
bash "${tls_setup}"

# A fixed local key avoids pair mismatches during renewal and upgrades.
identity=/var/lib/neodse-vnc
key_hash=$(sha256sum "${identity}/server.key")
certificate_hash=$(sha256sum "${identity}/server.crt")
bash "${tls_setup}"
[[ ${key_hash} == "$(sha256sum "${identity}/server.key")" ]]
[[ ${certificate_hash} == "$(sha256sum "${identity}/server.crt")" ]]
for days in 1 0; do
    openssl x509 -in "${identity}/server.crt" -signkey "${identity}/server.key" \
        -days "${days}" -out "${fixture}/expiring.crt"
    install -m 0644 "${fixture}/expiring.crt" "${identity}/server.crt"
    bash "${tls_setup}"
    openssl x509 -in "${identity}/server.crt" -noout -checkend 2592000 >/dev/null
    [[ ${key_hash} == "$(sha256sum "${identity}/server.key")" ]]
done
expect_setup_failure() {
    if bash "${tls_setup}" >"${fixture}/tls-denial.log" 2>&1; then
        printf '%s\n' 'VNC TLS setup accepted an unsafe identity.' >&2
        exit 1
    fi
}
chmod 0644 "${identity}/server.key"
expect_setup_failure
chmod 0600 "${identity}/server.key"
chmod 0666 "${identity}/server.crt"
expect_setup_failure
chmod 0644 "${identity}/server.crt"
chmod 0777 "${identity}"
expect_setup_failure
chmod 0755 "${identity}"
mv "${identity}/server.crt" "${fixture}/saved.crt"
ln -s "${fixture}/saved.crt" "${identity}/server.crt"
expect_setup_failure
rm "${identity}/server.crt"
mv "${fixture}/saved.crt" "${identity}/server.crt"
mv "${identity}/server.key" "${fixture}/saved.key"
expect_setup_failure
mv "${fixture}/saved.key" "${identity}/server.key"
# Repair an interrupted first installation using its already-created private key.
rm "${identity}/server.crt"
bash "${tls_setup}"
[[ ${key_hash} == "$(sha256sum "${identity}/server.key")" ]]
printf '%s\n' 'VNC TLS identity lifecycle and denial tests passed.'
mkdir -m 700 /run/neodse /run/neodse-vnc-auth
mkdir -p /run/user
mkdir -m 700 /run/user/0
export XDG_RUNTIME_DIR=/run/user/0
export NEODSE_WESTON_TEST=1
"${agent_test}" -test.run "^${test_name}$" -test.v -test.timeout=45s
