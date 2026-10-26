#!/usr/bin/env bash
# File purpose: Tests unprivileged plaintext sockets and route changes in a private network namespace.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

set -Eeuo pipefail

if [[ ${1:-} != --isolated ]]; then
    if [[ $# != 1 || ! -f $1 || ! -x $1 ]]; then
        printf 'Usage: %s PATH_TO_CONFIG_TEST_BINARY\n' "$0" >&2
        exit 2
    fi
    if (( EUID != 0 )); then
        printf '%s\n' 'Root is required to create the private network namespace; the socket test runs without privileges.' >&2
        exit 1
    fi
    for command_name in unshare ip setpriv; do
        if ! command -v "${command_name}" >/dev/null; then
            printf 'Required command is missing: %s\n' "${command_name}" >&2
            exit 1
        fi
    done
    export NEODSE_WIREGUARD_NAMESPACE_PARENT
    NEODSE_WIREGUARD_NAMESPACE_PARENT=$(readlink /proc/self/ns/net)
    staged=$(mktemp -d /tmp/neodse-wireguard-sockets.XXXXXX)
    trap 'rm -rf -- "${staged}"' EXIT
    # The unprivileged test must be able to traverse this root-owned directory.
    chmod 0755 "${staged}"
    install -m 0755 "$0" "${staged}/runner.sh"
    install -m 0755 "$1" "${staged}/config.test"
    unshare --net -- bash "${staged}/runner.sh" --isolated "${staged}/config.test"
    exit
fi
shift
if [[ $# != 1 || -z ${NEODSE_WIREGUARD_NAMESPACE_PARENT:-} || ${NEODSE_WIREGUARD_NAMESPACE_PARENT} == "$(readlink /proc/self/ns/net)" ]]; then
    printf '%s\n' 'The internal entry point requires a private network namespace.' >&2
    exit 1
fi

test_binary=$1
staged=$(dirname -- "${test_binary}")
sync_directory="${staged}/sync"
mkdir -m 0755 "${sync_directory}"
chown 65534:65534 "${sync_directory}"
ip link set lo up
ip link add neodse type wireguard
ip address add 10.90.0.1/24 dev neodse
ip link set neodse up
ip link add neodse-leak type dummy
ip address add 10.90.0.2/32 dev neodse-leak
ip link set neodse-leak up

# Keep namespace administration in this runner. The application test receives
# neither root identity, supplementary groups, nor Linux capabilities.
unprivileged=(setpriv --reuid=65534 --regid=65534 --clear-groups
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs)
test_name=TestPlaintextSocketControlIntegration
listed_tests=$("${unprivileged[@]}" "${test_binary}" -test.list "^${test_name}$")
if [[ ${listed_tests} != "${test_name}" ]]; then
    printf 'The test binary does not contain %s.\n' "${test_name}" >&2
    exit 1
fi

export NEODSE_WIREGUARD_SOCKET_TEST=1
export NEODSE_WIREGUARD_SOCKET_SYNC="${sync_directory}"
test_pid=
cleanup_test() {
    if [[ -n ${test_pid} ]]; then
        kill -- "${test_pid}" 2>/dev/null || true
        wait "${test_pid}" 2>/dev/null || true
    fi
}
trap cleanup_test EXIT
"${unprivileged[@]}" "${test_binary}" -test.run "^${test_name}$" -test.v -test.timeout=30s &
test_pid=$!
mutation_completed=false
deadline=$((SECONDS + 35))
while kill -0 "${test_pid}" 2>/dev/null; do
    if [[ ${mutation_completed} == false && -f ${sync_directory}/remove-interface ]]; then
        # The test has an active socket pinned to WireGuard. Reassigning its
        # address exposes any fallback to an ordinary interface after deletion.
        ip link delete neodse
        ip address add 10.90.0.1/32 dev neodse-leak
        : >"${sync_directory}/interface-removed"
        mutation_completed=true
    fi
    if (( SECONDS >= deadline )); then
        printf '%s\n' 'The WireGuard socket test exceeded its runner deadline.' >&2
        exit 1
    fi
    sleep 0.05
done
if wait "${test_pid}"; then
    test_pid=
else
    test_status=$?
    test_pid=
    exit "${test_status}"
fi
if [[ ${mutation_completed} != true ]]; then
    printf '%s\n' 'The WireGuard socket test did not exercise interface removal.' >&2
    exit 1
fi
