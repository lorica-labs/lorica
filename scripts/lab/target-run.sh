#!/usr/bin/env bash
# Run the shipped test binaries on the measurement VM.
#
# It travels inside the tar that target-build.sh packs rather than being a command
# string in target-tests.sh, because a remote command is re-wrapped in quotes on the
# way and a loop with a printf in it does not survive that.

set -uo pipefail

cd "$(dirname "$0")" || exit 1
root=$PWD

[ -d bin ] || { echo "FAIL  no bin/ beside $0" >&2; exit 1; }

# Loading an XDP program needs CAP_BPF and CAP_NET_ADMIN, and on the lab VMs that means
# passwordless sudo. It does not mean sudo has to exist: a machine where this already runs as
# root has the capabilities and may have no sudo at all — a Proxmox host is one, and that is
# where this refused to run while holding every privilege it was asking for.
if [ "$(id -u)" -eq 0 ]; then
    elevate=()
else
    sudo -n true 2>/dev/null \
        || { echo "FAIL  sudo needs a password; loading an XDP program needs CAP_BPF and CAP_NET_ADMIN" >&2; exit 1; }
    elevate=(sudo -n)
fi

# Every knob the caller set travels. sudo would otherwise reset it and the test would read
# its default, report on something else, and still go green — which is the worst failure
# mode on offer. The three paths below are passed after these on purpose: they are computed
# from where the tar landed on this machine, so they have to win over any namesake that
# came along for the ride.
keep=()
for name in $(env | cut -d= -f1 | grep '^LORICA_'); do
    keep+=("$name=${!name}")
done

status=0
for binary in bin/*; do
    printf '\n--- %s on %s\n' "$(basename "$binary")" "$(uname -r)"
    "${elevate[@]}" env "${keep[@]}" "LORICA_EBPF_OBJ=$root/ebpf/instrumented" \
                "LORICA_EBPF_PLAIN_OBJ=$root/ebpf/plain" \
                "LORICA_BENCH_PROGS=$root/progs" \
        "$binary" "$@" || status=1
done
exit $status
