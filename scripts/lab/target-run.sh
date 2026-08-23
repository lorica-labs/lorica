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

sudo -n true 2>/dev/null \
    || { echo "FAIL  sudo needs a password; loading an XDP program needs CAP_BPF and CAP_NET_ADMIN" >&2; exit 1; }

status=0
for binary in bin/*; do
    printf '\n--- %s on %s\n' "$(basename "$binary")" "$(uname -r)"
    sudo -n env "LORICA_EBPF_OBJ=$root/ebpf/instrumented" \
                "LORICA_EBPF_PLAIN_OBJ=$root/ebpf/plain" \
                "LORICA_BENCH_PROGS=$root/progs" \
        "$binary" "$@" || status=1
done
exit $status
