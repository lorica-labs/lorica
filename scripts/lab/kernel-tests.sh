#!/usr/bin/env bash
# Build the eBPF object and the tests that need a kernel, then run the tests as root.
#
#   kernel-tests.sh [--crate NAME] [--test NAME] [--ebpf-features LIST]
#                   [--] [args passed to the test]
#
# Three things make this a script rather than a cargo invocation. The eBPF object is
# a different target built by a different toolchain, so cargo cannot produce it as a
# dependency. Loading an XDP program needs CAP_BPF and CAP_NET_ADMIN, so the test
# binary runs under sudo while the build stays unprivileged, which keeps target/ out
# of root ownership. And the object has to be built with the instrumentation the
# tests read, which is not the object a performance measurement should use.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

CRATE=carapace-dataplane
TEST=""
EBPF_FEATURES=${CARAPACE_EBPF_FEATURES:-parse-probe,count-helpers}
PASS_THROUGH=()

while [ $# -gt 0 ]; do
    case $1 in
        --crate)          CRATE=$2; shift 2 ;;
        --test)           TEST=$2; shift 2 ;;
        --ebpf-features)  EBPF_FEATURES=$2; shift 2 ;;
        --)               shift; PASS_THROUGH=("$@"); break ;;
        -h|--help)        sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

sudo -n true 2>/dev/null \
    || die "sudo requires a password; loading an XDP program needs CAP_BPF and CAP_NET_ADMIN"

# shellcheck source=scripts/lab/build-ebpf.sh
. scripts/lab/build-ebpf.sh
build_ebpf "$EBPF_FEATURES" || die "the eBPF build failed"
export CARAPACE_EBPF_PLAIN_OBJ=$EBPF_PLAIN_OBJ
export CARAPACE_EBPF_OBJ=$EBPF_OBJ

# The userspace feature has to match the object: a test that reads the helper counts
# would otherwise look for a map the program was not built with.
# Each feature names its crate, because the crate under test is not always the one
# that declares them: the agent has the tick assertion and the dataplane has the
# features that assertion needs.
features=carapace-dataplane/kernel-tests
case $EBPF_FEATURES in
    *count-helpers*) features=$features,carapace-dataplane/count-helpers ;;
esac

args=(test -p "$CRATE" --features "$features" --no-run
      --message-format=json-render-diagnostics)
[ -n "$TEST" ] && args+=(--test "$TEST")

# The executables are read out of the cargo metadata rather than guessed from a
# target path: the hash in the file name changes on every rebuild, and a stale binary
# would report a pass for code that is no longer there.
mapfile -t binaries < <(cargo "${args[@]}" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test"):
        if msg.get("executable"):
            print(msg["executable"])
')
[ "${#binaries[@]}" -gt 0 ] || die "cargo produced no test executable"

status=0
for binary in "${binaries[@]}"; do
    printf '\n--- %s\n' "$(basename "$binary")"
    sudo -n --preserve-env=CARAPACE_EBPF_OBJ,CARAPACE_EBPF_PLAIN_OBJ \
        "$binary" "${PASS_THROUGH[@]}" || status=1
done

exit $status
