#!/usr/bin/env bash
# Build the eBPF object and the tests that need a kernel, then run the tests as root.
#
#   kernel-tests.sh [--test NAME] [--ebpf-features LIST] [--] [args passed to the test]
#
# Three things make this a script rather than a cargo invocation. The eBPF object is
# a different target built by a different toolchain, so cargo cannot produce it as a
# dependency. Loading an XDP program needs CAP_BPF and CAP_NET_ADMIN, so the test
# binary runs under sudo while the build stays unprivileged, which keeps target/ out
# of root ownership. And the object has to be built with the instrumentation the
# tests read, which is not the object a performance measurement should use.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

TEST=""
EBPF_FEATURES=${CARAPACE_EBPF_FEATURES:-parse-probe,count-helpers}
PASS_THROUGH=()

while [ $# -gt 0 ]; do
    case $1 in
        --test)           TEST=$2; shift 2 ;;
        --ebpf-features)  EBPF_FEATURES=$2; shift 2 ;;
        --)               shift; PASS_THROUGH=("$@"); break ;;
        -h|--help)        sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

sudo -n true 2>/dev/null \
    || die "sudo requires a password; loading an XDP program needs CAP_BPF and CAP_NET_ADMIN"

# Two objects, and they must not share a target directory. The instrumented one adds
# a map write per counted call, so a static call budget read from it would be
# measuring the instrumentation; the plain one is what ships.
echo 'building the eBPF object that ships'
(cd crates/carapace-ebpf && cargo +nightly build --release) || die "the plain eBPF build failed"
PLAIN=$PWD/crates/carapace-ebpf/target/bpfel-unknown-none/release/carapace-ebpf
[ -f "$PLAIN" ] || die "no object at $PLAIN after a successful build"
export CARAPACE_EBPF_PLAIN_OBJ=$PLAIN

if [ -n "$EBPF_FEATURES" ]; then
    printf 'building the instrumented eBPF object with features: %s\n' "$EBPF_FEATURES"
    INSTRUMENTED=$PWD/crates/carapace-ebpf/target/instrumented
    (cd crates/carapace-ebpf \
        && CARGO_TARGET_DIR=$INSTRUMENTED cargo +nightly build --release \
            --features "$EBPF_FEATURES") \
        || die "the instrumented eBPF build failed"
    OBJ=$INSTRUMENTED/bpfel-unknown-none/release/carapace-ebpf
else
    OBJ=$PLAIN
fi
[ -f "$OBJ" ] || die "no object at $OBJ after a successful build"
export CARAPACE_EBPF_OBJ=$OBJ

# The userspace feature has to match the object: a test that reads the helper counts
# would otherwise look for a map the program was not built with.
features=kernel-tests
case $EBPF_FEATURES in *count-helpers*) features=$features,count-helpers ;; esac

args=(test -p carapace-dataplane --features "$features" --no-run
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
