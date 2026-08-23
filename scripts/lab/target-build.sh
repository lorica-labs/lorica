#!/usr/bin/env bash
# Build, on the build VM, everything the measurement VM needs to run a test binary,
# and pack it into one tar the caller streams across.
#
#   target-build.sh [--crate NAME] [--test NAME] [--features LIST]
#                   [--ebpf-features LIST] [--plain] [--no-ebpf]
#
# The measurement VM has no toolchain, and its glibc is two minor versions behind this
# one: a dynamically linked binary built here does not start there. A statically linked
# musl binary removes the question, and it removes it for every task that measures,
# not just the first one.
#
# The eBPF objects and the bench objects travel with the binaries because the target
# cannot build them either. bench/progs/*.o is gitignored, so it is made here rather
# than assumed present.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

TRIPLE=${LORICA_TARGET_TRIPLE:-x86_64-unknown-linux-musl}
CRATE=lorica-dataplane
FEATURES=kernel-tests
EBPF_FEATURES=${LORICA_EBPF_FEATURES:-parse-probe,count-helpers}
WANT_EBPF=1
TEST=""

while [ $# -gt 0 ]; do
    case $1 in
        --crate)          CRATE=$2; shift 2 ;;
        --test)           TEST=$2; shift 2 ;;
        --features)       FEATURES=$2; shift 2 ;;
        --ebpf-features)  EBPF_FEATURES=$2; shift 2 ;;
        --plain)          EBPF_FEATURES=""; shift ;;
        --no-ebpf)        WANT_EBPF=0; shift ;;
        -h|--help)        sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

STAGE=$PWD/target/target-tests
TARBALL=$PWD/target/target-tests.tar
rm -rf "$STAGE" "$TARBALL"
mkdir -p "$STAGE/bin" "$STAGE/ebpf" "$STAGE/progs" || die "cannot create $STAGE"
cp scripts/lab/target-run.sh "$STAGE/" || die "cannot stage the runner"

if [ "$WANT_EBPF" -eq 1 ]; then
    # shellcheck source=scripts/lab/build-ebpf.sh
    . scripts/lab/build-ebpf.sh
    build_ebpf "$EBPF_FEATURES" || die "the eBPF build failed"
    cp "$EBPF_PLAIN_OBJ" "$STAGE/ebpf/plain" || die "cannot stage the plain object"
    cp "$EBPF_OBJ" "$STAGE/ebpf/instrumented" || die "cannot stage the instrumented object"

    make -C bench/progs all >&2 || die "make -C bench/progs failed: no xdp_pass.o to attach"
    cp bench/progs/*.o "$STAGE/progs/" || die "cannot stage the bench objects"
fi

# The userspace feature has to match the object, or a test reading the helper counts
# looks for a map the program was not built with.
case $EBPF_FEATURES in
    *count-helpers*) [ "$WANT_EBPF" -eq 1 ] && FEATURES=$FEATURES,count-helpers ;;
esac
case $EBPF_FEATURES in
    *stage-cutoff*) [ "$WANT_EBPF" -eq 1 ] && FEATURES=$FEATURES,stage-cutoff ;;
esac

args=(test -p "$CRATE" --target "$TRIPLE" --no-run
      --message-format=json-render-diagnostics)
[ -n "$FEATURES" ] && args+=(--features "$FEATURES")
[ -n "$TEST" ] && args+=(--test "$TEST")

# The executables come out of the cargo metadata rather than a guessed target path: the
# hash in the file name changes on every rebuild, and shipping a stale binary would
# report a pass for code that is no longer there.
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
[ "${#binaries[@]}" -gt 0 ] || die "cargo produced no test executable for $TRIPLE"

for binary in "${binaries[@]}"; do
    cp "$binary" "$STAGE/bin/" || die "cannot stage $binary"
    # A binary that turns out to be dynamically linked would fail on the target with a
    # glibc version message that reads like a missing package. Refuse it here instead.
    if file "$binary" | grep -q 'dynamically linked'; then
        die "$(basename "$binary") is dynamically linked; it will not start on the target"
    fi
done

tar cf "$TARBALL" -C "$(dirname "$STAGE")" "$(basename "$STAGE")" \
    || die "cannot pack $TARBALL"
printf 'packed %d test binaries into %s\n' "${#binaries[@]}" "$TARBALL" >&2
