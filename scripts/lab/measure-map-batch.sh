#!/usr/bin/env bash
# Throughput of the batch map commands per batch size, and the kernel memory a filled
# LPM_TRIE actually costs.
#
#   measure-map-batch.sh [--entries N] [--sizes A,B,C] [--out DIR] [--settle-ms MS]
#
# Runs on the development host, unlike the other measure-*.sh. The measurement VM is the
# only machine that may be measured and the only one with no toolchain, and its glibc is
# two minor versions behind the build VM's, so the binary is built static musl on the
# build VM and travels. That is target-build.sh and target-run.sh, the same two scripts
# target-tests.sh drives.
#
# It drives them directly rather than through target-tests.sh for one reason: cargo test
# builds unoptimised, and the naive one-syscall-per-element path this measurement has to
# price is a userspace loop through aya that an unoptimised build slows down far more
# than it slows the batched path. Measuring a ratio at opt-level 0 would flatter batching
# for a reason that has nothing to do with the kernel. A --profile passthrough on
# target-tests.sh would let this script call it again; the two env vars below are that
# passthrough until it exists.
#
# Two numbers come out for the memory, not one. `memlock` is what the kernel attributes
# to the map, and it undercounts: it charges every trie node at its nominal size and
# never reports the intermediate nodes. The SUnreclaim delta is what a two-gigabyte VPS
# actually feels. Neither answers the other's question, so both are published with the
# ratio between them and with the idle noise floor beside them.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/map-batch
ENTRIES=1000000
SIZES=1,100,1000,10000,100000
SETTLE_MS=2000
IFACE=${LORICA_IFACE:-enp6s19}
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run}

while [ $# -gt 0 ]; do
    case $1 in
        --entries)    ENTRIES=$2; shift 2 ;;
        --sizes)      SIZES=$2; shift 2 ;;
        --out)        OUT=$2; shift 2 ;;
        --settle-ms)  SETTLE_MS=$2; shift 2 ;;
        --iface)      IFACE=$2; shift 2 ;;
        -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-map-batch: %s\n' "$*" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
json="$OUT/map-batch-$stamp.json"
csv="$OUT/map-batch.csv"
log="$OUT/map-batch-$stamp.log"

# The environment record is captured on the machine that is measured, not on this one.
# The tree goes there for that script alone; nothing is built on the target.
env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh on $TARGET_HOST produced no usable path: '$env_remote'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

bash scripts/lab/deploy.sh "$BUILD_HOST" \
    "CARGO_PROFILE_DEV_OPT_LEVEL=3 CARGO_PROFILE_TEST_OPT_LEVEL=3 \
     bash scripts/lab/target-build.sh --test measure_batch" \
    || die "the build on $BUILD_HOST failed"

remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
    | remote "$TARGET_HOST" "rm -rf ~/$RUN_DIR && mkdir -p ~/$RUN_DIR && tar xf - -C ~/$RUN_DIR" \
    || die "could not ship the measurement binary to $TARGET_HOST"

remote "$TARGET_HOST" "bash ~/$RUN_DIR/target-tests/target-run.sh \
    --entries $ENTRIES --sizes $SIZES --settle-ms $SETTLE_MS" 2>&1 | tee "$log"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the run on $TARGET_HOST failed, see $log"

# target-run.sh prints a header line of its own before the binary speaks, so the record
# is cut out by its braces rather than taken as the whole of stdout.
sed -n '/^{/,/^}/p' "$log" > "$json"
[ -s "$json" ] || die "no JSON record in $log"

# One throughput row per line is a property of the record, so the table needs no JSON
# parser on a host that may not have one. An empty table is refused rather than written.
{
    echo 'op,batch,elements,elapsed_ns,ns_per_element,elements_per_s'
    sed -n 's/.*"op": "\([^"]*\)", "batch": \([0-9]*\), "elements": \([0-9]*\), "elapsed_ns": \([0-9]*\), "ns_per_element": \([0-9.]*\), "elements_per_s": \([0-9.]*\).*/\1,\2,\3,\4,\5,\6/p' "$json"
} > "$csv"
[ "$(wc -l < "$csv")" -gt 1 ] || die "no throughput row parsed out of $json"

printf '\n%s\n' "$csv"
cat "$csv"
printf '\nkernel memory, from %s:\n' "$json"
grep -E '"memlock_bytes"|"list_empty"|"list_full"|"counters"|"idle_noise"|"on_create"|"on_fill"|"on_release"|"fill_sunreclaim_over_memlock"' "$json"
printf '\nrecord      %s\nenvironment %s\n' "$json" "$OUT/$(basename "$env_remote")"
