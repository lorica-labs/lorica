#!/usr/bin/env bash
# What each layout of a leaky-bucket bank costs, and where it stops scaling.
#
#   measure-bucket-contention.sh [--out DIR] [--repeat N] [--cpus N] [--iface IF]
#
# Runs on the development host and drives the two lab machines, like
# measure-map-batch.sh. The bench object is C compiled by clang, so it is built on the
# build VM and travels to the measurement VM, which has no compiler; the frames travel
# with it because their source port chooses which bucket the program aims at.
#
# The decision this feeds is which layout the bank takes, and the answer is not free in
# either direction. A per-CPU bank never contends and is exact only in steady state, so a
# flood spread over source ports leaves each shard under rho while the aggregate exceeds
# the budget by a factor of N. A shared bank is exact at every instant and pays either a
# spin lock — two helper calls, and the per-packet budget already spends its one on the
# clock — or a lost update when two cores charge the same bucket.
#
# The same bench answers a second question, because it is the same trade-off under another
# name: reading fifty thousand per-CPU counters costs 264 ns a slot, the way out is a
# shared mmappable array, and BPF_F_MMAPABLE exists only for a non-per-CPU array. So the
# last two variants price a per-CPU counter bump against an atomic one.
#
# What this does NOT measure, and the report says so: the dilution factor itself. That
# needs RSS steering real traffic across queues, so it belongs to the wire sweep, where
# the lab has four queues and can therefore demonstrate the mechanism and a factor of
# four — never the factor of sixteen the motivation cites.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/bucket-contention
REPEAT=5000000
CPUS=0
IFACE=${LORICA_IFACE:-enp6s19}
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
BENCH_DIR=${LORICA_BENCH_DIR:-bucket-bench}

while [ $# -gt 0 ]; do
    case $1 in
        --out)     OUT=$2; shift 2 ;;
        --repeat)  REPEAT=$2; shift 2 ;;
        --cpus)    CPUS=$2; shift 2 ;;
        --iface)   IFACE=$2; shift 2 ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-bucket-contention: %s\n' "$*" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
csv="$OUT/bucket-contention.csv"
leakcsv="$OUT/bucket-leak.csv"
log="$OUT/bucket-contention-$stamp.log"
leaklog="$OUT/bucket-leak-$stamp.log"

# The tree goes to the measurement VM for two scripts it runs itself: the environment
# capture and the bench runner. Nothing is built there.
env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh on $TARGET_HOST produced no usable path: '$env_remote'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

target_cpus=$(remote "$TARGET_HOST" "nproc" | tr -d '\r')
case $target_cpus in ''|*[!0-9]*) die "cannot read the CPU count of $TARGET_HOST" ;; esac
[ "$CPUS" -gt 0 ] 2>/dev/null || CPUS=$target_cpus

# Two frames per CPU, differing only in source port, because that is the index of the
# bank. `p$i` aims at bucket i and `q$i` at bucket i * 64. A bucket is sixteen bytes, so
# the p set puts four buckets in ONE 64-byte cache line and the q set puts them a kilobyte
# apart: the difference between those two rows is false sharing, measured rather than
# reasoned about. The first version of this script had only the p set and read its own
# false sharing as a property of the layout.
#
# Built where python3 and clang are, shipped where the kernel under test is. The list of
# frames is accumulated in a loop rather than through seq and tr, because a tr set is one
# level of quoting away from replacing the letter n in every file name.
LINE_STRIDE=64
build="make -C bench/progs xdp_bucket_bench.o >/dev/null"
frames=""
i=0
while [ "$i" -lt "$CPUS" ]; do
    build="$build && python3 bench/progs/mkpkt.py bench/progs/p$i.bin 64 $i"
    build="$build && python3 bench/progs/mkpkt.py bench/progs/q$i.bin 64 $((i * LINE_STRIDE))"
    frames="$frames p$i.bin q$i.bin"
    i=$((i + 1))
done

bash scripts/lab/deploy.sh "$BUILD_HOST" "$build" || die "the bench build on $BUILD_HOST failed"

remote "$BUILD_HOST" "tar cf - -C ~/$REMOTE_DIR/bench/progs xdp_bucket_bench.o $frames" \
    | remote "$TARGET_HOST" "rm -rf ~/$BENCH_DIR && mkdir -p ~/$BENCH_DIR && tar xf - -C ~/$BENCH_DIR" \
    || die "could not ship the bench object to $TARGET_HOST"

runner="bash ~/$REMOTE_DIR/scripts/lab/bucket-bench-run.sh     --object ~/$BENCH_DIR/xdp_bucket_bench.o --packets ~/$BENCH_DIR     --repeat $REPEAT --cpus $CPUS"

remote "$TARGET_HOST" "$runner --phase cost" 2>&1 | tee "$log"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the cost phase on $TARGET_HOST failed, see $log"

remote "$TARGET_HOST" "$runner --phase leak" 2>&1 | tee "$leaklog"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the leak phase on $TARGET_HOST failed, see $leaklog"

# Each runner prints CSV and nothing else, but the ssh wrapper and the login shell can add
# lines, so each table is cut out by its own header rather than taken as the whole of
# stdout.
sed -n '/^variant,cpus,distribution/,$p' "$log" | grep -v '^$' > "$csv"
[ "$(wc -l < "$csv")" -gt 1 ] || die "no cost row in $log"
sed -n '/^variant,cpus,repeat/,$p' "$leaklog" | grep -v '^$' > "$leakcsv"
[ "$(wc -l < "$leakcsv")" -gt 1 ] || die "no leak row in $leaklog"

printf '\n%s\n' "$csv"
column -s, -t "$csv" 2>/dev/null || cat "$csv"
printf '\n%s\n' "$leakcsv"
column -s, -t "$leakcsv" 2>/dev/null || cat "$leakcsv"
printf '\nlogs        %s\n            %s\nenvironment %s\n' "$log" "$leaklog" "$OUT/$(basename "$env_remote")"
