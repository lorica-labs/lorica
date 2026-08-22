#!/usr/bin/env bash
# What a reverse-path lookup costs against the LPM lookup the pipeline already pays.
#
#   measure-fib-vs-lpm.sh [--out DIR] [--repeat N] [--iface IF]
#
# Runs on the development host and drives both lab machines, like
# measure-bucket-contention.sh: the fixture is C compiled by clang on the build VM and the
# kernel under test is on the measurement VM, which has no compiler.
#
# This conditions whether stage 5 is worth its place at all. The criterion decides WHETHER
# to arm reverse path filtering; this decides what arming it costs. Both numbers are read
# from the same frame in the same harness, so their ratio means something even though
# neither absolute value belongs to a real ingress interface — a test-run frame carries no
# ingress interface, so the fixture asks about loopback. The ratio is the deliverable; the
# absolute figures are reported with that caveat attached.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/fib-vs-lpm
REPEAT=1000000
IFACE=${CARAPACE_IFACE:-enp6s19}
BUILD_HOST=${CARAPACE_BUILD_HOST:-lab-dev}
TARGET_HOST=${CARAPACE_TARGET_HOST:-lab-target}
REMOTE_DIR=${CARAPACE_REMOTE_DIR:-src}
BENCH_DIR=${CARAPACE_BENCH_DIR:-fib-bench}
PIN=/sys/fs/bpf/fib-bench

while [ $# -gt 0 ]; do
    case $1 in
        --out)     OUT=$2; shift 2 ;;
        --repeat)  REPEAT=$2; shift 2 ;;
        --iface)   IFACE=$2; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-fib-vs-lpm: %s\n' "$*" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
csv="$OUT/fib-vs-lpm.csv"
log="$OUT/fib-vs-lpm-$stamp.log"

env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh on $TARGET_HOST produced no usable path: '$env_remote'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

bash scripts/lab/deploy.sh "$BUILD_HOST" \
    "make -C bench/progs xdp_fib_bench.o >/dev/null && python3 bench/progs/mkpkt.py bench/progs/fib.bin 64 0" \
    || die "the fixture build on $BUILD_HOST failed"

remote "$BUILD_HOST" "tar cf - -C ~/$REMOTE_DIR/bench/progs xdp_fib_bench.o fib.bin" \
    | remote "$TARGET_HOST" "rm -rf ~/$BENCH_DIR && mkdir -p ~/$BENCH_DIR && tar xf - -C ~/$BENCH_DIR" \
    || die "could not ship the fixture to $TARGET_HOST"

# One remote call per step, and not one command that does everything. A remote command is
# re-wrapped in single quotes on the way, so a single quote anywhere inside it — a
# `tr -d` argument, a `printf` format — closes the wrapper and the shell reports a syntax
# error at the end of a line it never showed. Splitting the steps removes the need for any
# quote at all.
#
# One process at a time: this measures the cost of a call and not contention, so nothing
# here needs several CPUs. The floor of the harness is the 15 ns an empty XDP_PASS costs on
# this machine and it is subtracted in the report, not here.
remote "$TARGET_HOST" "sudo -n rm -rf $PIN; sudo -n mkdir -p $PIN/maps" >/dev/null 2>&1
remote "$TARGET_HOST" \
    "sudo -n bpftool prog loadall ~/$BENCH_DIR/xdp_fib_bench.o $PIN pinmaps $PIN/maps" \
    || die "the verifier refused the fixture on $TARGET_HOST"

: > "$log"
for program in xdp_fib_reverse xdp_lpm_reverse; do
    printf '%s ' "$program" >> "$log"
    remote "$TARGET_HOST" \
        "sudo -n bpftool prog run pinned $PIN/$program data_in ~/$BENCH_DIR/fib.bin repeat $REPEAT" \
        >> "$log" 2>&1 \
        || die "$program did not run on $TARGET_HOST, see $log"
done
printf 'returns:\n' >> "$log"
remote "$TARGET_HOST" "sudo -n bpftool map dump pinned $PIN/maps/fib_returns" >> "$log" 2>&1
remote "$TARGET_HOST" "sudo -n rm -rf $PIN" >/dev/null 2>&1
cat "$log"

{
    echo 'program,repeat,ns_per_run'
    sed -n 's/^\(xdp_[a-z_]*\) .*duration (average): \([0-9]*\)ns.*/\1,'"$REPEAT"',\2/p' "$log"
} > "$csv"
[ "$(wc -l < "$csv")" -eq 3 ] \
    || die "expected two rows in $csv, got $(( $(wc -l < "$csv") - 1 )); see $log"

fib=$(awk -F, '$1 == "xdp_fib_reverse" { print $3 }' "$csv")
lpm=$(awk -F, '$1 == "xdp_lpm_reverse" { print $3 }' "$csv")
case $fib$lpm in ''|*[!0-9]*) die "one of the two figures is not a number: fib='$fib' lpm='$lpm'" ;; esac

printf '\n%s\n' "$csv"
column -s, -t "$csv" 2>/dev/null || cat "$csv"
# The floor is subtracted here rather than in the fixture, and the ratio is taken on the
# figures with the floor removed: a ratio of two numbers that both carry 15 ns of harness
# understates the difference between them.
awk -v f="$fib" -v l="$lpm" 'BEGIN {
    fa = (f > 15 ? f - 15 : 0); la = (l > 15 ? l - 15 : 0)
    printf "\nabove the 15 ns floor: fib %d ns, lpm %d ns, ratio %s\n", fa, la,
        (la > 0 ? sprintf("%.2f", fa / la) : "undefined, the LPM lookup measured at the floor")
}'
printf '\nlog         %s\nenvironment %s\n' "$log" "$OUT/$(basename "$env_remote")"
