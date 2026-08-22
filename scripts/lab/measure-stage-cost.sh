#!/usr/bin/env bash
# What each stage of the pipeline costs, in nanoseconds, cycles and cache misses.
#
#   measure-stage-cost.sh [--out DIR] [--levels A,B,C] [--iface IF]
#
# Runs on the development host and drives the two lab machines, like measure-map-batch.sh
# and for the same reason: the measurement VM is the only machine that may be measured and
# the only one with no toolchain, so the binary is built static musl on the build VM and
# travels.
#
# **Where the ventilation comes from.** Not from a profile. Every stage is
# `#[inline(never)]` and does get its own JIT symbol, but the name the kernel keeps is the
# last component of the Rust path, so four stage symbols are called `run` and three parser
# symbols `parse`; and on this hardware `bpf_dispatcher_xdp` collects a third of the
# samples of a `perf record`, which makes the denominator of any percentage a guess. This
# script measures the whole path with the pipeline cut after stage k, for every k, and the
# cost of a stage is a difference of two nanosecond figures. The cut is a compare against
# a load-time global present only in the `stage-cutoff` build, and what that compare costs
# is the last line the sweep prints.
#
# The counters are taken per level, one process per level, because the load and the
# harness are the same work at every level: their difference is the stage between them.
# `perf stat` around the whole sweep would have measured nine loads and one pipeline.
#
# The cache event is `cache-misses` and not `LLC-load-misses`: the second is a generic
# alias this guest answers `<not supported>` for, and a missing counter that reads as a
# zero is worse than an absent column.
#
# No CARGO_PROFILE_*_OPT_LEVEL prefix here, unlike measure-map-batch.sh. The number this
# script reports is chronometered by the kernel around a `BPF_PROG_TEST_RUN` loop, so the
# optimisation level of the userspace harness is not in it.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/stage-cost
LEVELS=1,2,3,4,5,6,7,8,9
IFACE=${CARAPACE_IFACE:-enp6s19}
BUILD_HOST=${CARAPACE_BUILD_HOST:-lab-dev}
TARGET_HOST=${CARAPACE_TARGET_HOST:-lab-target}
REMOTE_DIR=${CARAPACE_REMOTE_DIR:-src}
RUN_DIR=${CARAPACE_RUN_DIR:-run}

# The floor and the repeat count are properties of the measurement, not knobs: the floor
# is the previous phase's XDP_PASS figure on this machine and the repeat count is the one
# the test compiles in. They are named so the CSV can carry them.
FLOOR_NS=15
PACKETS=1000000

while [ $# -gt 0 ]; do
    case $1 in
        --out)     OUT=$2; shift 2 ;;
        --levels)  LEVELS=$2; shift 2 ;;
        --iface)   IFACE=$2; shift 2 ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-stage-cost: %s\n' "$*" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
sweep="$OUT/sweep-$stamp.txt"
csv="$OUT/stage-cost.csv"

# The environment record is captured on the machine that is measured. The tree goes there
# for that one script; nothing is built on the target.
env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh on $TARGET_HOST produced no usable path: '$env_remote'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

bash scripts/lab/deploy.sh "$BUILD_HOST" \
    "bash scripts/lab/target-build.sh --test stage_cost --ebpf-features stage-cutoff" \
    || die "the build on $BUILD_HOST failed"

remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
    | remote "$TARGET_HOST" "rm -rf ~/$RUN_DIR && mkdir -p ~/$RUN_DIR && tar xf - -C ~/$RUN_DIR" \
    || die "could not ship the measurement binary to $TARGET_HOST"

# The sweep in one process: the readable table, and the assertion that the curve is not
# flat. A cutoff object built without the feature reports the same figure at every level,
# which reads exactly like a pipeline whose stages are free.
remote "$TARGET_HOST" "bash ~/$RUN_DIR/target-tests/target-run.sh --nocapture" 2>&1 \
    | tee "$sweep"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the sweep on $TARGET_HOST failed, see $sweep"

runner="cd ~/$RUN_DIR/target-tests && b=\$(ls bin/* | head -1) && sudo -n perf stat -x, \
-e cycles,instructions,cache-misses -- env CARAPACE_EBPF_OBJ=\$PWD/ebpf/instrumented \
CARAPACE_EBPF_PLAIN_OBJ=\$PWD/ebpf/plain CARAPACE_STAGE_CUTOFF=LEVEL \$b \
one_level_of_the_pipeline_under_a_profiler --exact --nocapture"

echo 'stages,label,ns_raw,ns_above_floor,ns_this_level,cycles,instructions,ipc,llc_misses,llc_misses_per_packet' > "$csv"

previous_above=0
rows=0
for level in ${LEVELS//,/ }; do
    printf '\n--- level %s\n' "$level"
    out=$(remote "$TARGET_HOST" "${runner//LEVEL/$level}" 2>&1)

    record=$(printf '%s\n' "$out" | sed -n 's/^LEVEL,\([0-9]*\),\(.*\),\([0-9]*\)$/\1;\2;\3/p' | tail -1)
    [ -n "$record" ] || { printf '%s\n' "$out" >&2; die "level $level printed no LEVEL record"; }
    label=${record#*;}; label=${label%;*}
    ns_raw=${record##*;}
    case $ns_raw in ''|*[!0-9]*) die "level $level reported '$ns_raw' nanoseconds" ;; esac

    # perf writes its table to stderr in the -x, form: value,unit,event,...
    field() {
        printf '%s\n' "$out" | awk -F, -v ev="$1" '$3 == ev { print $1; exit }'
    }
    # A counter perf could not deliver reads `<not supported>`, which is not a number. It
    # becomes an empty cell rather than entering an arithmetic that would report a zero.
    numeric() { case $1 in ''|*[!0-9]*) echo "" ;; *) echo "$1" ;; esac; }
    cycles=$(numeric "$(field cycles)")
    instructions=$(numeric "$(field instructions)")
    llc=$(numeric "$(field cache-misses)")

    ipc=""
    if [ -n "$cycles" ] && [ -n "$instructions" ] && [ "$cycles" -gt 0 ]; then
        # The ternary is parenthesised: awk reads a bare `>` as a redirection and would
        # write to a file called 0 instead of printing.
        ipc=$(awk -v i="$instructions" -v c="$cycles" 'BEGIN { printf "%.3f", (c > 0 ? i / c : 0) }')
    fi
    llc_per_pkt=""
    if [ -n "$llc" ]; then
        llc_per_pkt=$(awk -v m="$llc" -v p="$PACKETS" 'BEGIN { printf "%.4f", (p > 0 ? m / p : 0) }')
    fi

    above=$((ns_raw - FLOOR_NS))
    [ "$above" -lt 0 ] && above=0
    this=$((above - previous_above))
    previous_above=$above

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$level" "$label" "$ns_raw" "$above" "$this" \
        "$cycles" "$instructions" "$ipc" "$llc" "$llc_per_pkt" >> "$csv"
    rows=$((rows + 1))
done

[ "$rows" -gt 1 ] || die "one level is not a ventilation"

# A flat curve is the failure mode that looks like a result. Refuse it here rather than
# leave it to a reader: the whole point of the sweep is that the levels differ.
first=$(awk -F, 'NR == 2 { print $4 }' "$csv")
last=$(awk -F, 'END { print $4 }' "$csv")
case $first$last in ''|*[!0-9]*) die "the CSV carries no nanosecond column" ;; esac
[ "$last" -gt "$first" ] \
    || die "the deepest level costs $last ns and the shallowest $first ns: the object was built without the stage-cutoff feature, so every level ran the whole pipeline"

printf '\n%s\n' "$csv"
column -s, -t "$csv" 2>/dev/null || cat "$csv"
printf '\nsweep       %s\nenvironment %s\n' "$sweep" "$OUT/$(basename "$env_remote")"
