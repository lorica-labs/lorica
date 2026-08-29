#!/usr/bin/env bash
# What each stage of the pipeline costs, in nanoseconds, cycles and cache misses.
#
#   measure-stage-cost.sh [--out DIR] [--levels A,B,C] [--iface IF]
#                         [--max-instructions N] [--max-ns N] [--max-cycles N]
#
# **Which unit to quote, and why it is not the nanoseconds.** The `ns` columns are the
# `duration` field `BPF_PROG_TEST_RUN` returns, and that field was measured against the CPU
# time of the same work: 128 ns of `duration` for 262 ns of task-clock, a factor of 2.06,
# stable across levels and across repeats. Every nanosecond this project has ever published
# comes from that field, so every *ratio* and every stage-to-stage *difference* stays valid —
# the factor is common to both terms — while every *absolute* is about half the CPU time
# actually spent. The frequency cannot be pinned from inside the guest either: there is no
# cpufreq at all, and /proc/cpuinfo reports the nominal TSC rate rather than the core clock.
# Measured out of `cycles / task-clock`, this host runs at 1.87 to 1.95 GHz with no turbo.
#
# So **cycles per packet is the figure to quote** rather than the nanoseconds, because it
# assumes no clock this guest cannot read -- but the 0.4 % reproducibility this header used to
# claim for it is not what this machine delivers. Three consecutive runs of one unchanged
# program measured 612.5, 619.7 and 652.4 cycles per packet, monotonically rising, a spread of
# 6.5 %; the instruction count over the same three runs was 1444.5, 1444.5 and 1445.4, a
# spread of 0.06 %. Nothing here explains the drift, and it is not neighbour load: the lowest
# figure came from the busiest run.
#
# What follows from that: **the instruction ceiling is the tight guard and the cycle ceiling is
# not**. A code regression is caught at a tenth of an instruction per packet. The cycle ceiling
# has to carry the 6.5 % this machine moves by, so it only catches a gross change, and its
# margin is a measurement of the instrument rather than a budget for the program.
#
# The three ceilings, on 6.8.0-138 with the whole signature catalogue armed, which is the
# largest program the configuration space produces: 1298.4 instructions, 531 cycles and
# 131 ns of `duration` per packet. Armed at 1325 (2 %, ten times the 0.16 % spread), 545
# (2.6 %) and 144 (10 %). None is a CI step and the reason is in ci.yml; all three say so
# out loud when they are not armed, because a ceiling of 765 stood against a program of 1317
# for a whole phase and the absent flag is why nobody saw it.
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
# Empty by default: the sweep prints how many levels the pipeline has and this script
# reads it from there. A list written down here went stale the day a stage folded into the
# parse, and the script then asked for a level that does not exist and reported the refusal
# as a broken measurement. --levels stays, for measuring one level on purpose.
LEVELS=
# Extra eBPF features to build the measured object with, comma separated, on top of
# `stage-cutoff`. Empty by default: the sweep measures the object that ships. It exists so
# a variant behind a feature flag can be measured with the same instrument and in the same
# session as its baseline, which is the only way a difference between the two is about the
# code rather than about two afternoons.
EBPF_EXTRA=${EBPF_EXTRA:-}
# Empty means report only. Set it and the deepest level is compared against it and the
# script fails on excess: that is assertion 3, armed on instructions and not on nanoseconds
# because instructions reproduce to about one per packet where the nanoseconds drift.
MAX_INSTRUCTIONS=
# The same, in nanoseconds. Armable here and not in a Rust test, because a nanosecond
# ceiling is a property of one machine and this script names the machine it drives, while a
# test runs wherever the suite runs: the same pipeline reads 121 ns on the measurement VM
# and about 158 on the build VM, so a checked-in constant would be wrong on one of them.
MAX_NS=
# And in cycles, which is the unit that needs no frequency and reproduces six times better
# than the nanoseconds. See the note on units below.
MAX_CYCLES=
IFACE=${LORICA_IFACE:-enp6s19}
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run}

# The floor and the repeat count are properties of the measurement, not knobs: the floor
# is the previous phase's XDP_PASS figure on this machine and the repeat count is the one
# the test compiles in. They are named so the CSV can carry them.
FLOOR_NS=15
PACKETS=1000000

while [ $# -gt 0 ]; do
    case $1 in
        --out)     OUT=$2; shift 2 ;;
        --levels)  LEVELS=$2; shift 2 ;;
        --max-instructions) MAX_INSTRUCTIONS=$2; shift 2 ;;
        --max-ns)  MAX_NS=$2; shift 2 ;;
        --max-cycles) MAX_CYCLES=$2; shift 2 ;;
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
    "bash scripts/lab/target-build.sh --test stage_cost --ebpf-features stage-cutoff${EBPF_EXTRA:+,$EBPF_EXTRA}" \
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

# The profiler is named rather than assumed, the way kernel-matrix.sh already names it, and
# sudo is asked for only when it is needed. Proxmox ships its perf as `perf_7.0` and no `perf`
# at all, and a host that runs this as root holds the capabilities without having sudo
# installed. Both were true of the first machine outside the lab VMs this was pointed at, and
# it refused on each in turn while wanting nothing it did not already have.
PERF=${LORICA_PERF:-perf}
# The uid that matters is the one on the target, not the one running this script. Asking the
# local shell would answer about the wrong machine and quietly drop the sudo the lab VMs need.
remote_uid=$(remote "$TARGET_HOST" "id -u" | tr -dc "[:digit:]")
case $remote_uid in
    '') die "could not read the uid on $TARGET_HOST" ;;
    0) elevate="" ;;
    *) elevate="sudo -n " ;;
esac
remote "$TARGET_HOST" "command -v $PERF >/dev/null" \
    || die "$TARGET_HOST has no $PERF on its PATH: name the binary with LORICA_PERF, and note that a Proxmox host calls it perf_7.0"

# The command and the parse of what it prints live in scripts/lab/test-run-level.sh, so
# that measure-noise.sh measures this load and not a second copy of it that drifts.
# shellcheck source=scripts/lab/test-run-level.sh
. scripts/lab/test-run-level.sh

echo 'stages,label,ns_raw,ns_above_floor,ns_this_level,cycles,instructions,ipc,llc_misses,llc_misses_per_packet' > "$csv"

previous_above=0
rows=0
if [ -z "$LEVELS" ]; then
    count=$(grep "^LEVELS," "$sweep" | tail -1 | cut -d, -f2 | tr -dc "[:digit:]")
    case $count in
        ''|*[!0-9]*) die "the sweep did not say how many levels the pipeline has, see $sweep" ;;
    esac
    # From one, because level one is the program returning immediately: it is this object's
    # own startup, which every figure below subtracts. A profiler around this process counts
    # the load and the verifier once, and the only term that cancels them is another run of
    # the same object.
    level=1
    while [ "$level" -le "$count" ]; do
        LEVELS="$LEVELS $level"
        level=$((level + 1))
    done
fi

for level in ${LEVELS//,/ }; do
    printf '\n--- level %s\n' "$level"
    out=$(remote "$TARGET_HOST" "$(test_run_command "$RUN_DIR" "$level" "$elevate" "$PERF")" 2>&1)

    test_run_fields "$out" \
        || { printf '%s\n' "$out" >&2; die "level $level printed no LEVEL record"; }
    label=$TR_LABEL
    ns_raw=$TR_NS
    case $ns_raw in ''|*[!0-9]*) die "level $level reported '$ns_raw' nanoseconds" ;; esac

    cycles=$TR_CYCLES
    instructions=$TR_INSTRUCTIONS
    llc=$TR_LLC

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

# A flat curve is the failure mode that looks like a result, so it is refused here rather
# than left to a reader. On the instruction column and not on the nanoseconds: the whole
# pipeline is seventy nanoseconds now, so a single-shot per-level figure carries more drift
# than the difference between two levels, and this guard fired on its own noise. Instructions
# are deterministic to about one per packet, which is what a "did the cutoff take" check needs.
floor=$(awk -F, 'NR == 2 { print $7 }' "$csv")
deepest=$(awk -F, 'END { print $7 }' "$csv")
floor_cycles=$(awk -F, 'NR == 2 { print $6 }' "$csv")
deepest_cycles=$(awk -F, 'END { print $6 }' "$csv")
case $floor$deepest$floor_cycles$deepest_cycles in
    ''|*[!0-9]*) die "the CSV carries no instruction or cycle column" ;;
esac
[ "$deepest" -gt "$floor" ] || die "the deepest level executes $deepest instructions and the empty program $floor: the object was built without the stage-cutoff feature, so every level ran the whole pipeline"

# The program, with the harness subtracted. This is the figure assertion 3 is armed on:
# the syscall and the kernel test-run loop are in both terms and cancel, which is what
# makes it comparable at all, and it reproduces to about one instruction per packet.
per_packet=$(awk -v d="$deepest" -v f="$floor" -v p="$PACKETS" 'BEGIN { printf "%.1f", (p > 0 ? (d - f) / p : 0) }')
echo
echo "instructions per packet, harness subtracted: $per_packet"

# An unarmed guard that says nothing is the failure mode this project has already paid for:
# the ceiling stood at 765 while the program measured 1317, and because the flag was absent
# nothing anywhere said so. Silence is now impossible in either direction.
if [ -n "$MAX_INSTRUCTIONS" ]; then
    over=$(awk -v v="$per_packet" -v m="$MAX_INSTRUCTIONS" 'BEGIN { print (v > m ? 1 : 0) }')
    [ "$over" -eq 0 ] || die "$per_packet instructions per packet against a ceiling of $MAX_INSTRUCTIONS"
    echo "assertion 3: $per_packet instructions per packet, ceiling $MAX_INSTRUCTIONS, within budget"
else
    echo "assertion 3: NOT ARMED, no --max-instructions given. $per_packet measured, nothing checked."
fi

# Cycles per packet, by the same subtraction as the instructions and for the same reason.
# This is the figure to quote: it reproduces to 0.4 % where the nanoseconds reproduce to
# 2.4 %, and it carries no assumption about a frequency this guest cannot even read.
per_packet_cycles=$(awk -v d="$deepest_cycles" -v f="$floor_cycles" -v p="$PACKETS" 'BEGIN { printf "%.1f", (p > 0 ? (d - f) / p : 0) }')
echo "cycles per packet, harness subtracted:       $per_packet_cycles"

if [ -n "$MAX_CYCLES" ]; then
    over=$(awk -v v="$per_packet_cycles" -v m="$MAX_CYCLES" 'BEGIN { print (v > m ? 1 : 0) }')
    [ "$over" -eq 0 ] || die "$per_packet_cycles cycles per packet against a ceiling of $MAX_CYCLES"
    echo "assertion 3 ter: $per_packet_cycles cycles per packet, ceiling $MAX_CYCLES, within budget"
else
    echo "assertion 3 ter: NOT ARMED, no --max-cycles given."
fi

if [ -n "$MAX_NS" ]; then
    deepest_ns=$(cut -d, -f4 "$csv" | tail -1)
    over=$(awk -v v="$deepest_ns" -v m="$MAX_NS" 'BEGIN { print (v > m ? 1 : 0) }')
    [ "$over" -eq 0 ] || die "$deepest_ns ns per packet against a ceiling of $MAX_NS"
    echo "assertion 3 bis: $deepest_ns ns per packet above the floor, ceiling $MAX_NS, within budget"
else
    echo "assertion 3 bis: NOT ARMED, no --max-ns given."
fi

printf '\n%s\n' "$csv"
column -s, -t "$csv" 2>/dev/null || cat "$csv"
printf '\nsweep       %s\nenvironment %s\n' "$sweep" "$OUT/$(basename "$env_remote")"
