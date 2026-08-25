#!/usr/bin/env bash
# Measure what the per-prefix cardinality scan costs, per instruction set, on the machine
# that is allowed to publish numbers.
#
#   replay-carpet-bombing.sh [--prefixes N[,N...]] [--out DIR] [--samples N] [--iface NAME]
#
# Runs wherever the agent would run. It attaches nothing, opens no socket and loads no
# bytecode: the stage under measurement is userspace arithmetic over a buffer the tick
# already read. That is why nanoseconds printed here are nanoseconds and the metrology
# correction that applies to `BPF_PROG_TEST_RUN` timings does not reach them.
#
# Two things are produced and the order is not cosmetic. First the equivalence between the
# vector paths and the scalar reference is re-established on this processor, because a scan
# cost measured on paths that disagree is the cost of computing the wrong answer. Only then
# is the cost measured, one figure per instruction set the processor actually has.
#
# WHY THIS SCRIPT REFUSES MORE THAN IT REPORTS. A harness that can print a number without
# having measured one invalidates every green it has ever returned, and this tree has been
# caught by that twice, both times on a full disk. So: the previous criterion estimates for
# these ids are deleted before the run, so a stale file cannot be read as this run's result;
# free space is checked before anything is written; the set of paths the processor reports
# is compared against the set criterion actually produced an estimate for, and a path that
# is present in the first and missing from the second aborts the whole campaign instead of
# being skipped; a mean of zero or below aborts it too. A path the processor does not have
# is named as unavailable and never given a figure.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

PREFIXES=256
OUT=bench/results/cardinality
SAMPLES=
# No wire is involved, so the environment record is told so rather than being pointed at a
# test NIC it would report nothing about.
IFACE=lo

while [ $# -gt 0 ]; do
    case $1 in
        --prefixes) PREFIXES=$2; shift 2 ;;
        --out)      OUT=$2; shift 2 ;;
        --samples)  SAMPLES=$2; shift 2 ;;
        --iface)    IFACE=$2; shift 2 ;;
        -h|--help)  sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'replay-carpet-bombing: %s\n' "$1" >&2; exit 2; }

command -v cargo >/dev/null || die "no cargo on this host"
command -v python3 >/dev/null || die "no python3: reading criterion's estimates needs it"

sizes=$(echo "$PREFIXES" | tr ',' ' ')
[ -n "$sizes" ] || die "--prefixes takes at least one entry count"
for n in $sizes; do
    case $n in
        ''|*[!0-9]*) die "--prefixes takes positive integers separated by commas, got $PREFIXES" ;;
    esac
    [ "$n" -gt 0 ] || die "--prefixes takes positive integers, got $n"
done

if [ -n "$SAMPLES" ]; then
    case $SAMPLES in
        ''|*[!0-9]*) die "--samples takes a positive integer, got $SAMPLES" ;;
    esac
    # Criterion's own floor. Below it the harness refuses and there would be no estimate to
    # read, which is the failure this script exists to make loud rather than silent.
    [ "$SAMPLES" -ge 10 ] || die "--samples below 10 is one criterion refuses to run"
fi

# Before anything is written. The two bad campaigns this guard exists for both ended with a
# full disk and a results directory holding a plausible-looking zero.
free_kb=$(df -Pk . | awk 'NR==2 {print $4}')
case ${free_kb:-} in
    ''|*[!0-9]*) die "could not read free space on the tree's filesystem" ;;
esac
[ "$free_kb" -ge 262144 ] || die "only $free_kb KiB free where criterion writes its estimates: refusing to start a campaign that would report a short write as a measurement"

mkdir -p "$OUT" || die "cannot create $OUT"

# The paths this processor has, read from the processor and not from the bench. Comparing
# this list against what criterion produced is the whole difference between "that path is
# not here" and "that path did not run".
flags=$(awk '/^flags|^Features/ { print; exit }' /proc/cpuinfo)
[ -n "$flags" ] || die "/proc/cpuinfo reported no feature line, so no expected path set can be derived"
has() { case " $flags " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

expected=(scalar)
has avx2 && expected+=(avx2)
has avx512f && expected+=(avx512)
# aarch64 spells NEON `asimd` in /proc/cpuinfo.
has asimd && expected+=(neon)

absent=()
for isa in scalar avx512 avx2 neon; do
    case " ${expected[*]} " in
        *" $isa "*) ;;
        *) absent+=("$isa") ;;
    esac
done

env_file=$(scripts/lab/capture-env.sh "$OUT" "$IFACE")
[ -n "$env_file" ] || die "capture-env produced no path"

# Correctness first. --nocapture so the per-path equivalence line and the measured
# allocation count land in the log rather than being swallowed by the harness.
if ! cargo test -p lorica-detect --test cardinality -- --nocapture > "$OUT/equivalence.log" 2>&1; then
    die "the vector/scalar equivalence test failed, see $OUT/equivalence.log. No cost is reported: a scan cost on paths that disagree is the cost of the wrong answer"
fi

# Deleted, not overwritten. criterion keeps the previous run under the same id, so a bench
# that dies leaves an estimates.json that reads exactly like a fresh one.
rm -rf target/criterion/scan

pace=()
[ -z "$SAMPLES" ] || pace=(-- --sample-size "$SAMPLES")
if ! LORICA_CARD_PREFIXES=$PREFIXES \
    cargo bench -p lorica-detect --bench scan "${pace[@]}" > "$OUT/bench.log" 2>&1; then
    die "cargo bench failed, see $OUT/bench.log"
fi

reader=$(mktemp) || die "cannot create a temporary file"
trap 'rm -f "$reader"' EXIT
cat > "$reader" <<'PY'
import json
import os
import sys

csv_path = sys.argv[1]
isas = os.environ["CARD_ISAS"].split()
sizes = os.environ["CARD_SIZES"].split()

rows = []
missing = []
for size in sizes:
    for isa in isas:
        # `benches/scan.rs` names its ids `<isa>_<slots>` for exactly this: criterion
        # rewrites a slash in an id, and a path assembled from the console output would be
        # a guess at that rewriting.
        bench_id = "%s_%s" % (isa, size)
        est = os.path.join("target", "criterion", "scan", bench_id, "new", "estimates.json")
        try:
            with open(est) as handle:
                mean = json.load(handle)["mean"]
            point = mean["point_estimate"]
            lower = mean["confidence_interval"]["lower_bound"]
            upper = mean["confidence_interval"]["upper_bound"]
        except (OSError, ValueError, KeyError, TypeError):
            missing.append("%s/%s" % (isa, size))
            continue
        if not (point > 0 and lower > 0 and upper > 0):
            sys.exit("%s holds a mean of %r, which is not a measurement" % (est, point))
        rows.append("%s,%s,%.2f,%.2f,%.2f" % (isa, size, point, lower, upper))

if missing:
    sys.exit(
        "the processor reports these paths and criterion produced no estimate for them: %s. "
        "That is a campaign that did not run, not a campaign with nothing to say"
        % ", ".join(missing)
    )
if not rows:
    sys.exit("no row survived, so nothing is written")

with open(csv_path, "w") as handle:
    handle.write("isa,prefixes,mean_ns,lower_ns,upper_ns\n")
    for row in rows:
        handle.write(row + "\n")
print(len(rows))
PY

csv="$OUT/carpet-bombing.csv"
rows=$(CARD_ISAS="${expected[*]}" CARD_SIZES="$sizes" python3 "$reader" "$csv")
status=$?
[ "$status" -eq 0 ] || die "the estimates were not readable as measurements (above); $csv was not written"
[ -s "$csv" ] || die "$csv is empty after a run that reported $rows rows"
case ${rows:-} in
    ''|*[!0-9]*) die "the estimate reader printed no row count" ;;
esac
[ "$rows" -gt 0 ] || die "zero rows: refusing to call this a result"

model=$(awk -F: '/model name|^Model/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo)
printf 'replay-carpet-bombing: host=%s cpu=%s prefixes=%s measured=%s unavailable=%s rows=%s env=%s\n' \
    "$(hostname)" "${model:-unknown}" "$PREFIXES" "${expected[*]}" "${absent[*]:-none}" "$rows" "$env_file"
# The rows themselves, so the terminal carries the same numbers the file does.
while IFS= read -r line; do
    printf 'replay-carpet-bombing: %s\n' "$line"
done < "$csv"

echo "$csv"
