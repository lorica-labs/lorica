#!/usr/bin/env bash
# What the agent costs to read its counters. Runs ON the measurement VM.
#
#   measure-agent-cpu.sh --agent PATH --object PATH [--counters N] [--hz N]
#                        [--duration S] [--batch N] [--sweep-every N] [--settle S]
#                        [--cpu-budget PCT] [--rss-max KIB] [--out DIR]
#
# The exit criterion of this phase is a percentage of one core, measured and not derived,
# so the method matters more than the number:
#
#   * CPU comes from utime+stime in /proc/<pid>/stat, read before and after, divided by
#     the wall time and by one core. Not from `time`, which would include the fork and
#     the load of the eBPF object, and not from `top`, which samples.
#   * The load of the program and the sizing of the map happen before the first sample.
#     They are startup, they happen once, and counting them would make a long run look
#     cheaper than a short one on the same code.
#   * RSS is read after a declared settling window, and the window is printed with the
#     number. jemalloc returns 90 % of a peak after about 8.8 s on this hardware,
#     measured, so an RSS taken immediately after startup reports the allocator holding
#     pages rather than the agent needing them.
#
# It writes the raw counters it read, not only the ratio: a percentage with no numerator
# cannot be checked by anybody later.

set -uo pipefail

# No cd. Unlike the other lab scripts this one is copied next to the binary it measures,
# because the machine it runs on has no checkout, so every path it is given is relative
# to wherever the caller stands.

AGENT=""
OBJECT=""
COUNTERS=50000
HZ=10
DURATION=300
BATCH=1000
SWEEP_EVERY=1
SETTLE=15
# The two numbers of the invisibility contract. Named here so a run says which contract
# it was judged against, rather than the reader assuming the ones in a document.
CPU_BUDGET=1.0
RSS_MAX=51200
OUT=bench/results/agent-cpu

while [ $# -gt 0 ]; do
    case $1 in
        --agent)     AGENT=$2; shift 2 ;;
        --object)    OBJECT=$2; shift 2 ;;
        --counters)  COUNTERS=$2; shift 2 ;;
        --hz)        HZ=$2; shift 2 ;;
        --duration)  DURATION=$2; shift 2 ;;
        --batch)     BATCH=$2; shift 2 ;;
        --sweep-every) SWEEP_EVERY=$2; shift 2 ;;
        --settle)    SETTLE=$2; shift 2 ;;
        --cpu-budget) CPU_BUDGET=$2; shift 2 ;;
        --rss-max)   RSS_MAX=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

[ -x "$AGENT" ] || die "--agent must point at an executable, got '${AGENT}'"
[ -f "$OBJECT" ] || die "--object must point at the eBPF object, got '${OBJECT}'"
[ "$DURATION" -gt "$SETTLE" ] || die "--duration must exceed --settle, or RSS is read after the end"

# The number the cost is linear in, computed once: the named counters every tick plus
# the whole map every SWEEP_EVERY ticks. 18 is CounterId::COUNT, and the agent prints its
# own figure at startup, which is checked against this one below.
SLOT_READS=$(( 18 * HZ + (COUNTERS * HZ) / SWEEP_EVERY ))

mkdir -p "$OUT" || die "cannot create $OUT"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TICKS_PER_S=$(getconf CLK_TCK)
[ -n "$TICKS_PER_S" ] || die "getconf CLK_TCK said nothing, so no CPU time can be converted"
CPUS=$(nproc)
POSSIBLE=$(cat /sys/devices/system/cpu/possible)

[ -n "$(command -v sudo)" ] && sudo -n true 2>/dev/null \
    || die "loading a BPF program needs CAP_BPF, and sudo asks for a password"

SOCKET=/run/carapace/measure-$$.sock
LOG=$OUT/agent-$STAMP.log

sudo -n "$AGENT" --object "$OBJECT" --socket "$SOCKET" \
    --counters "$COUNTERS" --hz "$HZ" --batch "$BATCH" \
    --sweep-every "$SWEEP_EVERY" \
    --seconds "$((DURATION + 5))" > "$LOG" 2>&1 &
launcher=$!

# The agent runs under sudo, so the pid to watch is the child of the launcher and not the
# launcher itself. Waiting for the socket rather than sleeping a fixed time also means the
# first sample is taken after the map is loaded and sized, never during it.
pid=""
for _ in $(seq 1 100); do
    pid=$(pgrep -x -P "$launcher" carapaced 2>/dev/null | head -1)
    [ -n "$pid" ] && [ -S "$SOCKET" ] && break
    sleep 0.2
done
[ -n "$pid" ] || { cat "$LOG" >&2; die "the agent never started"; }
# The agent prints the cadence it was actually given. Checked rather than trusted: a
# missing flag in the line above would leave every configuration measuring the same
# thing, and three identical numbers look like a flat curve rather than like a bug.
grep -qE "full sweep every $SWEEP_EVERY ticks, +$SLOT_READS slot reads" "$LOG" \
    || { cat "$LOG" >&2; die "the agent did not take --sweep-every $SWEEP_EVERY"; }
[ -S "$SOCKET" ] || { cat "$LOG" >&2; die "the agent never opened its control socket"; }

cpu_ticks() {
    # utime is field 14 and stime is field 15 of /proc/<pid>/stat. The command name in
    # field 2 can contain spaces, so everything is counted after the closing bracket.
    awk '{ n = index($0, ") "); $0 = substr($0, n + 2); print $12 + $13 }' "/proc/$1/stat"
}

start_ticks=$(cpu_ticks "$pid")
start_ns=$(date +%s%N)
[ -n "$start_ticks" ] || die "cannot read the CPU time of pid $pid"

sleep "$SETTLE"
rss_settled=$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status")
sleep "$((DURATION - SETTLE))"

end_ticks=$(cpu_ticks "$pid")
end_ns=$(date +%s%N)
rss_end=$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status")
status=$(printf 'status\n' | timeout 5 socat - "UNIX-CONNECT:$SOCKET" 2>/dev/null \
         || printf 'status\n' | timeout 5 nc -U "$SOCKET" 2>/dev/null)

wait "$launcher" 2>/dev/null

for value in "$end_ticks" "$rss_end" "$rss_settled"; do
    case $value in
        ''|*[!0-9]*) die "a reading came back empty or non-numeric ('$value'); refusing to compute a ratio from it" ;;
    esac
done

read -r elapsed_s cpu_s percent_core <<EOF
$(awk -v a="$start_ticks" -v b="$end_ticks" -v t="$TICKS_PER_S" \
      -v s="$start_ns" -v e="$end_ns" '
  BEGIN {
      wall = (e - s) / 1e9;
      cpu  = (b - a) / t;
      # Parenthesised: awk reads an unparenthesised > inside printf as a redirection,
      # prints nothing, and the empty value passes a later comparison silently.
      printf "%.3f %.4f %.4f\n", wall, cpu, (wall > 0 ? 100 * cpu / wall : -1);
  }')
EOF
[ -n "$percent_core" ] || die "the CPU ratio came out empty"

sweeps=$(printf '%s' "$status" | awk -F'[:,]' '/"full_sweeps"/ { gsub(/[^0-9]/, "", $2); print $2 }')
: "${sweeps:=unknown}"

json=$OUT/agent-cpu-$STAMP.json
cat > "$json" <<EOF
{
  "stamp": "$STAMP",
  "kernel": "$(uname -r)",
  "online_cpus": $CPUS,
  "possible_cpus": "$POSSIBLE",
  "counter_slots": $COUNTERS,
  "hz": $HZ,
  "batch": $BATCH,
  "sweep_every_ticks": $SWEEP_EVERY,
  "slot_reads_per_second": $SLOT_READS,
  "cpu_budget_percent": $CPU_BUDGET,
  "rss_max_kib": $RSS_MAX,
  "duration_s": $elapsed_s,
  "cpu_seconds": $cpu_s,
  "percent_of_one_core": $percent_core,
  "full_sweeps_reported": "$sweeps",
  "rss_kib_after_settle_s": $rss_settled,
  "settle_s": $SETTLE,
  "rss_kib_at_end": $rss_end
}
EOF

csv=$OUT/agent-cpu.csv
[ -f "$csv" ] || echo "stamp,kernel,counter_slots,hz,batch,sweep_every,slot_reads_per_s,duration_s,cpu_seconds,percent_of_one_core,rss_kib" > "$csv"
echo "$STAMP,$(uname -r),$COUNTERS,$HZ,$BATCH,$SWEEP_EVERY,$SLOT_READS,$elapsed_s,$cpu_s,$percent_core,$rss_end" >> "$csv"

printf '%s counter slots at %s Hz, full sweep every %s ticks, %s slot reads/s, over %s s on %s\n' \
    "$COUNTERS" "$HZ" "$SWEEP_EVERY" "$SLOT_READS" "$elapsed_s" "$(uname -r)"
printf 'CPU  %s s of one core, %s %% of one core\n' "$cpu_s" "$percent_core"
printf 'RSS  %s KiB after %s s of settling, %s KiB at the end\n' "$rss_settled" "$SETTLE" "$rss_end"
printf '%s\n' "$json"

# The two criteria, and it is the script that says so rather than a reader eyeballing a
# number. Exit 3, not 1: the measurement succeeded and a target was missed, and those are
# different outcomes.
missed=0
awk -v p="$percent_core" -v b="$CPU_BUDGET" 'BEGIN { exit (p < b) ? 0 : 1 }' \
    && printf 'ok    CPU %s %% of one core, under %s %%\n' "$percent_core" "$CPU_BUDGET" \
    || { printf 'OVER  CPU %s %% of one core, against a budget of %s %%\n' \
                "$percent_core" "$CPU_BUDGET"; missed=1; }

# RSS is compared at the settled reading, not at the peak. jemalloc gives back 90 % of a
# peak in about 8.8 s on this hardware, measured, so an earlier reading measures the
# allocator holding pages and would fail a perfectly healthy agent.
if [ "$rss_settled" -lt "$RSS_MAX" ]; then
    printf 'ok    RSS %s KiB after %s s, under %s KiB\n' "$rss_settled" "$SETTLE" "$RSS_MAX"
else
    printf 'OVER  RSS %s KiB after %s s, against a ceiling of %s KiB\n' \
        "$rss_settled" "$SETTLE" "$RSS_MAX"
    missed=1
fi

[ "$missed" -eq 0 ] || exit 3
