#!/usr/bin/env bash
# What the agent costs when nothing is happening, and whether it gives back what an
# incident made it take.
#
#   measure-invisibility.sh [--duration S] [--out DIR] [--role smoke|campaign]
#                           [--agent PATH] [--object PATH] [--profiles PATH]
#                           [--counters N] [--hz N] [--batch N] [--sweep-every N]
#                           [--settle S] [--metrics-addr ADDR] [--scrape-hz N]
#                           [--budget-hz N] [--observability-budget PCT]
#
# **Every figure here may be published as a nanosecond or as a percentage, unlike the
# packet path.** Nothing on this path goes through the `duration` field of
# `BPF_PROG_TEST_RUN`, which measure-stage-cost.sh had to correct by 2.06 after measuring
# 128 ns of `duration` against 262 ns of task-clock for the same work. What is measured here
# is utime+stime out of /proc/<pid>/stat and Rss out of /proc/<pid>/smaps_rollup: kernel
# accounting of one userspace process, in units the kernel itself keeps. So no correction
# factor applies to any line this script prints, and a reader must not import the one that
# governs the packet-path nanoseconds.
#
# **The machine is part of the number, so the machine is on every line.** `inv.host` and
# `inv.role` come out before anything else. The measurement VM is the only machine whose
# figures are the project's; a run anywhere else is a test of this harness, `--role smoke`
# says so, and the summary repeats it in words.
#
# **Three agent runs, and why it cannot be one.** The tick's allocation count is read off the
# agent's own closing line, and that counter is process-wide: it counts the `String` an
# exposition renders as readily as anything the tick did. So an agent that is scraped cannot
# answer for the tick, and the two quiet arms exist for that one reading. The observed arm
# carries the rest: at-rest CPU, CPU under a scrape load, the RSS points, and the scrape cost
# as the difference between two phases of the *same* process -- same map, same buffers, same
# page tables, so the difference is the scrape and nothing else. Two processes compared
# against each other would have carried two startups.
#
# **Both verdicts are two-point, and that is the whole worth of them.** One reading cannot
# tell a constant from a slope, and both criteria here fail that way in opposite directions.
# The RSS: measured at 422 scrapes, the agent kept 20 KiB it never gave back -- the
# exposition's output buffer growing once, exactly as crates/loricad/src/main.rs says it
# does, and not a leak. A single before/after pair calls that "retained" and fails a healthy
# agent. The allocations: the agent reported the same 6 after the first sweep over 201, 401
# and 801 ticks, so a single run above zero reads as "the tick allocates" when nothing in
# the tick does. So the load runs twice and the verdict is about the *second* retention, and
# the quiet agent runs twice at two lengths and the verdict is whether the count moved.
#
# The probe scrape happens before the rest baseline is taken, so the exposition buffer is
# already grown when `inv.rss_kib_rest` is read and what the two rounds then compare is only
# what scales with load. That is deliberate: what scales with load is the leak.
#
# **The ventilation is `Anonymous` against `Rss - Anonymous`, because there is no `File`
# line.** /proc/<pid>/smaps_rollup carries `Rss Pss Pss_Dirty Pss_Anon Pss_File
# Shared_Clean …`; `Pss_File` is a proportional share and not an RSS, and a measurement that
# grepped for `File:` would find nothing and report a zero. `Private_Dirty` is on every line
# as well: that is the part the agent actually owns, and the part a budget is about.
#
# **What the scrape cost is normalised to, and why.** The load phase scrapes at *at most*
# `--scrape-hz` -- the cap exists so a long campaign cannot exhaust the ephemeral range
# through TIME_WAIT, and the rate a bash loop actually reaches is well under it and is
# published as `inv.scrape_rate_hz`; 28 a second measured here against a cap of 200. The
# rate is high on purpose because the per-scrape cost has to clear the instrument: one
# CLK_TCK tick over one phase is printed as
# `inv.cpu_quantum_percent_core`, and a delta under it is reported as unresolvable rather
# than divided. The published cost is then that per-scrape figure at `--budget-hz`, one
# scrape a second by default — the same cadence as the journal rollup, so the two halves of
# observability are quoted at the same rate.
#
# **The journal rollup is a parameter and not a measurement here, and the reason is in the
# code.** crates/loricad/src/log/mod.rs installs one subscriber at a fixed level with no
# `EnvFilter`, and the agent exposes no flag for it, so there is no arm without the rollup
# to subtract. What this script can do is prove it ran and bound it: it counts the aggregate
# lines and reads back the agent's own `lines=` field, and the at-rest CPU it publishes
# already contains the rollup. Isolating it needs a build the agent does not have.
#
# **The result file is written last and holds exactly the lines that went to stdout.** Every
# value goes through `emit`, which refuses an empty or non-numeric reading instead of
# comparing it; the file is rendered from the same array at the end. Two renderings of the
# same run is how a green file starts disagreeing with a green terminal, and a harness that
# can produce a file without having measured invalidates every file it ever produced -- this
# tree has been there twice on a full disk.
#
# **Nothing lands under /tmp.** It is tmpfs here, and a page or an RSS figure taken against
# a tmpfs-backed file is not the figure it claims to be: store/blocklist measured the same
# 76 MiB list reporting +79 600 KiB of `Private_Dirty` there against +8 on a real
# filesystem. The agent log and the result file go under --out, inside the checkout.
#
# No `perf` anywhere. `perf stat --output <file>` returns Permission denied on this guest
# even as root, and the two counters this script needs are in /proc.

set -uo pipefail

# Unlike measure-agent-cpu.sh this one does cd to the root of the checkout: it reads the
# memlock budgets out of the policy source rather than restating them, and it builds what it
# was not handed. Both need the tree.
cd "$(dirname "$0")/../.." || exit 1

DURATION=3600
OUT=bench/results/invisibility
ROLE=smoke
AGENT=""
OBJECT=""
PROFILES=crates/lorica-policy/src/profile.rs
# The agent configuration measure-agent-cpu.sh states its CPU criterion at. Same numbers on
# purpose: an invisibility figure that came from a different map size could not be read next
# to the one that phase published.
COUNTERS=50000
HZ=10
BATCH=1000
SWEEP_EVERY=1
SETTLE=15
# Not the agent's own default port, so this harness cannot collide with something already
# listening there and report the wrong process.
METRICS_ADDR=127.0.0.1:9137
SCRAPE_HZ=200
BUDGET_HZ=1
OBSERVABILITY_BUDGET=0.15

while [ $# -gt 0 ]; do
    case $1 in
        --duration)   DURATION=$2; shift 2 ;;
        --out)        OUT=$2; shift 2 ;;
        --role)       ROLE=$2; shift 2 ;;
        --agent)      AGENT=$2; shift 2 ;;
        --object)     OBJECT=$2; shift 2 ;;
        --profiles)   PROFILES=$2; shift 2 ;;
        --counters)   COUNTERS=$2; shift 2 ;;
        --hz)         HZ=$2; shift 2 ;;
        --batch)      BATCH=$2; shift 2 ;;
        --sweep-every) SWEEP_EVERY=$2; shift 2 ;;
        --settle)     SETTLE=$2; shift 2 ;;
        --metrics-addr) METRICS_ADDR=$2; shift 2 ;;
        --scrape-hz)  SCRAPE_HZ=$2; shift 2 ;;
        --budget-hz)  BUDGET_HZ=$2; shift 2 ;;
        --observability-budget) OBSERVABILITY_BUDGET=$2; shift 2 ;;
        -h|--help)    sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

PIDS=()
cleanup() {
    [ "${#PIDS[@]}" -gt 0 ] || return 0
    for launcher in "${PIDS[@]}"; do
        # Both under sudo: the launcher is sudo itself and its child is root, so an
        # unprivileged kill would report success against neither.
        sudo -n pkill -x -P "$launcher" loricad 2>/dev/null
        sudo -n kill "$launcher" 2>/dev/null
    done
    return 0
}
trap cleanup EXIT

case $ROLE in
    smoke|campaign) ;;
    *) die "--role is smoke or campaign, got '$ROLE'; the role is what tells a reader whether these are project figures" ;;
esac

# The whole span is two settles and six phases: settle, rest, load, recovery, load, recovery
# on the observed agent, then settle and one quiet phase on the second.
PHASE=$(( (DURATION - 2 * SETTLE) / 6 ))
TICKS_PER_S=$(getconf CLK_TCK)
case $TICKS_PER_S in
    ''|*[!0-9]*) die "getconf CLK_TCK said '$TICKS_PER_S', so no CPU time can be converted" ;;
esac
PAGE_BYTES=$(getconf PAGESIZE)
case $PAGE_BYTES in
    ''|*[!0-9]*) die "getconf PAGESIZE said '$PAGE_BYTES', so no RSS difference can be judged against a page" ;;
esac
PAGE_KIB=$((PAGE_BYTES / 1024))

# One CLK_TCK tick spread over one phase, as a percentage of one core. This is the finest
# CPU difference the instrument can express, and the budget verdict is only as good as it.
QUANTUM=$(awk -v t="$TICKS_PER_S" -v p="$PHASE" 'BEGIN {
    if (t > 0 && p > 0) { printf "%.4f\n", 100 / (t * p) }
}')
[ -n "$QUANTUM" ] || die "the CPU quantum came out empty, so no CPU difference here can be qualified"

# Ten seconds is the floor because one tick over a shorter phase is already 0.1 % of a core,
# which is most of the budget being verified. Between the floor and roughly a hundred seconds
# the verdict is coarse and the script says so per run; the campaign duration is what makes
# it fine.
[ "$PHASE" -ge 10 ] \
    || die "--duration $DURATION with --settle $SETTLE leaves ${PHASE} s per phase, under the 10 s below which one CLK_TCK tick is 0.1 % of a core"

[ -n "${EPOCHSECONDS:-}" ] \
    || die "this bash has no EPOCHSECONDS, and the scrape loop must not fork a clock per iteration"

sudo -n true 2>/dev/null \
    || die "loading a BPF program needs CAP_BPF, and sudo asks for a password"

# ---------------------------------------------------------------------------
# The memlock budgets, read out of the policy source and never restated
# ---------------------------------------------------------------------------
#
# One arm of one match, per profile, times whatever MIB is defined as in the same file. This
# tree has shipped a script carrying a hardcoded 18 for a CounterId::COUNT of 34, with a
# comment claiming it was checked, so a budget written down here would go stale in silence
# and a budget read here goes stale loudly.
[ -r "$PROFILES" ] \
    || die "cannot read the profile source at '$PROFILES'; the memlock budgets are read from it, not restated here"
BUDGETS=$(awk '
    /const MIB/ {
        c = $0; sub(/.*=/, "", c); sub(/;.*/, "", c); gsub(/_/, "", c);
        k = split(c, p, /[^0-9]+/); mib = 1; got = 0;
        for (i = 1; i <= k; i++) { if (p[i] != "") { mib *= p[i]; got = 1 } }
        if (!got) { mib = 0 }
    }
    /fn memlock_budget/ { inside = 1; next }
    inside && /fn / { inside = 0 }
    inside && /Self::/ {
        name = $0; sub(/.*Self::/, "", name); sub(/[^A-Za-z0-9_].*/, "", name);
        rhs = $0; sub(/.*=>/, "", rhs); sub(/,.*/, "", rhs); gsub(/_/, "", rhs);
        unit = 1;
        if (rhs ~ /MIB/) { unit = mib }
        k = split(rhs, p, /[^0-9]+/); v = 1; got = 0;
        for (i = 1; i <= k; i++) { if (p[i] != "") { v *= p[i]; got = 1 } }
        if (!got || unit == 0) { exit 2 }
        printf "%s %d\n", tolower(name), v * unit;
        n++
    }
    END { if (!n) { exit 3 } }
' "$PROFILES")
[ -n "$BUDGETS" ] \
    || die "no memlock budget could be read out of $PROFILES; refusing to publish a budget line rather than print a zero"

# ---------------------------------------------------------------------------
# What is measured, and building it when it was not handed over
# ---------------------------------------------------------------------------
#
# The measurement VM has no toolchain, which is why both paths are flags. On a machine that
# does have one, an absent binary is built rather than refused, and the shipping object is
# the one built: the instrumented object adds a map write per counted call, so a tick cost
# read off it would be measuring the instrumentation.
[ -n "$AGENT" ] || AGENT=target/release/loricad
if [ ! -x "$AGENT" ] && command -v cargo > /dev/null 2>&1; then
    cargo build --release -p loricad || die "building loricad failed"
fi
[ -x "$AGENT" ] \
    || die "no executable agent at '$AGENT' and no cargo here to build one; pass --agent with a binary that travelled"

if [ -z "$OBJECT" ]; then
    # Sourced, so tested for readability and not for an execute bit: a Windows checkout does
    # not carry one, and this file is never run as a command.
    [ -r scripts/lab/build-ebpf.sh ] \
        || die "scripts/lab/build-ebpf.sh is not readable, and it is sourced to name the eBPF object"
    # shellcheck source=scripts/lab/build-ebpf.sh
    . scripts/lab/build-ebpf.sh
    build_ebpf "" || die "the eBPF build failed"
    OBJECT=$EBPF_PLAIN_OBJ
fi
[ -f "$OBJECT" ] || die "--object must point at the eBPF object, got '$OBJECT'"

mkdir -p "$OUT" || die "cannot create $OUT"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
HOST=$(uname -n)
KERNEL=$(uname -r)
CPUS=$(nproc)
SOCKET_BASE=/run/lorica/measure-inv-$$

# ---------------------------------------------------------------------------
# Readings
# ---------------------------------------------------------------------------

cpu_ticks() {
    # utime is field 14 and stime field 15 of /proc/<pid>/stat. The command name in field 2
    # can hold spaces, so everything is counted from after the closing bracket.
    awk '{ n = index($0, ") "); $0 = substr($0, n + 2); print $12 + $13 }' "/proc/$1/stat"
}

resident() {
    # Rss, Anonymous and Private_Dirty out of smaps_rollup, in KiB. Read under sudo because
    # the agent runs as root and this file is not world-readable, and printed as one line so
    # the three come from one read of one process at one instant. A missing line exits
    # non-zero rather than defaulting: a budget compared against a silent zero passes for
    # every process that ever ran.
    sudo -n awk '
        /^Rss:/           { rss = $2 }
        /^Anonymous:/     { anon = $2 }
        /^Private_Dirty:/ { dirty = $2 }
        END {
            if (rss == "" || anon == "" || dirty == "") { exit 1 }
            printf "%s %s %s\n", rss, anon, dirty
        }
    ' "/proc/$1/smaps_rollup"
}

seen() {
    local count
    count=$(grep -cF "$1" "$2" 2>/dev/null)
    [ "${count:-0}" -gt 0 ]
}

# Reads the file, never `agent | grep -q`: grep -q exits at the first match, the writer dies
# of SIGPIPE, and under `set -o pipefail` the whole condition comes back 141 while the
# pattern was in fact there.
digits_after() {
    grep -o "$1" "$2" | tail -1 | tr -dc "0-9"
}

AGENT_PID=""
LAUNCHER=""
ARM=0
start_agent() {
    local metrics=$1 seconds=$2 log=$3
    ARM=$((ARM + 1))
    sudo -n "$AGENT" --object "$OBJECT" --socket "$SOCKET_BASE-$ARM.sock" \
        --counters "$COUNTERS" --hz "$HZ" --batch "$BATCH" \
        --sweep-every "$SWEEP_EVERY" --metrics "$metrics" \
        --seconds "$seconds" > "$log" 2>&1 &
    LAUNCHER=$!
    PIDS+=("$LAUNCHER")

    # The pid to watch is the child of sudo, not sudo. Waiting for the startup line rather
    # than sleeping also puts the load of the program and the sizing of the map behind the
    # first sample, where they belong: they happen once and charging them to a run would make
    # a long one look cheaper than a short one on the same code.
    AGENT_PID=""
    local attempt
    for attempt in $(seq 1 200); do
        AGENT_PID=$(pgrep -x -P "$LAUNCHER" loricad 2>/dev/null | head -1)
        if [ -n "$AGENT_PID" ] && seen "counter slots, batch" "$log"; then
            break
        fi
        sleep 0.2
    done
    [ -n "$AGENT_PID" ] || { cat "$log" >&2; die "the agent never started; its output is above"; }
    seen "counter slots, batch" "$log" \
        || { cat "$log" >&2; die "the agent never printed its startup line, so what it was configured with is unknown"; }

    # Each flag checked against its own echo, not against one number derived from all of
    # them: a flag that did not arrive would otherwise leave every arm measuring the same
    # thing, and two equal numbers look like a flat result rather than like a bug.
    seen "$COUNTERS counter slots" "$log" || { cat "$log" >&2; die "the agent did not take --counters $COUNTERS"; }
    seen "batch $BATCH" "$log" || { cat "$log" >&2; die "the agent did not take --batch $BATCH"; }
    seen "$HZ Hz" "$log" || { cat "$log" >&2; die "the agent did not take --hz $HZ"; }
    seen "full sweep every $SWEEP_EVERY ticks," "$log" || { cat "$log" >&2; die "the agent did not take --sweep-every $SWEEP_EVERY"; }
}

# ---------------------------------------------------------------------------
# The scrape load
# ---------------------------------------------------------------------------
#
# bash's own net redirection, so there is no curl to be absent on a measured machine and no
# process forked per request. The request is `GET /metrics` and a bare newline: the endpoint
# reads once and compares a prefix, so a CRLF would be two bytes it never looks at. The whole
# body is read before the socket closes, because a scraper that walks away early makes the
# agent do less work than the one being measured.

SCRAPE_SLEEP=$(awk -v hz="$SCRAPE_HZ" 'BEGIN { if (hz > 0) { printf "%.5f\n", 1 / hz } }')
[ -n "$SCRAPE_SLEEP" ] || die "--scrape-hz $SCRAPE_HZ gives no interval to wait between scrapes"

scrape_once() {
    local host=${1%:*} port=${1##*:} first=""
    exec 3<>"/dev/tcp/$host/$port" || return 1
    printf 'GET /metrics HTTP/1.0\n\n' >&3 || { exec 3<&- 3>&-; return 1; }
    IFS= read -r -t 5 first <&3
    while IFS= read -r -t 5 _ <&3; do :; done
    exec 3<&- 3>&-
    printf '%s' "$first"
}

flood() {
    local end=$2 host=${1%:*} port=${1##*:} ok=0 bad=0
    while [ "$EPOCHSECONDS" -lt "$end" ]; do
        if exec 3<>"/dev/tcp/$host/$port" 2>/dev/null; then
            printf 'GET /metrics HTTP/1.0\n\n' >&3 2>/dev/null
            while IFS= read -r -t 5 _ <&3; do :; done
            exec 3<&- 3>&-
            ok=$((ok + 1))
        else
            bad=$((bad + 1))
        fi
        sleep "$SCRAPE_SLEEP"
    done
    printf '%s %s\n' "$ok" "$bad"
}

# ---------------------------------------------------------------------------
# The observed arm: rest, then load and recovery twice
# ---------------------------------------------------------------------------

SPAN=$((SETTLE + 5 * PHASE))
OBSERVED_LOG=$OUT/invisibility-observed-$STAMP.log
start_agent "$METRICS_ADDR" "$((SPAN + 5))" "$OBSERVED_LOG"
observed_pid=$AGENT_PID
observed_launcher=$LAUNCHER

SLOT_READS=$(digits_after "ticks, *[0-9]* slot reads" "$OBSERVED_LOG")
case $SLOT_READS in
    ''|*[!0-9]*) cat "$OBSERVED_LOG" >&2; die "the agent did not state its slot reads per second" ;;
esac

# One scrape before anything is timed, so a load phase cannot count thousands of refused
# connections as a load. The status line is checked rather than the body: the exposition is
# what the endpoint's own tests are about, and what this needs to know is that it answered.
probe=$(scrape_once "$METRICS_ADDR") \
    || die "cannot reach /metrics at $METRICS_ADDR, so the scrape cost cannot be measured"
case $probe in
    *200*) ;;
    *) die "the first scrape of $METRICS_ADDR answered '$probe' instead of a 200, so the load phase would measure refusals" ;;
esac

sleep "$SETTLE"
t0_ticks=$(cpu_ticks "$observed_pid"); t0_ns=$(date +%s%N)

sleep "$PHASE"
rest_ticks=$(cpu_ticks "$observed_pid"); rest_ns=$(date +%s%N)
read -r rss_rest anon_rest dirty_rest <<EOF
$(resident "$observed_pid")
EOF

# Two identical rounds of load and recovery. The recovery window is one phase with no scraper
# attached, and it is printed with the figure it produced: an RSS read the instant the load
# stopped reports the allocator holding pages rather than the agent needing them.
scrapes=(); scrape_failures=()
load_ticks=(); load_ns=(); rss_load=(); anon_load=(); dirty_load=()
after_ticks=(); after_ns=(); rss_after=(); anon_after=(); dirty_after=()
for round in 0 1; do
    load_end=$((EPOCHSECONDS + PHASE))
    read -r ok bad <<EOF
$(flood "$METRICS_ADDR" "$load_end")
EOF
    now=$EPOCHSECONDS
    [ "$now" -lt "$load_end" ] && sleep "$((load_end - now))"
    scrapes+=("$ok"); scrape_failures+=("$bad")
    load_ticks+=("$(cpu_ticks "$observed_pid")"); load_ns+=("$(date +%s%N)")
    read -r r a d <<EOF
$(resident "$observed_pid")
EOF
    rss_load+=("$r"); anon_load+=("$a"); dirty_load+=("$d")

    sleep "$PHASE"
    after_ticks+=("$(cpu_ticks "$observed_pid")"); after_ns+=("$(date +%s%N)")
    read -r r a d <<EOF
$(resident "$observed_pid")
EOF
    rss_after+=("$r"); anon_after+=("$a"); dirty_after+=("$d")
done

digest_lines=$(grep -cF digest "$OBSERVED_LOG")
rollup_lines=$(digits_after "lines=[0-9]*" "$OBSERVED_LOG")
wait "$observed_launcher" 2>/dev/null
observed_allocations=$(digits_after "[0-9]* allocations after the first sweep" "$OBSERVED_LOG")

# ---------------------------------------------------------------------------
# The quiet arm: the tick's own allocation count
# ---------------------------------------------------------------------------

QUIET_LOG=$OUT/invisibility-quiet-$STAMP.log
start_agent off "$((SETTLE + PHASE + 5))" "$QUIET_LOG"
quiet_pid=$AGENT_PID
quiet_launcher=$LAUNCHER

sleep "$SETTLE"
q0_ticks=$(cpu_ticks "$quiet_pid"); q0_ns=$(date +%s%N)
sleep "$PHASE"
q1_ticks=$(cpu_ticks "$quiet_pid"); q1_ns=$(date +%s%N)
read -r rss_quiet anon_quiet dirty_quiet <<EOF
$(resident "$quiet_pid")
EOF
wait "$quiet_launcher" 2>/dev/null

quiet_digest_lines=$(grep -cF digest "$QUIET_LOG")
tick_allocations=$(digits_after "[0-9]* allocations after the first sweep" "$QUIET_LOG")
reallocations=$(digits_after "[0-9]* snapshot buffers reallocated" "$QUIET_LOG")
quiet_ticks_done=$(digits_after "loricad: [0-9]* ticks," "$QUIET_LOG")
quiet_failures=$(digits_after "[0-9]* failed," "$QUIET_LOG")

# A second quiet arm, short and fixed, for the same reason the load is run twice: one figure
# cannot tell a constant from a slope. The agent's counter is "allocations after the first
# sweep" and it is a total, so an agent that allocated once at the end of startup and an
# agent that allocates every tick both report a number above zero -- measured here at 6
# against 201, 401 and 801 ticks, the same 6 every time. Twenty seconds is enough lever
# against a phase of at least ten, and it is fixed rather than derived so the short arm costs
# a campaign the same twenty seconds it costs a smoke run.
ALLOC_PROBE_S=20
SHORT_LOG=$OUT/invisibility-short-$STAMP.log
start_agent off "$ALLOC_PROBE_S" "$SHORT_LOG"
wait "$LAUNCHER" 2>/dev/null
short_allocations=$(digits_after "[0-9]* allocations after the first sweep" "$SHORT_LOG")
short_ticks=$(digits_after "loricad: [0-9]* ticks," "$SHORT_LOG")

# ---------------------------------------------------------------------------
# Nothing above may be compared until it is known to be a number
# ---------------------------------------------------------------------------

LINES=()
emit() {
    case $2 in
        '') die "no value was read for $1; refusing to publish a line rather than default it to zero" ;;
    esac
    LINES+=("$1=$2")
}
emit_num() {
    case $2 in
        ''|*[!0-9.-]*) die "$1 came back as '$2', which is not a number; refusing to compare it" ;;
    esac
    LINES+=("$1=$2")
}

percent() {
    # (end - start) ticks over (end - start) wall, as a percentage of one core. The ternary
    # is parenthesised: awk reads a bare > inside printf as a redirection into a file called
    # 0, prints nothing at all, and the empty result then passes any later comparison.
    awk -v a="$1" -v b="$2" -v s="$3" -v e="$4" -v t="$TICKS_PER_S" 'BEGIN {
        wall = (e - s) / 1e9;
        cpu = (b - a) / t;
        if (wall > 0) { printf "%.4f\n", 100 * cpu / wall }
    }'
}

cpu_rest=$(percent "$t0_ticks" "$rest_ticks" "$t0_ns" "$rest_ns")
cpu_load1=$(percent "$rest_ticks" "${load_ticks[0]}" "$rest_ns" "${load_ns[0]}")
cpu_after1=$(percent "${load_ticks[0]}" "${after_ticks[0]}" "${load_ns[0]}" "${after_ns[0]}")
cpu_load2=$(percent "${after_ticks[0]}" "${load_ticks[1]}" "${after_ns[0]}" "${load_ns[1]}")
cpu_after2=$(percent "${load_ticks[1]}" "${after_ticks[1]}" "${load_ns[1]}" "${after_ns[1]}")
cpu_quiet=$(percent "$q0_ticks" "$q1_ticks" "$q0_ns" "$q1_ns")

emit inv.host "$HOST"
emit inv.role "$ROLE"
emit inv.kernel "$KERNEL"
emit_num inv.online_cpus "$CPUS"
emit_num inv.clk_tck "$TICKS_PER_S"
emit_num inv.page_kib "$PAGE_KIB"
emit_num inv.duration_s "$DURATION"
emit_num inv.settle_s "$SETTLE"
emit_num inv.phase_s "$PHASE"
emit_num inv.cpu_quantum_percent_core "$QUANTUM"
emit_num inv.counter_slots "$COUNTERS"
emit_num inv.hz "$HZ"
emit_num inv.batch "$BATCH"
emit_num inv.sweep_every "$SWEEP_EVERY"
emit_num inv.slot_reads_per_s "$SLOT_READS"

emit_num inv.cpu_percent_core_rest "$cpu_rest"
emit_num inv.cpu_percent_core_load "$cpu_load1"
emit_num inv.cpu_percent_core_recovered "$cpu_after1"
emit_num inv.cpu_percent_core_load_repeat "$cpu_load2"
emit_num inv.cpu_percent_core_recovered_repeat "$cpu_after2"
emit_num inv.cpu_percent_core_quiet "$cpu_quiet"

emit_num inv.rss_kib_rest "$rss_rest"
emit_num inv.rss_anonymous_kib_rest "$anon_rest"
emit_num inv.rss_file_backed_kib_rest "$((rss_rest - anon_rest))"
emit_num inv.rss_private_dirty_kib_rest "$dirty_rest"
for round in 0 1; do
    suffix=""
    [ "$round" -eq 1 ] && suffix=_repeat
    emit_num "inv.rss_kib_load$suffix" "${rss_load[$round]}"
    emit_num "inv.rss_anonymous_kib_load$suffix" "${anon_load[$round]}"
    emit_num "inv.rss_file_backed_kib_load$suffix" "$(( ${rss_load[$round]} - ${anon_load[$round]} ))"
    emit_num "inv.rss_private_dirty_kib_load$suffix" "${dirty_load[$round]}"
    emit_num "inv.rss_kib_after$suffix" "${rss_after[$round]}"
    emit_num "inv.rss_anonymous_kib_after$suffix" "${anon_after[$round]}"
    emit_num "inv.rss_file_backed_kib_after$suffix" "$(( ${rss_after[$round]} - ${anon_after[$round]} ))"
    emit_num "inv.rss_private_dirty_kib_after$suffix" "${dirty_after[$round]}"
done
emit_num inv.rss_kib_quiet "$rss_quiet"
emit_num inv.rss_anonymous_kib_quiet "$anon_quiet"
emit_num inv.rss_file_backed_kib_quiet "$((rss_quiet - anon_quiet))"

emit_num inv.scrapes "${scrapes[0]}"
emit_num inv.scrapes_repeat "${scrapes[1]}"
emit_num inv.scrape_failures "${scrape_failures[0]}"
emit_num inv.scrape_failures_repeat "${scrape_failures[1]}"
[ "${scrapes[0]}" -gt 0 ] && [ "${scrapes[1]}" -gt 0 ] \
    || die "a load phase completed no scrape, so there is no observability cost to divide and no second retention to compare"
scrape_rate=$(awk -v n="${scrapes[0]}" -v p="$PHASE" 'BEGIN { if (p > 0) { printf "%.2f\n", n / p } }')
emit_num inv.scrape_rate_hz "$scrape_rate"

# The cost of the load phase against the rest phase of the same process, and then per scrape.
# Reported as unresolvable rather than divided when it does not clear one CLK_TCK tick: a
# per-scrape microsecond figure derived from a difference smaller than the instrument is a
# number about the instrument. The second round is published beside the first rather than
# averaged into it, because two figures show a reader the spread and a mean hides it.
scrape_delta=$(awk -v a="$cpu_load1" -v b="$cpu_rest" 'BEGIN { printf "%.4f\n", a - b }')
scrape_delta2=$(awk -v a="$cpu_load2" -v b="$cpu_after1" 'BEGIN { printf "%.4f\n", a - b }')
emit_num inv.scrape_load_delta_percent_core "$scrape_delta"
emit_num inv.scrape_load_delta_percent_core_repeat "$scrape_delta2"
if awk -v d="$scrape_delta" -v q="$QUANTUM" 'BEGIN { if (d > q) { exit 0 } exit 1 }'; then
    scrape_us=$(awk -v d="$scrape_delta" -v p="$PHASE" -v n="${scrapes[0]}" 'BEGIN {
        if (n > 0) { printf "%.2f\n", d / 100 * p / n * 1e6 }
    }')
    emit_num inv.scrape_cpu_us_per_scrape "$scrape_us"
    observability=$(awk -v u="$scrape_us" -v hz="$BUDGET_HZ" 'BEGIN { printf "%.4f\n", u * hz * 1e-4 }')
    emit_num inv.observability_percent_core_at_budget_hz "$observability"
    emit_num inv.observability_budget_hz "$BUDGET_HZ"
    emit_num inv.observability_budget_percent_core "$OBSERVABILITY_BUDGET"
    if awk -v o="$observability" -v b="$OBSERVABILITY_BUDGET" 'BEGIN { if (o < b) { exit 0 } exit 1 }'; then
        emit inv.observability_verdict under
    else
        emit inv.observability_verdict over
    fi
else
    emit inv.scrape_cpu_us_per_scrape unresolved
    emit inv.observability_percent_core_at_budget_hz unresolved
    emit_num inv.observability_budget_hz "$BUDGET_HZ"
    emit_num inv.observability_budget_percent_core "$OBSERVABILITY_BUDGET"
    emit inv.observability_verdict below-quantum
fi

# The rollup ran, proven rather than assumed, and its own count read back off its own line.
[ "$digest_lines" -gt 0 ] \
    || die "the agent wrote no aggregate line, so the rollup half of observability was never exercised"
emit_num inv.rollup_aggregate_lines "$digest_lines"
emit_num inv.rollup_lines_reported "$rollup_lines"
emit_num inv.rollup_aggregate_lines_quiet "$quiet_digest_lines"
emit inv.rollup_percent_core inseparable-no-flag

# The agent's own figure, read back and never recounted. It covers the whole tick and not
# only the sweep -- the counter is process-wide, and the quiet arm is what makes the tick the
# only thing that ran. The sweep's own zero is proven elsewhere, by tests/no_alloc_in_tick.rs
# over a thousand sweeps.
emit_num inv.tick_allocations "$tick_allocations"
emit_num inv.tick_allocations_short "$short_allocations"
emit_num inv.snapshot_reallocations "$reallocations"
emit_num inv.observed_allocations "$observed_allocations"
emit_num inv.quiet_ticks "$quiet_ticks_done"
emit_num inv.quiet_ticks_short "$short_ticks"
emit_num inv.quiet_read_failures "$quiet_failures"

[ "$quiet_ticks_done" -ne "$short_ticks" ] \
    || die "both quiet arms ran $short_ticks ticks, so there is no lever to tell a constant allocation count from a per-tick one"
if [ "$tick_allocations" -eq "$short_allocations" ]; then
    # Equal over two different tick counts: nothing in the tick allocates, whatever the
    # residue after the first sweep is. Zero would be the same statement with no residue.
    alloc_verdict=constant
else
    alloc_verdict=per-tick
fi
emit inv.tick_allocation_verdict "$alloc_verdict"

while read -r profile bytes; do
    emit_num "inv.memlock_budget_bytes.$profile" "$bytes"
done <<EOF
$BUDGETS
EOF

# The verdict that is not a number, and it is about the second retention rather than the
# first. What each load *peaked* at is published above; what decides is what survived the
# recovery window, once per round. A one-time buffer retains on the first round and nothing
# on the second; a leak retains on both, and that is the mode this exists to forbid. One
# page is the resolution of the instrument -- RSS moves in pages, and getconf says how big
# one is here rather than this script assuming it.
peak=$((${rss_load[0]} - rss_rest))
kept1=$((${rss_after[0]} - rss_rest))
kept2=$((${rss_after[1]} - ${rss_after[0]}))
emit_num inv.rss_peak_growth_kib "$peak"
emit_num inv.rss_retained_kib "$kept1"
emit_num inv.rss_retained_kib_repeat "$kept2"
if [ "$kept1" -le "$PAGE_KIB" ] && [ "$kept2" -le "$PAGE_KIB" ]; then
    rss_verdict=flat
elif [ "$kept2" -le "$PAGE_KIB" ]; then
    rss_verdict=ceiling
else
    rss_verdict=growing
fi
emit inv.rss_return_verdict "$rss_verdict"

# ---------------------------------------------------------------------------
# Written last, and from the array that was printed
# ---------------------------------------------------------------------------

printf '%s\n' "${LINES[@]}"

result=$OUT/invisibility-$STAMP.txt
printf '%s\n' "${LINES[@]}" > "$result" || die "cannot write $result"
printf '%s\n' "$result"

if [ "$ROLE" != campaign ]; then
    printf 'NOTE  measured on %s in role %s: these are figures about this harness, not figures of the project\n' \
        "$HOST" "$ROLE"
fi

missed=0
if [ "$alloc_verdict" = constant ]; then
    printf 'ok    %s allocations after the first sweep on %s over %s ticks and the same %s over %s: nothing in the tick allocates\n' \
        "$tick_allocations" "$HOST" "$quiet_ticks_done" "$short_allocations" "$short_ticks"
else
    printf 'OVER  %s allocations over %s ticks against %s over %s on %s: the count follows the tick\n' \
        "$tick_allocations" "$quiet_ticks_done" "$short_allocations" "$short_ticks" "$HOST"
    missed=1
fi
printf 'RSS   on %s: %s KiB at rest, %s under load, %s after %s s, %s under load again, %s after %s s\n' \
    "$HOST" "$rss_rest" "${rss_load[0]}" "${rss_after[0]}" "$PHASE" "${rss_load[1]}" "${rss_after[1]}" "$PHASE"
case $rss_verdict in
    flat)    printf 'ok    neither load left more than a %s KiB page behind on %s\n' "$PAGE_KIB" "$HOST" ;;
    ceiling) printf 'ok    the first load kept %s KiB and the second kept %s on %s: a ceiling, not a leak\n' "$kept1" "$kept2" "$HOST" ;;
    *)       printf 'OVER  RSS kept %s KiB on the first load and %s on the second on %s: retention scales with load\n' "$kept1" "$kept2" "$HOST"; missed=1 ;;
esac
case $(printf '%s' "${LINES[*]}") in
    *inv.observability_verdict=over*) printf 'OVER  observability above %s %% of one core at %s scrape/s on %s\n' "$OBSERVABILITY_BUDGET" "$BUDGET_HZ" "$HOST"; missed=1 ;;
esac

# Exit 3, not 1: the measurement succeeded and a criterion was missed, and those are
# different outcomes for whoever reads the code.
[ "$missed" -eq 0 ] || exit 3
