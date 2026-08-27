#!/usr/bin/env bash
# Where the cycle dispersion comes from: turbo and DVFS, C-states, or the tick and the
# neighbourhood.
#
#   measure-noise.sh [--cpu N] [--reps N] [--campaigns LIST] [--level N]
#                    [--freq-khz N] [--out DIR]
#
# **The problem this exists for.** Four runs of the same unchanged program measured 612.5,
# 619.7, 652.4 and 614.8 cycles per packet -- 6.5 % apart -- while the instruction count
# over the same runs reproduced to 0.11 %. The program is identical, so the 6.5 % is the
# machine. Until it is attributed and reduced, no gain below 6 % can be validated in
# cycles at all, and the cycle ceiling in measure-stage-cost.sh has to carry the whole
# spread as margin rather than as budget.
#
# It is not the virtualisation: the same measurement on bare metal came out worse, 14.2 %.
# What is left is a measurement that wanders on a busy machine -- an unpinned process, a
# frequency that moves, a core that sleeps between runs, a tick that fires in the middle of
# one. This script adds one control at a time and reports what each one buys.
#
# **The three campaigns, cumulative, and the order is not arbitrary.** Frequency first,
# because it contaminates everything after it: a C-state wake-up includes a frequency ramp,
# and a neighbour core in C6 hands turbo budget back to the others.
#
#   0  nothing at all, the bare configuration; CV0 is the reference every delta is against
#   A  taskset + performance governor + no_turbo=1 + scaling_min_freq = scaling_max_freq
#      + the uncore frequency frozen           -> isolates turbo and DVFS
#   B  A + one file descriptor held open on /dev/cpu_dma_latency at 0 for the whole run
#                                              -> isolates the C-states
#   C  B + isolcpus / nohz_full                -> isolates the tick, RCU and the neighbours
#
# Campaign C is written here and refuses to run: `nohz_full` is boot-only and `isolcpus` is
# a boot parameter, so C needs a reboot that this script cannot perform and must not fake.
# It is not in the default list, and asking for it on a kernel whose /proc/cmdline does not
# carry both is a refusal and not a skip -- a harness that quietly drops a campaign is how a
# green verdict comes out of a machine that was never configured.
#
# **Three Haswell-EP facts behind the knobs, none of them optional here.**
#
# The uncore has its own frequency and it is dynamic -- Haswell-EP is the first generation
# where that is true. With the core clock pinned, LLC and DRAM latency keep moving *in core
# cycles*, which lands directly in the number this project publishes. So campaign A also
# freezes the uncore: MSR 0x620 (UNCORE_RATIO_LIMIT, max ratio in bits 0-6, min ratio in
# bits 8-14) written with min = max, or the `intel_uncore_frequency` driver where the kernel
# exposes it. A campaign A without it pins half the clock and reports the other half as
# residue.
#
# `intel_idle.max_cstate=0` is a trap and is deliberately not used: it disables the
# intel_idle driver and falls back to acpi_idle, which can re-expose deep states -- the
# opposite of what it looks like it does. The clean and reversible mechanism is a file
# descriptor held open on /dev/cpu_dma_latency carrying a 0 microsecond target, and its
# restoration is the close: nothing to put back, nothing to forget to put back.
#
# C6 exit latency on Haswell is 133 microseconds, with L1, L2 and the TLB lost. A
# `BPF_PROG_TEST_RUN` with repeat = 1e6 is barely sensitive to it -- paid once, amortised
# over a million packets -- but a one-shot measurement taken after the core has been idle
# pays all of it, which is exactly the shape of a harness that runs one level at a time.
#
# **Why the runs are interleaved and never batched.** Thirty runs of configuration 0
# followed by thirty of A cannot tell a configuration effect from a slow drift of the
# machine: a thermal ramp, a neighbour VM waking up, a cron job at the half hour. Any of
# those lands entirely on whichever configuration held the second half of the hour and is
# then published as its effect. Interleaved -- one run of every configuration, then the next
# repetition -- a drift is spread across all of them and cancels out of the differences.
# The 612.5 / 619.7 / 652.4 sequence that opened this file was monotonically rising, which
# is precisely the shape a batched protocol would have misread.
#
# **turbostat is the referee, and its absence is part of the verdict.** The knobs above are
# written into sysfs and an MSR; that they were accepted is not that they took effect. So
# `turbostat --interval 1` runs alongside every measurement and at least Bzy_MHz and CPU%c6
# come back per configuration: a campaign A whose Bzy_MHz still moves did not pin the clock,
# a campaign B whose CPU%c6 is not ~0 did not close the C-states. Where turbostat is absent
# the run continues and every line it would have judged says so, and the verdict carries the
# mention -- a number nothing checked is worth naming as such rather than quietly trusting.
# Installed and mute is its own case and gets its own word: turbostat installs on a guest
# and reads nothing there, because what it wants are MSRs the guest has not got, so
# `noise.referee=mute` is published with the reason turbostat itself gave.
#
# **What is measured is the load of measure-stage-cost.sh and not a copy of it.** The
# command and the parse come from scripts/lab/test-run-level.sh, which that script now
# sources too. The dispersion of a different load would be a fact about a different load.
#
# Runs on the development host and drives the two lab machines, like measure-stage-cost.sh:
# the measurement VM is the only machine that may be measured and the only one with no
# toolchain, so the binary is built static musl on the build VM and travels.
#
# The target core is LORICA_NOISE_CPU or --cpu and there is no default: the right core is a
# property of the host partitioning -- the plan for oploy-pve-02 leaves the SMT siblings of
# every measurement island empty -- and a constant written down here would be the sibling of
# a measurement VM on the next machine this is pointed at.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

# shellcheck source=scripts/lab/test-run-level.sh
. scripts/lab/test-run-level.sh

OUT=bench/results/noise
CPU=${LORICA_NOISE_CPU:-}
REPS=30
CAMPAIGNS=0,A,B
# Level 1 is the program returning immediately: the syscall, the kernel test-run loop and
# this object's own startup, with no pipeline in it. That is the instrument itself, and its
# dispersion is the floor under every figure the instrument produces, so it is what this
# script asks about by default. It is also the one level that exists whatever shape the
# pipeline has: a level number written down here would go stale the day a stage folds into
# the parse, exactly as the --levels list of measure-stage-cost.sh once did.
LEVEL=1
FREQ_KHZ=2000000
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run}
PERF=${LORICA_PERF:-perf}

# The repeat count the test compiles in. Named so the per-packet figures can carry it and
# so nothing here divides by a number it invented.
PACKETS=1000000
# Thirty is the floor and not the default-you-may-lower: a CV over fewer than thirty runs
# has a confidence interval wider than the differences between the campaigns it is meant
# to separate.
MIN_REPS=30

while [ $# -gt 0 ]; do
    case $1 in
        --cpu)       CPU=$2; shift 2 ;;
        --reps)      REPS=$2; shift 2 ;;
        --campaigns) CAMPAIGNS=$2; shift 2 ;;
        --level)     LEVEL=$2; shift 2 ;;
        --freq-khz)  FREQ_KHZ=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        -h|--help)   sed -n '2,6p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }
# The tuning goes over stdin rather than through `bash -lc '...'`: it needs single quotes
# for the runner it evals, and it needs one shell to survive from the first sysfs write to
# the last, because the pm-qos file descriptor is only a constraint while its process lives.
remote_body() {
    printf '%s\n' "$2" | ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -s"
}

# ---------------------------------------------------------------------------
# What the arguments have to be before anything is deployed anywhere
# ---------------------------------------------------------------------------

case $CPU in
    '') die "no target core: set LORICA_NOISE_CPU or pass --cpu. There is no default because the right core depends on the host partitioning, and a constant here would be the SMT sibling of a measurement VM on the next machine" ;;
    *[!0-9]*) die "--cpu is a logical CPU number, got '$CPU'" ;;
esac
case $REPS in ''|*[!0-9]*) die "--reps is a count, got '$REPS'" ;; esac
[ "$REPS" -ge "$MIN_REPS" ] \
    || die "--reps $REPS is under $MIN_REPS: a CV over fewer than $MIN_REPS runs has an interval wider than the campaign differences it is meant to separate"
case $LEVEL in ''|*[!0-9]*) die "--level is a level number, got '$LEVEL'" ;; esac
case $FREQ_KHZ in ''|*[!0-9]*) die "--freq-khz is a frequency in kHz, got '$FREQ_KHZ'" ;; esac

WANT=${CAMPAIGNS//,/ }
for c in $WANT; do
    case $c in
        0|A|B|C) ;;
        *) die "--campaigns takes 0, A, B and C, got '$c'" ;;
    esac
done
case " $WANT " in
    *" 0 "*) ;;
    *) die "--campaigns must contain 0: every delta this script prints is against CV0, the bare configuration" ;;
esac

mkdir -p "$OUT" || die "cannot create $OUT"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RAW=$OUT/noise-runs-$STAMP.csv

# ---------------------------------------------------------------------------
# The preflight, on the machine that will be measured
# ---------------------------------------------------------------------------
#
# Everything is read before anything is built: a refusal that arrives after a cold cargo
# build has cost ten minutes to say what a single ssh could have said first. Nothing here
# writes; the values read are also the baseline the restore puts back.

PROBE_BODY='
PATH=$PATH:/usr/sbin:/sbin
E=
[ "$(id -u)" -eq 0 ] || E="sudo -n"
echo probe.uid=$(id -u)
if [ -z "$E" ] || $E true 2>/dev/null; then echo probe.sudo=yes; else echo probe.sudo=no; fi
echo probe.host=$(hostname)
echo probe.kernel=$(uname -r)
echo probe.nproc=$(nproc)
c=/sys/devices/system/cpu
f=$c/cpu$cpu/cpufreq
if [ -d $f ]; then
    echo probe.cpufreq=present
    echo probe.governor=$(cat $f/scaling_governor)
    echo probe.min_freq=$(cat $f/scaling_min_freq)
    echo probe.max_freq=$(cat $f/scaling_max_freq)
    echo probe.cpuinfo_min_freq=$(cat $f/cpuinfo_min_freq)
    echo probe.cpuinfo_max_freq=$(cat $f/cpuinfo_max_freq)
else
    echo probe.cpufreq=absent
fi
if [ -e $c/intel_pstate/no_turbo ]; then
    echo probe.turbo_knob=$c/intel_pstate/no_turbo
    echo probe.turbo_value=$(cat $c/intel_pstate/no_turbo)
    echo probe.turbo_off=1
elif [ -e $c/cpufreq/boost ]; then
    echo probe.turbo_knob=$c/cpufreq/boost
    echo probe.turbo_value=$(cat $c/cpufreq/boost)
    echo probe.turbo_off=0
else
    echo probe.turbo_knob=absent
fi
d=$(ls -d $c/intel_uncore_frequency/package_* 2>/dev/null | head -1)
if [ -n "$d" ]; then
    echo probe.uncore=driver
    echo probe.uncore_dir=$d
    echo probe.uncore_min=$(cat $d/min_freq_khz)
    echo probe.uncore_max=$(cat $d/max_freq_khz)
elif [ -c /dev/cpu/$cpu/msr ]; then
    if u=$($E rdmsr -p $cpu 0x620 2>/dev/null); then
        echo probe.uncore=msr
        echo probe.uncore_msr=$u
    else
        echo probe.uncore=msr_unreadable
    fi
else
    echo probe.uncore=absent
fi
if [ -c /dev/cpu_dma_latency ]; then echo probe.pmqos=present; else echo probe.pmqos=absent; fi
if command -v turbostat >/dev/null; then echo probe.turbostat=present; else echo probe.turbostat=absent; fi
if command -v taskset >/dev/null; then echo probe.taskset=present; else echo probe.taskset=absent; fi
if command -v $perf >/dev/null; then echo probe.perf=present; else echo probe.perf=absent; fi
echo probe.isolcpus=$(grep -c isolcpus= /proc/cmdline)
echo probe.nohz_full=$(grep -c nohz_full= /proc/cmdline)
echo probe.online=$(cat $c/cpu$cpu/online 2>/dev/null || echo 1)
echo probe.end=ok
'

probe=$(remote_body "$TARGET_HOST" "cpu=$CPU
perf=$PERF
$PROBE_BODY") || die "the preflight on $TARGET_HOST failed: $probe"

fact() { printf '%s\n' "$probe" | sed -n "s/^probe\\.$1=//p" | tail -1; }

[ "$(fact end)" = ok ] || { printf '%s\n' "$probe" >&2; die "the preflight on $TARGET_HOST did not run to the end"; }
TARGET_UID=$(fact uid)
case $TARGET_UID in ''|*[!0-9]*) die "could not read the uid on $TARGET_HOST" ;; esac
NPROC=$(fact nproc)
case $NPROC in ''|*[!0-9]*) die "could not read the cpu count on $TARGET_HOST" ;; esac
[ "$CPU" -lt "$NPROC" ] || die "core $CPU does not exist on $TARGET_HOST, which has $NPROC"

# The uid that matters is the one on the target, not the one running this script, and sudo
# is asked for only where a knob needs it. A host that runs this as root already holds the
# capabilities and may not have sudo installed at all.
if [ "$TARGET_UID" -eq 0 ]; then ELEVATE=""; else ELEVATE="sudo -n "; fi

[ "$(fact perf)" = present ] \
    || die "$TARGET_HOST has no $PERF on its PATH: name the binary with LORICA_PERF, and note that a Proxmox host calls it perf_7.0"

# Campaign C is checked before the knobs of A and B, and on purpose: what it is missing is
# a reboot, and telling a reader that before telling them about a governor is telling them
# the thing they have to act on.
case " $WANT " in
    *" C "*)
        [ "$(fact isolcpus)" = 1 ] && [ "$(fact nohz_full)" = 1 ] \
            || die "campaign C needs isolcpus and nohz_full and the /proc/cmdline of $TARGET_HOST carries isolcpus=$(fact isolcpus) nohz_full=$(fact nohz_full) (1 means present). nohz_full is boot-only: this is a reboot, not a knob, and it is refused rather than skipped so that no verdict claims a C that never ran" ;;
esac

TUNED=0
case " $WANT " in *" A "*|*" B "*|*" C "*) TUNED=1 ;; esac

if [ "$TUNED" -eq 1 ]; then
    [ "$TARGET_UID" -eq 0 ] || [ "$(fact sudo)" = yes ] \
        || die "campaigns A, B and C write the governor, the turbo knob and an MSR on $TARGET_HOST, and sudo there asks for a password"
    [ "$(fact taskset)" = present ] || die "campaign A pins the load and $TARGET_HOST has no taskset"
    [ "$(fact cpufreq)" = present ] \
        || die "campaign A needs cpufreq and $TARGET_HOST has no /sys/devices/system/cpu/cpu$CPU/cpufreq: a guest sees no governor, no scaling_min_freq and no turbo knob, so the frequency there cannot be pinned and A cannot be told apart from 0"
    TURBO_KNOB=$(fact turbo_knob)
    [ "$TURBO_KNOB" != absent ] \
        || die "campaign A needs a turbo knob and $TARGET_HOST has neither intel_pstate/no_turbo nor cpufreq/boost"
    UNCORE=$(fact uncore)
    case $UNCORE in
        driver|msr) ;;
        *) die "campaign A freezes the uncore and $TARGET_HOST offers neither intel_uncore_frequency nor a readable MSR 0x620 (read: $UNCORE). Haswell-EP moves the uncore clock on its own with the cores pinned, so an A without it reports the uncore as residue" ;;
    esac
fi

case " $WANT " in
    *" B "*|*" C "*)
        [ "$(fact pmqos)" = present ] \
            || die "campaign B holds /dev/cpu_dma_latency at 0 and $TARGET_HOST has no such device" ;;
esac

REFEREE=$(fact turbostat)
[ "$REFEREE" = present ] \
    || printf 'NOTE  %s has no turbostat: Bzy_MHz and CPU%%c6 will be empty and no line here checks that the knobs took effect\n' "$TARGET_HOST" >&2

# The uncore target, computed from what was read and never from a ratio written down here.
# Bits 0-6 are the maximum ratio and bits 8-14 the minimum; min = max is the freeze.
UNCORE_TARGET=""
if [ "$TUNED" -eq 1 ] && [ "$(fact uncore)" = msr ]; then
    base_msr=$(fact uncore_msr)
    case $base_msr in
        ''|*[!0-9a-fA-F]*) die "MSR 0x620 on $TARGET_HOST read back as '$base_msr', which is not a value to compute a freeze from" ;;
    esac
    ratio=$(( 0x$base_msr & 0x7f ))
    [ "$ratio" -gt 0 ] || die "MSR 0x620 on $TARGET_HOST reports a maximum uncore ratio of 0, which is not a frequency to pin the uncore at"
    UNCORE_TARGET=$(printf '%x' $(( (ratio << 8) | ratio )))
fi

# ---------------------------------------------------------------------------
# The restore, and the trap that owns it
# ---------------------------------------------------------------------------
#
# Every knob goes back to the value the preflight read, and the pm-qos descriptor is closed
# by the death of the process that held it. The trap covers the interrupt and the normal
# end alike: a campaign abandoned with Ctrl-C leaves a machine at a pinned frequency with
# its C-states shut, and the next person to measure on it measures that.

PRELUDE=""
BASELINE_READY=0

RESTORE_BODY='
PATH=$PATH:/usr/sbin:/sbin
E=
[ "$(id -u)" -eq 0 ] || E="sudo -n"
w() { printf %s "$2" | $E tee "$1" >/dev/null 2>&1; }
c=/sys/devices/system/cpu
f=$c/cpu$cpu/cpufreq
if [ -d $f ] && [ -n "$base_governor" ]; then
    w $f/scaling_min_freq $cpuinfo_min_freq
    w $f/scaling_max_freq $base_max_freq
    w $f/scaling_min_freq $base_min_freq
    w $f/scaling_governor $base_governor
fi
[ "$turbo_knob" = absent ] || w $turbo_knob $turbo_value
if [ "$uncore" = driver ]; then
    w $uncore_dir/min_freq_khz $uncore_min
    w $uncore_dir/max_freq_khz $uncore_max
elif [ "$uncore" = msr ]; then
    $E wrmsr -p $cpu 0x620 0x$uncore_msr 2>/dev/null
fi
$E pkill -f cpu_dma_latency_holder 2>/dev/null
echo restore.done=ok
'

cleanup() {
    [ "$BASELINE_READY" -eq 1 ] || return 0
    printf 'restoring %s\n' "$TARGET_HOST" >&2
    remote_body "$TARGET_HOST" "$PRELUDE
$RESTORE_BODY" >&2
    return 0
}
# One handler on EXIT and a plain exit on the signals, rather than the same handler on all
# three: a trap on INT that does not exit hands control back to the loop, which then goes on
# measuring a machine it has just put back, and the EXIT trap runs the restore anyway.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Every value the remote side needs, quoted here once. The runner is single-quoted on the
# far side and carries no single quote of its own, which is checked by the only thing that
# can check it: it is built by test_run_command and that function's output is a fixed shape.
PRELUDE=$(printf '%s\n' \
    "cpu=$CPU" \
    "perf=$PERF" \
    "packets=$PACKETS" \
    "freq_khz=$FREQ_KHZ" \
    "run_dir=$RUN_DIR" \
    "base_governor=$(fact governor)" \
    "base_min_freq=$(fact min_freq)" \
    "base_max_freq=$(fact max_freq)" \
    "cpuinfo_min_freq=$(fact cpuinfo_min_freq)" \
    "turbo_knob=$(fact turbo_knob)" \
    "turbo_value=$(fact turbo_value)" \
    "turbo_off=$(fact turbo_off)" \
    "uncore=$(fact uncore)" \
    "uncore_dir=$(fact uncore_dir)" \
    "uncore_min=$(fact uncore_min)" \
    "uncore_max=$(fact uncore_max)" \
    "uncore_msr=$(fact uncore_msr)" \
    "uncore_target=$UNCORE_TARGET" \
    "referee=$REFEREE")
BASELINE_READY=1

# ---------------------------------------------------------------------------
# Build once, ship once
# ---------------------------------------------------------------------------

bash scripts/lab/deploy.sh "$BUILD_HOST" \
    "bash scripts/lab/target-build.sh --test stage_cost --ebpf-features stage-cutoff" \
    || die "the build on $BUILD_HOST failed"

remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
    | remote "$TARGET_HOST" "rm -rf ~/$RUN_DIR && mkdir -p ~/$RUN_DIR && tar xf - -C ~/$RUN_DIR" \
    || die "could not ship the measurement binary to $TARGET_HOST"

# ---------------------------------------------------------------------------
# One run: apply, measure under the referee, put back
# ---------------------------------------------------------------------------
#
# The configuration is applied and undone around every single run rather than held across a
# block of thirty, because the runs are interleaved and that is the whole point of them.
# The cost is a governor write per run, which is microseconds against a measurement of
# seconds; the alternative costs the ability to tell a configuration from an hour of the day.

RUN_BODY='
PATH=$PATH:/usr/sbin:/sbin
E=
[ "$(id -u)" -eq 0 ] || E="sudo -n"
c=/sys/devices/system/cpu
f=$c/cpu$cpu/cpufreq
ts=$HOME/$run_dir/noise-turbostat.txt
ts_pid=
holder=

w() { printf %s "$2" | $E tee "$1" >/dev/null; }
need() { w "$1" "$2" || { echo NOISE_FAIL=write:$1; exit 1; }; }

restore() {
    if [ -n "$ts_pid" ]; then
        # The launcher is sudo and its child is the root turbostat, so killing only the one
        # this shell forked leaves the referee running until the next reboot.
        $E pkill -x -P $ts_pid turbostat 2>/dev/null
        $E kill $ts_pid 2>/dev/null
    fi
    if [ -n "$holder" ]; then
        $E pkill -f cpu_dma_latency_holder 2>/dev/null
        kill $holder 2>/dev/null
    fi
    if [ "$cfg" != 0 ] && [ -d $f ]; then
        w $f/scaling_min_freq $cpuinfo_min_freq
        w $f/scaling_max_freq $base_max_freq
        w $f/scaling_min_freq $base_min_freq
        w $f/scaling_governor $base_governor
        [ "$turbo_knob" = absent ] || w $turbo_knob $turbo_value
        if [ "$uncore" = driver ]; then
            w $uncore_dir/min_freq_khz $uncore_min
            w $uncore_dir/max_freq_khz $uncore_max
        elif [ "$uncore" = msr ]; then
            $E wrmsr -p $cpu 0x620 0x$uncore_msr 2>/dev/null
        fi
    fi
}
trap restore EXIT INT TERM

if [ "$cfg" != 0 ]; then
    need $f/scaling_governor performance
    [ "$turbo_knob" = absent ] || need $turbo_knob $turbo_off
    # Down first, then up, then down: the kernel refuses a minimum above the current
    # maximum, so a single pair of writes works in one direction only.
    need $f/scaling_min_freq $cpuinfo_min_freq
    need $f/scaling_max_freq $freq_khz
    need $f/scaling_min_freq $freq_khz
    if [ "$uncore" = driver ]; then
        need $uncore_dir/min_freq_khz $uncore_max
        need $uncore_dir/max_freq_khz $uncore_max
    elif [ "$uncore" = msr ]; then
        $E wrmsr -p $cpu 0x620 0x$uncore_target || { echo NOISE_FAIL=wrmsr; exit 1; }
    fi
    echo NOISE_GOVERNOR=$(cat $f/scaling_governor)
    echo NOISE_MIN=$(cat $f/scaling_min_freq)
    echo NOISE_MAX=$(cat $f/scaling_max_freq)
fi

if [ "$cfg" = B ] || [ "$cfg" = C ]; then
    # The name is on the command line so the restore can find this process again after an
    # ssh that died mid-run. dd writes four zero bytes into the descriptor the shell holds
    # and does not close it: the constraint lives as long as this sleep does, and lifts by
    # itself the moment it is killed. Nothing to put back, which is the whole reason this
    # is not intel_idle.max_cstate=0.
    $E bash -c "exec 3<>/dev/cpu_dma_latency; dd if=/dev/zero bs=4 count=1 >&3 2>/dev/null; exec -a cpu_dma_latency_holder sleep 3600" &
    holder=$!
    i=0
    latency=
    while [ $i -lt 20 ]; do
        # Under $E: the device is 0600 root on the lab machines, so an unprivileged read
        # back reports the constraint as unreadable and fails a run that worked.
        latency=$($E od -An -tu4 -N4 /dev/cpu_dma_latency 2>/dev/null | tr -dc 0-9)
        [ "$latency" = 0 ] && break
        i=$((i + 1))
        sleep 0.1
    done
    if [ "$latency" != 0 ]; then
        echo NOISE_FAIL=pmqos_target_is_${latency:-unreadable}
        exit 1
    fi
    echo NOISE_PMQOS=$latency
fi

if [ "$referee" = present ]; then
    # Its stderr is kept rather than dropped: turbostat installs on any machine and refuses
    # to read on a guest, and "the referee said nothing" is a different fact from "there is
    # no referee installed" only if the reason comes back with it.
    $E turbostat --interval 1 --quiet --show CPU,Bzy_MHz,CPU%c6 > $ts 2> $ts.err &
    ts_pid=$!
fi

echo NOISE_PERF_BEGIN
eval "$runner" 2>&1
echo NOISE_PERF_END

if [ -n "$ts_pid" ]; then
    $E pkill -x -P $ts_pid turbostat 2>/dev/null
    $E kill $ts_pid 2>/dev/null
    wait $ts_pid 2>/dev/null
    ts_pid=
    echo NOISE_TURBOSTAT_BEGIN
    cat $ts 2>/dev/null
    echo NOISE_TURBOSTAT_END
    echo NOISE_TURBOSTAT_ERR_BEGIN
    head -3 $ts.err 2>/dev/null
    echo NOISE_TURBOSTAT_ERR_END
fi
echo NOISE_RUN=ok
'

echo 'rep,config,cycles,instructions,ns,cache_misses,bzy_mhz,cpu_c6' > "$RAW" \
    || die "cannot write $RAW"

# Bzy_MHz and CPU%c6 for the target core, as the median of whatever samples the referee
# produced during this one run. The header is re-read every time it reappears: turbostat
# repeats it, and its column order is a property of the version installed rather than of
# this script.
turbostat_median() {
    printf '%s\n' "$1" | awk -v cpu="$2" '
        /Bzy_MHz/ { for (i = 1; i <= NF; i++) { if ($i == "CPU") ci = i; if ($i == "Bzy_MHz") bi = i; if ($i == "CPU%c6") si = i } next }
        ci && $ci == cpu { b[nb++] = $bi + 0; if (si) { s[ns++] = $si + 0 } }
        function med(a, n,   i, j, x, m) {
            for (i = 1; i < n; i++) { x = a[i]; j = i - 1; while (j >= 0 && a[j] > x) { a[j+1] = a[j]; j-- } a[j+1] = x }
            m = int(n / 2)
            return (n % 2 ? a[m] : (a[m-1] + a[m]) / 2)
        }
        END {
            if (nb == 0) { exit 0 }
            printf "%.1f %s\n", med(b, nb), (ns > 0 ? sprintf("%.3f", med(s, ns)) : "")
        }'
}

runs=0
rep=1
REFEREE_WHY=""
while [ "$rep" -le "$REPS" ]; do
    for cfg in $WANT; do
        prefix=""
        [ "$cfg" = 0 ] || prefix="taskset -c $CPU "
        runner=$(test_run_command "$RUN_DIR" "$LEVEL" "$ELEVATE" "$PERF" "$prefix")
        out=$(remote_body "$TARGET_HOST" "$PRELUDE
cfg=$cfg
$(printf "runner='%s'" "$runner")
$RUN_BODY" 2>&1)

        case $out in
            *NOISE_RUN=ok*) ;;
            *) printf '%s\n' "$out" >&2
               die "repetition $rep of campaign $cfg did not finish on $TARGET_HOST" ;;
        esac

        perf_out=$(printf '%s\n' "$out" | sed -n '/^NOISE_PERF_BEGIN$/,/^NOISE_PERF_END$/p')
        test_run_fields "$perf_out" \
            || { printf '%s\n' "$out" >&2; die "repetition $rep of campaign $cfg printed no LEVEL record"; }
        case $TR_NS in
            ''|*[!0-9]*) die "repetition $rep of campaign $cfg reported '$TR_NS' nanoseconds" ;;
        esac
        case $TR_CYCLES in
            ''|*[!0-9]*) printf '%s\n' "$out" >&2
                         die "repetition $rep of campaign $cfg produced no cycle count, and a dispersion of nothing is not a result" ;;
        esac
        case $TR_INSTRUCTIONS in
            ''|*[!0-9]*) printf '%s\n' "$out" >&2
                         die "repetition $rep of campaign $cfg produced no instruction count, and the instruction column is the control that says the load did not change" ;;
        esac

        bzy=""; c6=""
        if [ "$REFEREE" = present ]; then
            ts_out=$(printf '%s\n' "$out" | sed -n '/^NOISE_TURBOSTAT_BEGIN$/,/^NOISE_TURBOSTAT_END$/p')
            # Split on whitespace through the positional parameters: the arguments were
            # consumed long ago, and a here-document terminator is one stray carriage
            # return away from swallowing the rest of the script.
            # shellcheck disable=SC2046
            set -- $(turbostat_median "$ts_out" "$CPU")
            bzy=${1:-}; c6=${2:-}
            if [ -z "$bzy" ] && [ -z "$REFEREE_WHY" ]; then
                REFEREE_WHY=$(printf '%s\n' "$out" \
                    | sed -n '/^NOISE_TURBOSTAT_ERR_BEGIN$/,/^NOISE_TURBOSTAT_ERR_END$/p' \
                    | sed -e '1d' -e '$d' | tr '\n' ' ' | sed -e 's/[[:space:]]*$//')
                [ -n "$REFEREE_WHY" ] || REFEREE_WHY="turbostat printed no row for core $CPU and said nothing about why"
            fi
        fi

        printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$rep" "$cfg" "$TR_CYCLES" "$TR_INSTRUCTIONS" "$TR_NS" "$TR_LLC" "$bzy" "$c6" >> "$RAW"
        runs=$((runs + 1))
        printf 'rep %s/%s campaign %s: %s cycles, %s instructions%s\n' \
            "$rep" "$REPS" "$cfg" "$TR_CYCLES" "$TR_INSTRUCTIONS" \
            "$([ -n "$bzy" ] && printf ', %s MHz, %s %%c6' "$bzy" "$c6")"
    done
    rep=$((rep + 1))
done

[ "$runs" -gt 0 ] || die "no run completed, so there is nothing to disperse"

# turbostat installs on a guest and then reads nothing there, because the counters it wants
# are MSRs the guest does not have. Present-and-mute is neither absent nor a failure: the
# cycles measured are still the cycles measured, and what is lost is only the confirmation
# that the knobs took. So it is named, carried into the result file, and repeated on the
# verdict -- which is the whole difference between a missing referee and a missed one.
if [ "$REFEREE" = present ] \
    && [ -z "$(awk -F, 'NR > 1 && $7 != "" { print 1; exit }' "$RAW")" ]; then
    REFEREE=mute
    printf 'NOTE  turbostat on %s produced no reading: %s\n' "$TARGET_HOST" "$REFEREE_WHY" >&2
fi

# ---------------------------------------------------------------------------
# Median, CV, and the deltas between the campaigns
# ---------------------------------------------------------------------------

# Sample standard deviation over the mean, in percent. Prints nothing at all when the mean
# is not positive or the column is empty, so an unmeasured configuration becomes a refusal
# upstream rather than a zero that reads like perfect stability.
stats() {
    awk -F, -v cfg="$2" -v col="$3" '
        NR > 1 && $2 == cfg && $col != "" { v[n++] = $col + 0 }
        END {
            if (n == 0) { exit 0 }
            for (i = 1; i < n; i++) { x = v[i]; j = i - 1; while (j >= 0 && v[j] > x) { v[j+1] = v[j]; j-- } v[j+1] = x }
            m = int(n / 2)
            med = (n % 2 ? v[m] : (v[m-1] + v[m]) / 2)
            s = 0
            for (i = 0; i < n; i++) { s += v[i] }
            mean = s / n
            if (mean <= 0) { exit 0 }
            q = 0
            for (i = 0; i < n; i++) { d = v[i] - mean; q += d * d }
            sd = (n > 1 ? sqrt(q / (n - 1)) : 0)
            printf "%.4f %.4f %d\n", med, 100 * sd / mean, n
        }' "$1"
}

LINES=()
emit() {
    case $2 in
        '') die "no value was read for $1; refusing to publish a line rather than default it to zero" ;;
    esac
    LINES+=("$1=$2")
}

emit noise.host "$(fact host)"
emit noise.kernel "$(fact kernel)"
emit noise.cpu "$CPU"
emit noise.level "$LEVEL"
emit noise.packets "$PACKETS"
emit noise.reps "$REPS"
emit noise.runs "$runs"
emit noise.campaigns "$CAMPAIGNS"
emit noise.freq_khz "$FREQ_KHZ"
emit noise.referee "$REFEREE"
[ "$REFEREE" = present ] || emit noise.referee_why "${REFEREE_WHY:-turbostat is not installed on $TARGET_HOST}"
emit noise.uncore_method "$(fact uncore)"
emit noise.interleaved yes

name_of() {
    case $1 in
        0) echo bare ;;
        A) echo a ;;
        B) echo b ;;
        C) echo c ;;
    esac
}

declare -A CV
for cfg in $WANT; do
    key=noise.$(name_of "$cfg")
    # shellcheck disable=SC2046
    set -- $(stats "$RAW" "$cfg" 3)
    med=${1:-}; cv=${2:-}; n=${3:-}
    [ -n "$cv" ] || die "campaign $cfg produced no cycle statistic out of $RAW"
    [ "$n" -eq "$REPS" ] \
        || die "campaign $cfg carries $n cycle readings for $REPS repetitions, so the CV is not over what was asked for"
    CV[$cfg]=$cv
    emit "$key.n" "$n"
    emit "$key.cycles_median" "$med"
    emit "$key.cycles_per_packet_median" \
        "$(awk -v m="$med" -v p="$PACKETS" 'BEGIN { printf "%.1f", (p > 0 ? m / p : 0) }')"
    emit "$key.cycles_cv_percent" "$cv"

    # shellcheck disable=SC2046
    set -- $(stats "$RAW" "$cfg" 4)
    imed=${1:-}; icv=${2:-}; ino=${3:-}
    [ -n "$icv" ] || die "campaign $cfg produced no instruction statistic out of $RAW"
    emit "$key.instructions_median" "$imed"
    emit "$key.instructions_cv_percent" "$icv"
    emit "$key.instructions_n" "$ino"

    if [ "$REFEREE" = present ]; then
        # shellcheck disable=SC2046
        set -- $(stats "$RAW" "$cfg" 7)
        bmed=${1:-}; bcv=${2:-}
        [ -n "$bmed" ] \
            || die "turbostat is installed on $TARGET_HOST but campaign $cfg came back with no Bzy_MHz, so nothing judged whether the clock was pinned"
        emit "$key.bzy_mhz_median" "$bmed"
        emit "$key.bzy_mhz_cv_percent" "$bcv"
        # shellcheck disable=SC2046
        set -- $(stats "$RAW" "$cfg" 8)
        smed=${1:-}
        # A CPU%c6 that is genuinely zero everywhere has a zero mean, which stats refuses to
        # divide by: the median is still the reading that matters and it is published alone,
        # and a campaign B is meant to read exactly zero there.
        if [ -n "$smed" ]; then
            emit "$key.cpu_c6_median" "$smed"
        else
            LINES+=("$key.cpu_c6_median=0.0000")
        fi
    fi
done

# The deltas, in points of CV, each against the campaign before it. A delta is what a
# control bought; the last one standing is what none of them explains.
delta() {
    awk -v a="${CV[$1]:-}" -v b="${CV[$2]:-}" 'BEGIN {
        if (a == "" || b == "") { exit 0 }
        printf "%.4f\n", a - b
    }'
}
prev=""
for cfg in $WANT; do
    if [ -n "$prev" ]; then
        d=$(delta "$prev" "$cfg")
        [ -n "$d" ] || die "no CV delta could be formed between campaign $prev and campaign $cfg"
        emit "noise.delta_cv_$(name_of "$prev")_to_$(name_of "$cfg")" "$d"
    fi
    prev=$cfg
done
if [ -n "$prev" ] && [ "$prev" != 0 ]; then
    d=$(delta 0 "$prev")
    [ -n "$d" ] || die "no CV delta could be formed between the bare configuration and campaign $prev"
    emit "noise.delta_cv_bare_to_$(name_of "$prev")" "$d"
    emit "noise.residual_cv_percent" "${CV[$prev]}"
fi

# ---------------------------------------------------------------------------
# Written last, and from the array that was printed
# ---------------------------------------------------------------------------

printf '%s\n' "${LINES[@]}"

result=$OUT/noise-$STAMP.txt
printf '%s\n' "${LINES[@]}" > "$result" || die "cannot write $result"
printf '\nruns   %s\nresult %s\n' "$RAW" "$result"

for cfg in $WANT; do
    printf 'CV     campaign %s: %s %% on cycles, %s %% on instructions\n' \
        "$cfg" "${CV[$cfg]}" \
        "$(printf '%s\n' "${LINES[@]}" | sed -n "s/^noise\\.$(name_of "$cfg")\\.instructions_cv_percent=//p")"
done

case " $WANT " in
    *" C "*) ;;
    *) printf 'NOTE  campaign C did not run: it needs isolcpus and nohz_full at boot, so the residue reported here still contains the tick, the RCU callbacks and the neighbours\n' ;;
esac
[ "$REFEREE" = present ] \
    || printf 'NOTE  the referee was %s on %s (%s): nothing above confirms that the governor, the turbo knob, the uncore ratio or the C-state target took effect, and every campaign difference here is to be read with that missing\n' \
        "$REFEREE" "$TARGET_HOST" "${REFEREE_WHY:-turbostat is not installed}"
