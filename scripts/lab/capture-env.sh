#!/usr/bin/env bash
# Write a timestamped environment record next to a measurement result, and print
# its path. Without it a number in bench/results/ is unreproducible.
#
#   capture-env.sh <outdir> [iface]

# Deliberately neither -e nor pipefail. A capture records what the machine will
# give it and always prints its path: `clang --version | head -1` kills clang with
# SIGPIPE, which under pipefail would abort the capture and leave the caller with
# an empty filename for a file that exists.
set -u

outdir=${1:?usage: capture-env.sh <outdir> [iface]}
iface=${2:-${LORICA_IFACE:-enp6s19}}

mkdir -p "$outdir"
out="$outdir/env-$(date -u +%Y%m%dT%H%M%SZ).txt"

section() { printf '\n===== %s =====\n' "$1"; }

# An empty field and an absent one read the same way to a human and differently to a script,
# so neither is left blank. `|| echo n/a` cannot do this on its own: on a pipeline the `||`
# tests the last element, and `tr` succeeds on empty input, so the fallback never fires and
# the field comes out blank — which is exactly what the first version of this did.
field() { v=$(eval "$1" 2>/dev/null); printf '%s\n' "${v:-n/a}"; }

{
    printf 'captured-utc  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'host          %s\n' "$(hostname)"
    printf 'iface         %s\n' "$iface"

    section 'uname -a';       uname -a
    section 'lscpu';          lscpu
    section '/proc/cmdline';  cat /proc/cmdline
    section 'clocksource'
    printf 'current   %s\n'   "$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)"
    printf 'available %s\n'   "$(cat /sys/devices/system/clocksource/clocksource0/available_clocksource)"
    ls -d /dev/ptp* 2>/dev/null || echo 'no /dev/ptp*'

    section "ethtool -i $iface"; ethtool -i "$iface" 2>&1
    section "ethtool -k $iface"; ethtool -k "$iface" 2>&1
    section "ethtool -l $iface"; ethtool -l "$iface" 2>&1
    section "ip -d link show $iface"; ip -d link show "$iface" 2>&1

    section 'tuning'
    printf 'nmi_watchdog        %s\n' "$(cat /proc/sys/kernel/nmi_watchdog)"
    printf 'randomize_va_space  %s\n' "$(cat /proc/sys/kernel/randomize_va_space)"
    printf 'thp                 %s\n' "$(cat /sys/kernel/mm/transparent_hugepage/enabled)"
    printf 'perf_event_paranoid %s\n' "$(cat /proc/sys/kernel/perf_event_paranoid)"
    printf 'bpf_stats_enabled   %s\n' "$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo n/a)"
    printf 'governor            %s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'no cpufreq in guest')"
    printf 'irqbalance          %s\n' "$(systemctl is-active irqbalance 2>/dev/null || true)"

    # Everything below stopped being background and became an experimental variable the day a
    # program whose instruction count reproduces to 0.11 % measured 6.5 % of spread in cycles.
    # A capture that records the interface but not the frequency policy cannot tell two runs
    # apart. Every read is tolerant of an absent file on purpose: a guest has no cpufreq, no
    # MSR and no uncore, and a capture that dies on the machine it is describing is worthless.
    section 'frequency and idle policy'
    cpufreq=/sys/devices/system/cpu/cpu0/cpufreq
    printf 'scaling_driver      %s\n' "$(field "cat $cpufreq/scaling_driver")"
    printf 'scaling_governor    %s\n' "$(field "cat $cpufreq/scaling_governor")"
    printf 'scaling_min_freq    %s\n' "$(field "cat $cpufreq/scaling_min_freq")"
    printf 'scaling_max_freq    %s\n' "$(field "cat $cpufreq/scaling_max_freq")"
    printf 'no_turbo            %s\n' "$(field "cat /sys/devices/system/cpu/intel_pstate/no_turbo")"
    # cpu0 above, and here whether the other CPUs agree with it. A governor set on one core is
    # a different machine from a governor set on all of them, and one read cannot tell them
    # apart. Empty means they all agree.
    printf 'governors off cpu0  %s\n' \
        "$(field "grep -L \"\$(cat $cpufreq/scaling_governor)\" /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | tr '\n' ' '")"
    printf 'idle states cpu0    %s\n' \
        "$(field "cat /sys/devices/system/cpu/cpu0/cpuidle/state*/name | tr '\n' ' '")"
    # Readable, and reading sets nothing: only an open-for-write holds a PM QoS constraint, and
    # it lasts exactly as long as that descriptor. What comes back is the current global target
    # in microseconds, so 0 means something is forbidding the deep states right now.
    printf 'cpu_dma_latency us  %s\n' \
        "$(field "od -An -td4 -N4 /dev/cpu_dma_latency | tr -d ' '")"

    section 'speculative mitigations'
    # In software on Haswell, so each of these is cycles on every syscall, and
    # BPF_PROG_TEST_RUN is a syscall per iteration.
    for v in /sys/devices/system/cpu/vulnerabilities/*; do
        [ -r "$v" ] || continue
        printf '%-26s %s\n' "$(basename "$v")" "$(cat "$v" 2>/dev/null)"
    done

    section 'numa allocation counters'
    # Absolute and cumulative since boot, which is not what anybody wants: the number that
    # means something is the DELTA across a run. Capture before and after and subtract. Any
    # growth of numa_miss during a bench says the preferred node stopped serving locally.
    grep -E 'numa_hit|numa_miss|numa_foreign|numa_local|numa_other' /proc/vmstat 2>/dev/null \
        || echo 'no numa counters in /proc/vmstat'
    numactl --hardware 2>/dev/null | head -8 || echo 'numactl absent'

    section 'versions'
    bpftool version 2>&1 | head -2
    clang --version 2>&1 | head -1
    ethtool --version 2>&1 | head -1
    printf 'os  %s\n' "$(. /etc/os-release; echo "$PRETTY_NAME")"

    section 'loaded xdp programs'
    ip -j -d link show 2>/dev/null | grep -o '"xdp":{[^}]*}' || echo 'none'
} > "$out"

echo "$out"
