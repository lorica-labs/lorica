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

    section 'versions'
    bpftool version 2>&1 | head -2
    clang --version 2>&1 | head -1
    ethtool --version 2>&1 | head -1
    printf 'os  %s\n' "$(. /etc/os-release; echo "$PRETTY_NAME")"

    section 'loaded xdp programs'
    ip -j -d link show 2>/dev/null | grep -o '"xdp":{[^}]*}' || echo 'none'
} > "$out"

echo "$out"
