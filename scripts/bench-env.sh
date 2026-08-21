#!/usr/bin/env bash
# Put the machine in the state a benchmark result assumes. Applies what this
# machine exposes and says out loud what it does not: a guest cannot pin its own
# frequency, and pretending otherwise makes every number here unfalsifiable.
#
#   bench-env.sh          apply
#   bench-env.sh --show   report current values without changing anything

set -uo pipefail

show_only=0
[ "${1:-}" = --show ] && show_only=1

set_value() {
    local value=$1 path=$2
    if [ ! -w "$path" ] && [ ! -e "$path" ]; then
        printf 'skip  %s (absent on this machine)\n' "$path"
        return
    fi
    if [ "$show_only" = 1 ]; then
        printf 'now   %-58s %s\n' "$path" "$(cat "$path" 2>/dev/null)"
        return
    fi
    if echo "$value" | sudo -n tee "$path" >/dev/null 2>&1; then
        printf 'set   %-58s %s\n' "$path" "$value"
    else
        printf 'FAIL  %-58s could not write %s\n' "$path" "$value"
    fi
}

if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    if [ "$show_only" = 1 ]; then
        printf 'now   governor %s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
    else
        sudo -n cpupower frequency-set -g performance >/dev/null 2>&1 \
            && echo 'set   governor performance' \
            || echo 'FAIL  cpupower frequency-set -g performance'
    fi
    set_value 1 /sys/devices/system/cpu/intel_pstate/no_turbo
    set_value 0 /sys/devices/system/cpu/cpufreq/boost
else
    echo 'skip  governor and turbo: no cpufreq in this guest, the hypervisor owns the frequency'
fi

set_value never /sys/kernel/mm/transparent_hugepage/enabled
set_value 0     /proc/sys/kernel/randomize_va_space
set_value 0     /proc/sys/kernel/nmi_watchdog
