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

# Two things the script cannot fix and every counter-read measurement depends on.
#
# `bpf_map_value_size` multiplies a per-CPU value by num_possible_cpus() and
# `bpf_percpu_array_copy` walks for_each_possible_cpu, so a guest booted with more
# possible processors than online ones pays a copy per phantom processor on every
# element of every batch read — measured at ~34 ns per processor per element. It is
# fixed at boot (maxcpus=, or the hypervisor's CPU hotplug window), not from sysfs.
#
# schedstat's runqueue-wait, which is one of the three suspects the tick diagnostic
# separates, reads zero unless sched_schedstats is on. A zero there means "not
# measured", so it is worth turning on before a campaign and off after.
possible=$(cat /sys/devices/system/cpu/possible 2>/dev/null)
online=$(cat /sys/devices/system/cpu/online 2>/dev/null)
count_cpus() {
    local total=0 range
    for range in ${1//,/ }; do
        if [ "${range%-*}" = "$range" ]; then
            total=$((total + 1))
        else
            total=$((total + ${range#*-} - ${range%-*} + 1))
        fi
    done
    printf '%s' "$total"
}
if [ -n "$possible" ] && [ -n "$online" ]; then
    n_possible=$(count_cpus "$possible")
    n_online=$(count_cpus "$online")
    if [ "$n_possible" -gt "$n_online" ]; then
        printf 'WARN  possible=%s (%s) online=%s (%s): every per-CPU map copies %s phantom processors per element\n' \
            "$possible" "$n_possible" "$online" "$n_online" "$((n_possible - n_online))"
    else
        printf 'now   possible=%s online=%s, no phantom processors\n' "$possible" "$online"
    fi
fi

set_value 1 /proc/sys/kernel/sched_schedstats
