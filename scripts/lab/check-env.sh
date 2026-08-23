#!/usr/bin/env bash
# Refuse to measure on a machine whose state would not match what the results claim.
# Exits non-zero on the first failed control, naming the fix.
#
#   check-env.sh [--iface NAME] [--steal-seconds N] [--steal-max PCT]
#
# Role is derived from the hostname (lorica-dev / lorica-target / lorica-gen)
# and can be forced with LORICA_ROLE. Two controls are target-only: the kernel
# version and the apt hold that keeps it there.

set -uo pipefail

IFACE=${LORICA_IFACE:-enp6s19}
STEAL_SECONDS=${LORICA_STEAL_SECONDS:-60}
# Policy threshold, not a measurement: above this the guest is not getting the CPU
# it thinks it has and every per-packet number is inflated by an unknown amount.
STEAL_MAX=${LORICA_STEAL_MAX:-1.0}

while [ $# -gt 0 ]; do
    case $1 in
        --iface)         IFACE=$2; shift 2 ;;
        --steal-seconds) STEAL_SECONDS=$2; shift 2 ;;
        --steal-max)     STEAL_MAX=$2; shift 2 ;;
        -h|--help)       sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ROLE=${LORICA_ROLE:-}
if [ -z "$ROLE" ]; then
    case $(hostname) in
        lorica-dev)    ROLE=dev ;;
        lorica-target) ROLE=target ;;
        lorica-gen)    ROLE=gen ;;
        *) echo "unknown host $(hostname): set LORICA_ROLE to dev, target or gen" >&2; exit 2 ;;
    esac
fi

ok()   { printf 'ok    %s\n' "$1"; }
note() { printf 'note  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n      fix: %s\n' "$1" "$2" >&2; exit 1; }

printf 'check-env: role=%s host=%s iface=%s\n' "$ROLE" "$(hostname)" "$IFACE"

sudo -n true 2>/dev/null \
    || fail "sudo requires a password" \
            "install /etc/sudoers.d/lorica with 'hookwood ALL=(ALL) NOPASSWD:ALL', mode 0440"

# --- kernel, target only ------------------------------------------------------
if [ "$ROLE" = target ]; then
    release=$(uname -r)
    case $release in
        6.8.*) ok "kernel $release" ;;
        *) fail "kernel is $release, the measurement target is 6.8" \
                "apt install linux-image-virtual linux-headers-virtual; apt remove 'linux-*-hwe-24.04*'; update-grub; reboot" ;;
    esac

    holds=$(apt-mark showhold)
    case $holds in
        *linux-image-virtual*|*linux-image-generic*) ok "kernel held: $(echo "$holds" | tr '\n' ' ')" ;;
        *) fail "no hold on the kernel packages" \
                "apt-mark hold linux-image-virtual linux-image-generic linux-headers-generic" ;;
    esac
fi

# --- BTF ----------------------------------------------------------------------
[ -r /sys/kernel/btf/vmlinux ] \
    && ok "BTF present" \
    || fail "/sys/kernel/btf/vmlinux missing" "install a kernel built with CONFIG_DEBUG_INFO_BTF"

# --- hardware counters --------------------------------------------------------
# 902 runs on --cpu host and is not a profiling target: it generates traffic.
if [ "$ROLE" != gen ]; then
    perf_out=$(perf stat -e cycles -- sleep 1 2>&1)
    case $perf_out in
        *"<not supported>"*|*"not supported"*)
            fail "perf stat -e cycles is not supported" \
                 "the VM has no PMU: set --cpu custom-host-pmu, then qm stop and qm start (a guest reboot is not enough)" ;;
        *) ok "perf stat -e cycles: $(echo "$perf_out" | grep -m1 cycles | tr -s ' ' | sed 's/^ *//')" ;;
    esac

    pmu_line=$(sudo -n dmesg | grep -i -m1 'Performance Events')
    case $pmu_line in
        *"software events only"*|"")
            fail "kernel reports no hardware PMU: ${pmu_line:-no Performance Events line}" \
                 "qm showcmd <vmid> --pretty | grep -- -cpu must contain +pmu, then qm stop and qm start" ;;
        *"PMU driver"*) ok "${pmu_line#*] }" ;;
        *) fail "unexpected PMU line: $pmu_line" "check the host CPU model exposes a PMU" ;;
    esac
fi

# --- clock --------------------------------------------------------------------
# Both ends of a latency measurement need the same clock, so target and gen are
# held to it. 900 compiles and runs virtme-ng; it never timestamps a packet.
if [ "$ROLE" = dev ]; then
    note "clock not checked on the build host: it produces no timestamped result"
else
clocksource=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)
[ "$clocksource" = tsc ] \
    && ok "clocksource tsc" \
    || fail "clocksource is $clocksource, the latency probe needs tsc" \
            "add 'clocksource=tsc tsc=reliable' to GRUB_CMDLINE_LINUX_DEFAULT, update-grub, reboot"

# Read /proc/modules rather than piping lsmod: under pipefail, grep -q exits on the
# first match and the writer dies of SIGPIPE, which would report a loaded module as
# missing.
grep -q '^ptp_kvm ' /proc/modules \
    && ok "ptp_kvm loaded" \
    || fail "ptp_kvm is not loaded" "modprobe ptp_kvm and add it to /etc/modules-load.d/lorica.conf"

ls /dev/ptp* >/dev/null 2>&1 \
    && ok "PTP device: $(ls -d /dev/ptp* | tr '\n' ' ')" \
    || fail "no /dev/ptp* device" "modprobe ptp_kvm; the host must expose kvmclock's PTP source"
fi

# --- test interface -----------------------------------------------------------
if [ "$ROLE" != dev ]; then
    [ -e "/sys/class/net/$IFACE" ] \
        || fail "interface $IFACE does not exist" "pass --iface, or add the vmbr1 NIC to the VM"

    driver=$(ethtool -i "$IFACE" | awk '/^driver:/ {print $2}')
    [ "$driver" = virtio_net ] \
        && ok "$IFACE driver virtio_net" \
        || fail "$IFACE driver is $driver, not virtio_net" \
                "an emulated e1000 silently forces XDP into generic mode: recreate the NIC as virtio"

    # Queue count is not a pass or fail: it decides whether XDP_TX takes the locked
    # path, so it is journalled and cited by the results.
    queues=$(ethtool -l "$IFACE" | awk '/^Current hardware settings:/{f=1} f && /^Combined:/{print $2; exit}')
    note "$IFACE combined queues: ${queues:-unknown}"

    # Any XDP program anywhere counts into a system-wide perf stat -e xdp:xdp_exception,
    # so a foreign one on another interface is journalled rather than ignored. On the
    # test interface it is fatal: our program could not attach, or would measure theirs.
    attached=$(sudo -n bpftool net show 2>/dev/null | sed -n '/^xdp:/,/^$/p' | sed '1d;/^$/d')
    if [ -n "$attached" ]; then
        case $attached in
            *"$IFACE"*) fail "an XDP program is already attached to $IFACE: $attached" \
                             "detach it, or pick another test interface with --iface" ;;
            *) note "foreign XDP programs on this host: $(echo "$attached" | tr -s ' \n' ' ')" ;;
        esac
    else
        ok "no XDP program attached on this host"
    fi
fi

# --- noise --------------------------------------------------------------------
if systemctl is-active --quiet irqbalance 2>/dev/null; then
    fail "irqbalance is active" \
         "systemctl disable --now irqbalance: it rewrites smp_affinity and moves IRQs onto the isolated cores"
fi
ok "irqbalance inactive"

watchdog=$(cat /proc/sys/kernel/nmi_watchdog)
[ "$watchdog" = 0 ] \
    && ok "nmi_watchdog 0" \
    || fail "nmi_watchdog is $watchdog" "scripts/bench-env.sh, or sysctl -w kernel.nmi_watchdog=0"

thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
case $thp in
    *"[never]"*) ok "transparent hugepages never" ;;
    *) fail "transparent hugepages: $thp" "scripts/bench-env.sh, or echo never > /sys/kernel/mm/transparent_hugepage/enabled" ;;
esac

if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    bad=$(grep -L performance /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
    [ -z "$bad" ] \
        && ok "governor performance on every CPU" \
        || fail "governor is not performance on: $(echo "$bad" | tr '\n' ' ')" "scripts/bench-env.sh"
    if [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        [ "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)" = 1 ] \
            && ok "turbo disabled" \
            || fail "turbo is enabled" "scripts/bench-env.sh"
    fi
else
    # Saying this out loud matters: a guest cannot pin its own frequency, so the
    # host governor is a threat to the validity of every number measured here.
    note "no cpufreq in this guest: frequency and turbo are controlled by the hypervisor, not by bench-env.sh"
fi

# --- steal time ---------------------------------------------------------------
if [ "$STEAL_SECONDS" -gt 0 ]; then
    read -r _ a1 a2 a3 a4 a5 a6 a7 steal1 _ < /proc/stat
    t1=$((a1 + a2 + a3 + a4 + a5 + a6 + a7 + steal1))
    sleep "$STEAL_SECONDS"
    read -r _ b1 b2 b3 b4 b5 b6 b7 steal2 _ < /proc/stat
    t2=$((b1 + b2 + b3 + b4 + b5 + b6 + b7 + steal2))
    # The parentheses are load-bearing: without them awk reads the > as a redirection
    # and prints nothing, which would turn an unmeasured window into a silent pass.
    pct=$(awk -v s=$((steal2 - steal1)) -v t=$((t2 - t1)) 'BEGIN {printf "%.3f", (t > 0 ? 100 * s / t : 0)}')
    [ -n "$pct" ] || fail "steal time could not be computed from /proc/stat" "report this: the field layout of /proc/stat changed"
    awk -v p="$pct" -v m="$STEAL_MAX" 'BEGIN {exit !(p <= m)}' \
        && ok "steal time ${pct}% over ${STEAL_SECONDS}s (max ${STEAL_MAX}%)" \
        || fail "steal time ${pct}% over ${STEAL_SECONDS}s exceeds ${STEAL_MAX}%" \
                "another guest is competing for the pinned cores: check --affinity on this VM and its neighbours"
else
    note "steal time not measured (--steal-seconds 0)"
fi

echo "check-env: all controls passed"
