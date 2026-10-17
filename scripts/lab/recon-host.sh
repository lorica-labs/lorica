#!/bin/sh
# Reconnaissance of a rented bare-metal host, before committing to it as a bench machine.
#
# Run this on a freshly provisioned server, read the verdict, destroy the server. The whole
# point is that hourly billing makes this cost about 0.50 EUR, and no provider documents the
# one thing that decides everything: which NIC is actually in the box.
#
# What matters, in order:
#   1. mlx5 (ConnectX) means DPDK needs no vfio-pci and no IOMMU -- the kernel keeps the
#      interface, so TRex cannot lock us out of SSH. Intel works but must be unbound.
#   2. A physical function, not an SR-IOV VF: a VF has no say over RSS or queue count, and
#      XDP_TX/XDP_REDIRECT may simply be missing.
#   3. Native XDP on the driver, not the generic fallback -- generic runs after skb
#      allocation and measures 2-4 Mpps instead of 24, which reads as "our program is slow".
#   4. Two separate NICs (public + private) so the flood never touches the public link.
#
# Read-only. Everything here is a query; nothing is configured or attached.

set -u

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
head_() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

VERDICT_NIC=fail
VERDICT_XDP=unknown
VERDICT_SEP=fail

head_ "Host"
info "$(uname -srm)"
info "$(sed -n 's/^model name[ \t]*: //p' /proc/cpuinfo | head -1)"
info "$(nproc) logical CPUs, $(lscpu 2>/dev/null | sed -n 's/^NUMA node(s): *//p') NUMA node(s)"
info "RAM $(awk '/MemTotal/{printf "%.0f GiB", $2/1048576}' /proc/meminfo)"

# TRex allocates its packet pools out of DRAM and its own docs are explicit that fewer than
# four populated channels costs both latency and throughput on the generator.
if command -v dmidecode >/dev/null 2>&1; then
    chans=$(dmidecode -t memory 2>/dev/null | grep -c 'Size: [0-9]')
    [ "${chans:-0}" -ge 4 ] && pass "populated DIMMs: $chans (>= 4, good for TRex)" \
                            || warn "populated DIMMs: ${chans:-?} (TRex wants >= 4 channels)"
else
    info "dmidecode absent: cannot count memory channels"
fi

head_ "Ethernet controllers"
lspci -nn 2>/dev/null | grep -i ethernet | while read -r l; do info "$l"; done

# The driver name is the verdict. mlx5_core is the one we want; the *vf drivers are the
# disqualifying answer.
head_ "Per-interface driver, link and XDP"
nic_count=0
for d in /sys/class/net/*; do
    ifn=$(basename "$d")
    case "$ifn" in lo|docker*|veth*|virbr*|bond*|dummy*) continue ;; esac
    [ -e "$d/device" ] || continue          # skip anything not backed by real hardware
    nic_count=$((nic_count + 1))

    drv=$(basename "$(readlink -f "$d/device/driver" 2>/dev/null)" 2>/dev/null)
    spd=$(cat "$d/speed" 2>/dev/null || echo '?')
    mac=$(cat "$d/address" 2>/dev/null)
    printf '\n  [%s] driver=%s speed=%sMb/s mac=%s\n' "$ifn" "${drv:-?}" "$spd" "$mac"

    case "$drv" in
        mlx5_core)
            pass "$ifn: Mellanox ConnectX -- bifurcated driver, no vfio-pci needed"
            VERDICT_NIC=pass ;;
        i40e|ice|ixgbe)
            [ "$VERDICT_NIC" = pass ] || VERDICT_NIC=warn
            warn "$ifn: Intel $drv -- native XDP fine, but TRex needs vfio-pci + IOMMU here"
            [ "$drv" = ice ] && warn "$ifn: E810/ice is broken with TRex (trex-core #672/#1136/#1205) -- not as generator" ;;
        bnxt_en)
            [ "$VERDICT_NIC" = pass ] || VERDICT_NIC=warn
            warn "$ifn: Broadcom -- native XDP yes, but TRex DPDK support is fragile" ;;
        iavf|ixgbevf|i40evf)
            fail "$ifn: SR-IOV virtual function -- no RSS control, XDP_TX may be missing" ;;
        virtio_net)
            fail "$ifn: virtio -- this is not bare metal networking, walk away" ;;
        igb|e1000e|r8169)
            fail "$ifn: 1G-class NIC ($drv) -- cannot carry a 10G bench" ;;
        *)
            warn "$ifn: unrecognised driver '${drv:-none}' -- check by hand" ;;
    esac

    # An SR-IOV physical function advertises the SR-IOV capability; a VF does not.
    slot=$(basename "$(readlink -f "$d/device" 2>/dev/null)" 2>/dev/null)
    if [ -n "${slot:-}" ] && command -v lspci >/dev/null 2>&1; then
        if lspci -vv -s "$slot" 2>/dev/null | grep -q 'SR-IOV'; then
            pass "$ifn: physical function (SR-IOV capability present)"
        elif [ -e "$d/device/physfn" ]; then
            fail "$ifn: this is a VIRTUAL function (physfn link exists)"
        else
            info "$ifn: no SR-IOV capability advertised (likely a plain PF)"
        fi
    fi

    if command -v ethtool >/dev/null 2>&1; then
        ethtool -i "$ifn" 2>/dev/null | sed -n 's/^/        /; /version\|firmware\|bus-info/p'
        info "channels: $(ethtool -l "$ifn" 2>/dev/null | awk '/^Combined/{c=$2} END{print c}') combined (max)"
    fi

    # xdp-loader reports what the driver really advertises. Without it, the honest answer is
    # "unknown" -- never assume native XDP from the driver name alone.
    if command -v xdp-loader >/dev/null 2>&1; then
        feats=$(xdp-loader features "$ifn" 2>/dev/null)
        if printf '%s' "$feats" | grep -q 'NETDEV_XDP_ACT_NDO_XMIT'; then
            pass "$ifn: native XDP with ndo_xmit (XDP_REDIRECT target capable)"
            VERDICT_XDP=pass
        elif printf '%s' "$feats" | grep -q 'NETDEV_XDP_ACT_BASIC'; then
            pass "$ifn: native XDP (basic)"
            [ "$VERDICT_XDP" = pass ] || VERDICT_XDP=basic
        else
            warn "$ifn: xdp-loader reports no native XDP action"
        fi
    fi
done

head_ "Public / private separation"
if [ "$nic_count" -ge 2 ]; then
    pass "$nic_count hardware interfaces -- flood the private one, keep SSH on the other"
    VERDICT_SEP=pass
else
    warn "single hardware interface -- SSH shares the link you are about to saturate."
    warn "Workable only with out-of-band KVM/IPMI. Confirm the console works BEFORE testing."
fi

head_ "Knobs needed to freeze the machine for measurement"
[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ] \
    && pass "intel_pstate/no_turbo writable (turbo can be frozen)" \
    || warn "no_turbo not available -- cycles/packet will drift with frequency"
if [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    info "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
else
    warn "no cpufreq sysfs -- cannot pin the frequency"
fi
[ -d /sys/kernel/mm/hugepages ] && pass "hugepages sysfs present (TRex allocates its own)" \
                                || warn "no hugepages sysfs"
if [ -d /sys/class/iommu ] && [ -n "$(ls -A /sys/class/iommu 2>/dev/null)" ]; then
    pass "IOMMU active -- vfio-pci usable if the NIC turns out to be Intel"
else
    warn "IOMMU inactive -- with an Intel NIC, TRex would need a kernel cmdline change + reboot"
fi
info "idle states: $(ls /sys/devices/system/cpu/cpu0/cpuidle 2>/dev/null | tr '\n' ' ')"
grep -q . /proc/cmdline && info "cmdline: $(cat /proc/cmdline)"

head_ "VERDICT"
case "$VERDICT_NIC" in
    pass) pass "NIC: ConnectX present. This host is a keeper." ;;
    warn) warn "NIC: usable but not ideal -- see the per-interface lines above." ;;
    *)    fail "NIC: unsuitable. Destroy this server and try another region or plan." ;;
esac
case "$VERDICT_XDP" in
    pass|basic) pass "XDP: native support confirmed by the driver itself." ;;
    *)          warn "XDP: unconfirmed. Install xdp-tools and re-run before trusting this host." ;;
esac
[ "$VERDICT_SEP" = pass ] && pass "Links: public and private are separate interfaces." \
                          || warn "Links: single interface -- verify out-of-band console first."
printf '\nKeep this output. It is the provenance of every number the bench will produce.\n'
