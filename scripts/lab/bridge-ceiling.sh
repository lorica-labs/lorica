#!/usr/bin/env bash
# The ceiling of the measurement tool itself. Ramps the offered UDP rate until
# the received rate stops following it, and records the knee. Above it the number
# describes the Linux bridge and vhost-net, not anything attached to the target,
# so this knee bounds every attack axis in the phase.
#
#   bridge-ceiling.sh --out DIR --gen-host SSH --dst-ip IP
#                     [--dev NAME] [--gen-dev NAME] [--rates "r1 r2 ..."]
#                     [--seconds N] [--repeat N]
#
# Runs on VM 901 (the receiver). It drives VM 902 over SSH to send. The target
# drops in XDP so the received count is what the transport delivered, not what
# the guest stack survived.

set -uo pipefail

OUT=bench/results/bridge-ceiling
DEV=${CARAPACE_IFACE:-enp6s19}
GEN_DEV=${CARAPACE_GEN_IFACE:-enp6s19}
GEN_HOST=lab-target       # placeholder, must be overridden with the gen host
DST_IP=
RATES="100kpps 250kpps 500kpps 750kpps 1Mpps 1500kpps 2Mpps 3Mpps"
SECONDS_PER=5
REPEAT=3
OBJ=bench/progs/xdp_drop.o

while [ $# -gt 0 ]; do
    case $1 in
        --out)      OUT=$2; shift 2 ;;
        --dev)      DEV=$2; shift 2 ;;
        --gen-dev)  GEN_DEV=$2; shift 2 ;;
        --gen-host) GEN_HOST=$2; shift 2 ;;
        --dst-ip)   DST_IP=$2; shift 2 ;;
        --rates)    RATES=$2; shift 2 ;;
        --seconds)  SECONDS_PER=$2; shift 2 ;;
        --repeat)   REPEAT=$2; shift 2 ;;
        --obj)      OBJ=$2; shift 2 ;;
        -h|--help)  sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$DST_IP" ] || { echo "bridge-ceiling: --dst-ip is required (this receiver's test address)" >&2; exit 2; }
[ -r "$OBJ" ] || { echo "bridge-ceiling: no $OBJ" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT" "$DEV")
[ -n "$env_file" ] || { echo "bridge-ceiling: capture-env produced no path" >&2; exit 2; }
csv="$OUT/bridge-ceiling.csv"
echo "offered_rate,offered_pps,received_pps,delivery_ratio,vhost_cpu_pct_host" > "$csv"

# Attach the dropper natively. If it lands in generic mode the whole ramp is
# invalid, so refuse rather than produce a lower ceiling than the machine has.
sudo -n ip link set dev "$DEV" xdpdrv obj "$OBJ" sec xdp || { echo "bridge-ceiling: native attach failed" >&2; exit 1; }
trap 'sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null' EXIT
mode=$(ip -d link show "$DEV" | grep -o 'xdp[a-z]*' | head -1)
[ "$mode" = xdp ] || { echo "bridge-ceiling: attach mode is $mode, not native xdp" >&2; exit 1; }

# Statistics counters survive an attach; the raw delta over the window is what
# matters, so a baseline is taken immediately before each burst.
rx_packets() { cat "/sys/class/net/$DEV/statistics/rx_packets"; }

# vhost-net runs on the hypervisor and its cost is not in any guest counter.
# Measured on the host if reachable, left blank and flagged in the report if not.
vhost_cpu() {
    if command -v ssh >/dev/null && [ -n "${CARAPACE_PVE_HOST:-}" ]; then
        ssh -o BatchMode=yes "$CARAPACE_PVE_HOST" \
            "top -bn1 | awk '/vhost/ {s+=\$9} END {print s+0}'" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

as_pps() {
    case $1 in
        *kpps) echo $(( ${1%kpps} * 1000 )) ;;
        *Mpps) echo $(( ${1%Mpps} * 1000000 )) ;;
        *pps)  echo "${1%pps}" ;;
        *)     echo "$1" ;;
    esac
}

# The dropper swallows inbound ARP too, so the generator can no longer resolve
# this host once it is attached. Pass our own MAC explicitly instead of relying
# on the sender's neighbour table.
dst_mac=$(cat "/sys/class/net/$DEV/address")

best_ratio_rate=0
for rate in $RATES; do
    offered=$(as_pps "$rate")
    recv_samples=()
    for _ in $(seq "$REPEAT"); do
        before=$(rx_packets)
        # gen-udp-flood.sh builds its own trafgen config on the sender from the
        # target address; it is deployed on the gen host under ~/carapace.
        ssh -o BatchMode=yes "$GEN_HOST" \
            "~/carapace/scripts/lab/gen-udp-flood.sh --dev '$GEN_DEV' --dst-ip '$DST_IP' --dst-mac '$dst_mac' --rate ${offered}pps --duration ${SECONDS_PER}s --cpus 2" \
            >/dev/null 2>&1 &
        gen_pid=$!
        sleep "$SECONDS_PER"
        after=$(rx_packets)
        wait "$gen_pid" 2>/dev/null || true
        recv_samples+=( $(( (after - before) / SECONDS_PER )) )
    done
    received=$(printf '%s\n' "${recv_samples[@]}" | sort -n | awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}')
    vhost=$(vhost_cpu)
    ratio=$(awk -v r="$received" -v o="$offered" 'BEGIN {printf "%.3f", (o>0 ? r/o : 0)}')
    echo "$rate,$offered,$received,$ratio,$vhost" | tee -a "$csv"
    awk -v r="$ratio" 'BEGIN {exit !(r >= 0.95)}' && best_ratio_rate=$offered
done

echo "bridge-ceiling: last rate delivered at >=95% was $best_ratio_rate pps" | tee "$OUT/knee.txt"
echo "$csv"
