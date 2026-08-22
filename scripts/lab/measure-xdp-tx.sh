#!/usr/bin/env bash
# The XDP_TX ceiling of virtio: how many packets a program can reflect back out
# the interface they arrived on. Without spare queues XDP_TX drops into a slower
# locked tx mode, and this rate may be the real bottleneck of the SYN cookie
# module before any hashing. Decides whether that module targets a VPS or only a
# gateway.
#
#   measure-xdp-tx.sh --gen-host SSH --self-ip IP --out DIR
#                     [--seconds N] [--repeat N] [--iface NAME] [--obj PATH]
#
# Runs on VM 901. The reflect program is attached here; the flood comes from 902.
# Reflected packets are counted at both ends: tx on 901 and rx back on 902.

set -uo pipefail

OUT=bench/results/xdp-tx
DEV=${CARAPACE_IFACE:-enp6s19}
GEN_HOST=lab-gen
SELF_IP=
SECONDS_PER=10
REPEAT=3
OBJ=bench/progs/xdp_reflect.o
FLOOD_PORT=19000

while [ $# -gt 0 ]; do
    case $1 in
        --out)      OUT=$2; shift 2 ;;
        --iface)    DEV=$2; shift 2 ;;
        --gen-host) GEN_HOST=$2; shift 2 ;;
        --self-ip)  SELF_IP=$2; shift 2 ;;
        --seconds)  SECONDS_PER=$2; shift 2 ;;
        --repeat)   REPEAT=$2; shift 2 ;;
        --obj)      OBJ=$2; shift 2 ;;
        -h|--help)  sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$SELF_IP" ] || { echo "measure-xdp-tx: --self-ip is required" >&2; exit 2; }
[ -r "$OBJ" ] || { echo "measure-xdp-tx: no $OBJ" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT" "$DEV")
[ -n "$env_file" ] || { echo "measure-xdp-tx: capture-env produced no path" >&2; exit 2; }

self_mac=$(cat "/sys/class/net/$DEV/address")
queues_now=$(ethtool -l "$DEV" | awk '/^Current/{f=1} f&&/^Combined:/{print $2; exit}')

cleanup() {
    sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null
    ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x trafgen 2>/dev/null' 2>/dev/null
}
trap cleanup EXIT

tx_packets() { cat "/sys/class/net/$DEV/statistics/tx_packets"; }
rx_packets() { cat "/sys/class/net/$DEV/statistics/rx_packets"; }

# received_pps  = what the reflector was fed (901 rx delta, reliable, as in T4)
# reflected_pps = what XDP_TX sent back (901 tx delta)
# The offered rate is not read from the sender: trafgen's zero-copy path does not
# increment the netdev tx counter, so a sender-side figure would understate it.
csv="$OUT/xdp-tx.csv"
echo "queues,rep,received_pps,reflected_pps,reflected_ratio" > "$csv"

measure_at_queues() {
    local q=$1
    # Detach first: virtio refuses to change the channel count while an XDP program
    # is attached, so a leftover attach makes ethtool -L fail for the wrong reason.
    sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null
    sudo -n ethtool -L "$DEV" combined "$q" 2>/dev/null || { echo "measure-xdp-tx: cannot set $q queues" >&2; return 1; }
    sudo -n ip link set dev "$DEV" xdpdrv obj "$OBJ" sec xdp || { echo "measure-xdp-tx: attach failed at $q queues" >&2; return 1; }
    [ "$(ip -d link show "$DEV" | grep -o 'xdp[a-z]*' | head -1)" = xdp ] \
        || { echo "measure-xdp-tx: attach not native at $q queues" >&2; return 1; }

    for rep in $(seq "$REPEAT"); do
        local tx0 tx1 rx0 rx1
        tx0=$(tx_packets); rx0=$(rx_packets)
        # Paced flood, not open: trafgen with no rate overruns its TX ring and
        # flushes almost nothing. 400 kpps is above the ~295 kpps the sender can
        # actually reach (00-plafond-outil.md), so trafgen sends flat out; the
        # duration covers the whole measurement window with margin. A wall-clock
        # timeout caps it so a slow rep cannot bleed into the next.
        local flood_secs=$(( SECONDS_PER + 5 ))
        ssh -o BatchMode=yes "$GEN_HOST" \
            "timeout -s INT $(( flood_secs + 3 ))s ~/carapace/scripts/lab/gen-udp-flood.sh --dst-ip $SELF_IP --dst-mac $self_mac --rate 400000pps --duration ${flood_secs}s --cpus 2 >/dev/null 2>&1" &
        local gen_pid=$!
        sleep 2   # let the flood ramp before the measurement window opens
        tx0=$(tx_packets); rx0=$(rx_packets)
        sleep "$SECONDS_PER"
        tx1=$(tx_packets); rx1=$(rx_packets)
        wait "$gen_pid" 2>/dev/null || true
        local received=$(( (rx1 - rx0) / SECONDS_PER ))
        local reflected=$(( (tx1 - tx0) / SECONDS_PER ))
        local ratio; ratio=$(awk -v r="$reflected" -v g="$received" 'BEGIN {printf "%.3f", (g>0 ? r/g : 0)}')
        echo "$q,$rep,$received,$reflected,$ratio" | tee -a "$csv"
    done

    sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null
}

measure_at_queues 1
measure_at_queues 4

# Restore the runbook default queue count.
sudo -n ethtool -L "$DEV" combined "${queues_now:-4}" 2>/dev/null || true

echo "$csv"
