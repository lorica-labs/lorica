#!/bin/sh
# Does the private fabric carry small packets, or only big ones?
#
# An iperf3 run that reports line rate proves almost nothing for this project: TCP at 1500 bytes
# reaches 9.4 Gbit/s with roughly 760 kpps, while the bench needs 14.88 Mpps for the same number
# of bits. Providers size private links in Gbps and sometimes police them in pps, so the two
# numbers have to be measured separately -- and this is the cheap one.
#
# pktgen is used rather than TRex or xdp-trafficgen because it is in every stock kernel: no DPDK,
# no hugepages, no vfio-pci binding, and no recent BPF feature to probe for. A few Mpps is all
# that is needed to expose a policer; saturating the link is TRex's job later.
#
# Two things this script learned the hard way on a Latitude.sh private VLAN:
#   - The private network is 802.1Q tagged (vlan.2050@eno2). pktgen must be pointed at the
#     PHYSICAL device and told to insert the tag itself: the vlan netdev has numtxqueues 1, so
#     generating on it caps the whole probe at a single queue.
#   - Threads sharing a device all default to queue_map 0 and then fight over one TX ring. Each
#     thread needs its own queue, or four threads perform like a third of one.
#
# Run on the GENERATOR. Read the receive side on the DUT at the same time:
#     sar -n DEV 1 25 | grep <private-iface>
#
# Usage: pps-probe.sh <phys-iface> <dst-mac> <dst-ip> [threads] [seconds] [vlan-id]

set -eu

IFACE=${1:?usage: pps-probe.sh <phys-iface> <dst-mac> <dst-ip> [threads] [seconds] [vlan-id]}
DST_MAC=${2:?missing destination MAC (the DUT private interface)}
DST_IP=${3:?missing destination IP (the DUT private address)}
THREADS=${4:-4}
SECONDS_RUN=${5:-20}
VLAN_ID=${6:-}

PG=/proc/net/pktgen

# Refuse to blast a link that carries the public address: on a rented box that is the SSH path,
# and providers null-route floods on their public side.
if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q 'inet ' ; then
    addr=$(ip -4 -br addr show dev "$IFACE" | awk '{print $3}')
    case "$addr" in
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) : ;;
        *) echo "REFUSING: $IFACE carries a public address ($addr). Use the private interface." >&2
           exit 1 ;;
    esac
fi

# A tagged private link is easy to miss: the IP sits on the vlan netdev, so the physical device
# looks unconfigured and untagged frames leave the host only to be dropped by the switch.
if [ -z "$VLAN_ID" ]; then
    guess=$(ip -d link show 2>/dev/null | awk -v i="$IFACE" '
        $0 ~ "@"i":" {name=$2}
        /vlan protocol 802.1Q id/ {for (n=1; n<=NF; n++) if ($n=="id") {print $(n+1); exit}}')
    if [ -n "${guess:-}" ]; then
        echo "NOTE: $IFACE carries VLAN $guess. Sending untagged would be silently dropped." >&2
        echo "      Re-run with '$guess' as the 6th argument, or pass '-' to force untagged." >&2
        exit 1
    fi
fi
[ "$VLAN_ID" = "-" ] && VLAN_ID=""

modprobe pktgen 2>/dev/null || true
[ -d "$PG" ] || { echo "pktgen not available (no $PG)" >&2; exit 1; }

cleanup() { echo "stop" > "$PG/pgctrl" 2>/dev/null || true; }
trap cleanup INT TERM EXIT

echo "reset" > "$PG/pgctrl"

i=0
while [ "$i" -lt "$THREADS" ]; do
    thread="$PG/kpktgend_$i"
    [ -e "$thread" ] || { echo "no $thread (fewer CPUs than threads asked)" >&2; break; }
    dev="$IFACE@$i"

    echo "rem_device_all" > "$thread"
    echo "add_device $dev" > "$thread"

    cfg="$PG/$dev"
    echo "count 0"          > "$cfg"   # 0 = run until stopped
    echo "clone_skb 1000"   > "$cfg"   # reuse the skb: this is what makes pktgen fast
    echo "pkt_size 60"      > "$cfg"   # 60 + 4 bytes FCS = the 64-byte frame that matters
    echo "delay 0"          > "$cfg"
    echo "dst $DST_IP"      > "$cfg"
    echo "dst_mac $DST_MAC" > "$cfg"
    # One TX ring per thread. Without this every thread lands on queue 0 and they serialise.
    echo "queue_map_min $i" > "$cfg"
    echo "queue_map_max $i" > "$cfg"
    [ -n "$VLAN_ID" ] && echo "vlan_id $VLAN_ID" > "$cfg"

    i=$((i + 1))
done

printf 'pktgen: %s thread(s) on %s -> %s (%s)%s, 64-byte frames, %ss\n' \
       "$i" "$IFACE" "$DST_IP" "$DST_MAC" \
       "$([ -n "$VLAN_ID" ] && printf ' vlan %s' "$VLAN_ID")" "$SECONDS_RUN"
printf 'watch the DUT now:  sar -n DEV 1 %s | grep <iface>\n\n' "$((SECONDS_RUN + 5))"

echo "start" > "$PG/pgctrl" &
START_PID=$!
sleep "$SECONDS_RUN"
echo "stop" > "$PG/pgctrl" 2>/dev/null || true
wait "$START_PID" 2>/dev/null || true
trap - INT TERM EXIT

total=0
i=0
while [ "$i" -lt "$THREADS" ]; do
    cfg="$PG/$IFACE@$i"
    [ -e "$cfg" ] || break
    pps=$(sed -n 's/.*[^0-9]\([0-9]\{1,\}\)pps.*/\1/p' "$cfg" | tail -1)
    if [ -n "${pps:-}" ]; then
        printf '  thread %s: %s pps\n' "$i" "$pps"
        total=$((total + pps))
    fi
    i=$((i + 1))
done

printf '\n  TOTAL SENT: %s pps (%s Mpps)\n' \
       "$total" "$(awk -v t="$total" 'BEGIN{printf "%.2f", t/1000000}')"
printf '\nCompare against what the DUT actually received.\n'
printf 'Sent >> received means a pps policer or an oversubscribed fabric between the two hosts.\n'
