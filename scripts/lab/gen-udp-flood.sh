#!/usr/bin/env bash
# 64-byte UDP flood with varied source ports and addresses, at a set rate.
# Source variation matters for an anti-DDoS: a single-flow flood is steered to
# one RSS queue and measures nothing about the multi-queue path.
#
#   gen-udp-flood.sh --dst-ip IP [--dst-mac MAC] [--dev NAME] [--rate PPS]
#                    [--num N] [--duration S] [--cpus N]
#
# Runs on VM 902. Rate is best-effort: trafgen approximates the inter-packet gap,
# and the receiver counts what actually arrived.

set -uo pipefail

DEV=${CARAPACE_IFACE:-enp6s19}
DST_IP=
DST_MAC=
RATE=
NUM=0
DURATION=
CPUS=1

while [ $# -gt 0 ]; do
    case $1 in
        --dev)      DEV=$2; shift 2 ;;
        --dst-ip)   DST_IP=$2; shift 2 ;;
        --dst-mac)  DST_MAC=$2; shift 2 ;;
        --rate)     RATE=$2; shift 2 ;;
        --num)      NUM=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --cpus)     CPUS=$2; shift 2 ;;
        -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$DST_IP" ] || { echo "gen-udp-flood: --dst-ip is required" >&2; exit 2; }
[ -n "$DST_MAC" ] || DST_MAC=$(ip neigh show "$DST_IP" dev "$DEV" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1); exit}}')
[ -n "$DST_MAC" ] || { echo "gen-udp-flood: no MAC for $DST_IP, pass --dst-mac (ping it first to populate the neighbour table)" >&2; exit 2; }

src_mac=$(cat "/sys/class/net/$DEV/address")
IFS=. read -r d1 d2 d3 d4 <<EOF
$DST_IP
EOF

conf=$(mktemp --suffix=.trafgen)
trap 'rm -f "$conf"' EXIT

mac_bytes() { echo "$1" | tr ':' ' ' | tr 'a-f' 'A-F' | sed 's/\([0-9A-F][0-9A-F]\)/0x\1,/g'; }

# 60-byte L2 frame (64 on the wire with FCS). drnd randomises the two low source
# address octets and the whole source port, so the flood spreads across RSS
# queues and the hash-collision surface the product cares about. The IPv4 and UDP
# checksums are left zero: the receiver drops in XDP before the stack verifies
# either, so computing them would only slow the generator.
cat > "$conf" <<EOF
{
  $(mac_bytes "$DST_MAC")
  $(mac_bytes "$src_mac")
  const16(0x0800),
  0x45, 0, const16(46),
  const16(0x0000), const16(0x4000),
  64, 17, const16(0),
  10, 90, drnd(1), drnd(1),
  $d1, $d2, $d3, $d4,
  drnd(2), const16(19000), const16(26), const16(0),
  fill(0x00, 18)
}
EOF

# trafgen 0.6.8 has no --duration; a wall-clock run is a packet count at the
# offered rate. Without a rate there is no count to derive, so the caller must
# either bound the run with --num or accept an open-ended --rate max flood.
num=$NUM
if [ "$num" = 0 ] && [ -n "$DURATION" ] && [ -n "$RATE" ]; then
    secs=${DURATION%s}
    pps=$(printf '%s' "$RATE" | sed -E 's/pps$//; s/kpps$/000/; s/Mpps$/000000/')
    num=$(( pps * secs ))
fi

cmd=(trafgen --dev "$DEV" --conf "$conf" --cpus "$CPUS" --no-sock-mem)
[ -n "$RATE" ] && cmd+=(--rate "$RATE")
[ "$num" != 0 ] && cmd+=(--num "$num")

echo "gen-udp-flood: dev=$DEV dst=$DST_IP/$DST_MAC rate=${RATE:-max} cpus=$CPUS num=${num:-open}" >&2
exec sudo -n "${cmd[@]}"
