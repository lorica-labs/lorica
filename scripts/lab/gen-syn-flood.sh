#!/usr/bin/env bash
# TCP SYN flood with varied source ports and addresses. Feeds T8: the target
# reflects SYNs with xdp_reflect, and this is what saturates it.
#
#   gen-syn-flood.sh --dst-ip IP --dst-port PORT [--dst-mac MAC] [--dev NAME]
#                    [--rate PPS] [--num N] [--duration S] [--cpus N]
#
# Runs on VM 902.

set -uo pipefail

DEV=${LORICA_IFACE:-enp6s19}
DST_IP=
DST_PORT=
DST_MAC=
RATE=
NUM=0
DURATION=
CPUS=1

while [ $# -gt 0 ]; do
    case $1 in
        --dev)      DEV=$2; shift 2 ;;
        --dst-ip)   DST_IP=$2; shift 2 ;;
        --dst-port) DST_PORT=$2; shift 2 ;;
        --dst-mac)  DST_MAC=$2; shift 2 ;;
        --rate)     RATE=$2; shift 2 ;;
        --num)      NUM=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --cpus)     CPUS=$2; shift 2 ;;
        -h|--help)  sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$DST_IP" ] || { echo "gen-syn-flood: --dst-ip is required" >&2; exit 2; }
[ -n "$DST_PORT" ] || { echo "gen-syn-flood: --dst-port is required" >&2; exit 2; }
[ -n "$DST_MAC" ] || DST_MAC=$(ip neigh show "$DST_IP" dev "$DEV" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1); exit}}')
[ -n "$DST_MAC" ] || { echo "gen-syn-flood: no MAC for $DST_IP, pass --dst-mac" >&2; exit 2; }

src_mac=$(cat "/sys/class/net/$DEV/address")
IFS=. read -r d1 d2 d3 d4 <<EOF
$DST_IP
EOF
dport_hi=$(( DST_PORT >> 8 )); dport_lo=$(( DST_PORT & 0xff ))

conf=$(mktemp --suffix=.trafgen)
trap 'rm -f "$conf"' EXIT

# 40-byte SYN: IPv4 (20) + TCP (20), SYN flag set, no options. Source address and
# port randomised so the reflected SYN-ACKs do not all collapse onto one flow.
cat > "$conf" <<EOF
{
  $(printf '0x%s, ' $(echo "$DST_MAC" | tr 'a-f' 'A-F' | tr ':' ' '))
  $(printf '0x%s, ' $(echo "$src_mac" | tr 'a-f' 'A-F' | tr ':' ' '))
  const16(0x0800),
  0x45, 0, const16(40),
  const16(0x0000), const16(0x4000),
  64, 6, const16(0),
  10, 90, drnd(1), drnd(1),
  $d1, $d2, $d3, $d4,
  drnd(2), $dport_hi, $dport_lo,
  drnd(4),
  const32(0),
  0x50, 0x02, const16(0x7210),
  const16(0), const16(0)
}
EOF

cmd=(trafgen --dev "$DEV" --conf "$conf" --cpus "$CPUS" --no-sock-mem)
# The unit is not optional, and leaving it off does not mean packets per second: trafgen
# answers `Invalid unit type for rate` and exits. That refusal was invisible here for two
# campaigns because the caller starts this detached and never reads its status, so the flood
# simply never happened and every phase downstream measured an idle link. A rate that already
# carries a unit is passed through, so `--rate 10Mbps` still works.
if [ -n "$RATE" ]; then
    case $RATE in
        *[!0-9]*) cmd+=(--rate "$RATE") ;;
        *)        cmd+=(--rate "${RATE}pps") ;;
    esac
fi
[ "$NUM" != 0 ] && cmd+=(--num "$NUM")

# `--duration` is not a trafgen option on this version -- it answers `unrecognized option` and
# exits -- so the bound is `timeout` around it. A killed run exits 124, which is this script
# succeeding at exactly what it was asked to do, so it is translated rather than propagated.
echo "gen-syn-flood: dev=$DEV dst=$DST_IP:$DST_PORT rate=${RATE:-max} cpus=$CPUS duration=${DURATION:-unbounded}" >&2
if [ -n "$DURATION" ]; then
    sudo -n timeout --signal=INT "${DURATION}s" "${cmd[@]}"
    code=$?
    [ "$code" -eq 124 ] && exit 0
    exit "$code"
fi
exec sudo -n "${cmd[@]}"
