#!/usr/bin/env bash
# The window a hot XDP attach opens in a live flow. virtnet_xdp_set() calls
# napi_disable() on every RX and TX queue and reconfigures the queue pairs, so
# attaching under traffic can stall the path — at the worst moment, the start of
# an attack. This decides whether an "armed but detached" mode can exist.
#
#   measure-hot-attach.sh --gen-host SSH --self-ip IP --out DIR
#                         [--repeat N] [--iface NAME] [--obj PATH]
#
# Runs on VM 901. Under real traffic (iperf3 + a gap-detecting probe from 902),
# it attaches then detaches xdp_pass repeatedly, and records the distribution of
# outage durations, never a mean.

set -uo pipefail

OUT=bench/results/hot-attach
DEV=${CARAPACE_IFACE:-enp6s19}
GEN_HOST=lab-gen
SELF_IP=
PEER_IP=
REPEAT=10
OBJ=bench/progs/xdp_pass.o
PROBE=${CARAPACE_PROBE:-/tmp/latency-probe}
SETTLE=2

while [ $# -gt 0 ]; do
    case $1 in
        --out)      OUT=$2; shift 2 ;;
        --iface)    DEV=$2; shift 2 ;;
        --gen-host) GEN_HOST=$2; shift 2 ;;
        --self-ip)  SELF_IP=$2; shift 2 ;;
        --peer-ip)  PEER_IP=$2; shift 2 ;;
        --repeat)   REPEAT=$2; shift 2 ;;
        --obj)      OBJ=$2; shift 2 ;;
        --probe)    PROBE=$2; shift 2 ;;
        -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$SELF_IP" ] && [ -n "$PEER_IP" ] || { echo "measure-hot-attach: --self-ip and --peer-ip are required" >&2; exit 2; }
[ -r "$OBJ" ] || { echo "measure-hot-attach: no $OBJ" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT" "$DEV")
[ -n "$env_file" ] || { echo "measure-hot-attach: capture-env produced no path" >&2; exit 2; }
csv="$OUT/hot-attach.csv"
echo "cycle,event,gap_ns,gap_closed,tcp_retrans_delta" > "$csv"

# The remote probe must be allowed to finish and write its CSV before anything is
# killed; the fetch below waits for it, so cleanup only reaps stragglers.
probe_done=0
cleanup() {
    sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null
    [ "$probe_done" = 0 ] && ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x latency-probe 2>/dev/null' 2>/dev/null
    ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x iperf3 2>/dev/null' 2>/dev/null
    pkill -x latency-probe 2>/dev/null
}
trap cleanup EXIT

sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null

# The attach loop is REPEAT cycles of two settle periods, plus one leading settle.
# The probe must outlast that but not by so much that the results wait is long.
loop_seconds=$(( REPEAT * 2 * SETTLE + SETTLE ))
run_seconds=$(( loop_seconds + 4 ))

# udp-echo server here; the gap-detecting probe runs from 902 against it. iperf3
# on 902 provides the bulk flow whose retransmissions we watch.
pkill -x latency-probe 2>/dev/null
setsid nohup "$PROBE" serve --profile udp-echo --bind "$SELF_IP:19002" >/tmp/hot-attach-srv.log 2>&1 < /dev/null &
srv=$!
ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x iperf3 2>/dev/null; sleep 0.3; setsid nohup iperf3 -s >/dev/null 2>&1 < /dev/null &' >/dev/null 2>&1
sleep 1
ss -ulnp 2>/dev/null | grep -q ":19002" || { echo "measure-hot-attach: udp-echo server not listening on $SELF_IP:19002" >&2; cat /tmp/hot-attach-srv.log >&2; exit 1; }

# Bulk flow 901 -> 902 for the whole run; retransmissions are read from ss on 901.
setsid nohup iperf3 -c "$PEER_IP" -t "$run_seconds" >/dev/null 2>&1 < /dev/null &

# The gap-detecting probe runs on 902 for the whole window and writes its gaps.
# 2000 pps gives a 1.5 ms gap threshold (3 send intervals), fine enough to resolve
# a napi_disable stall that a 45 pps profile would miss inside its 66 ms interval.
ssh -o BatchMode=yes "$GEN_HOST" \
    "setsid nohup $PROBE load --profile udp-echo --target $SELF_IP:19002 --rate 2000 --duration $run_seconds --out /tmp/hot-attach --gap-detect >/tmp/hot-attach.log 2>&1 < /dev/null & echo started" \
    >/dev/null 2>&1

retrans() { ss -ti 2>/dev/null | grep -oE 'retrans:[0-9]+/[0-9]+' | awk -F'[:/]' '{s+=$3} END {print s+0}'; }

sleep "$SETTLE"
for c in $(seq "$REPEAT"); do
    r0=$(retrans)
    sudo -n ip link set dev "$DEV" xdpdrv obj "$OBJ" sec xdp
    sleep "$SETTLE"
    r1=$(retrans)
    echo "$c,attach,,,$(( r1 - r0 ))" | tee -a "$csv"

    r0=$(retrans)
    sudo -n ip link set dev "$DEV" xdpdrv off
    sleep "$SETTLE"
    r1=$(retrans)
    echo "$c,detach,,,$(( r1 - r0 ))" | tee -a "$csv"
done

# Wait for the probe to finish and write its summary before touching anything.
# Gaps are timestamped from run start; all are recorded rather than matched to a
# cycle, since the distribution is the result.
for _ in $(seq 20); do
    ssh -o BatchMode=yes "$GEN_HOST" 'test -f /tmp/hot-attach/udp-echo-summary.csv' 2>/dev/null && break
    sleep 1
done
probe_done=1
kill "$srv" 2>/dev/null
summary=$(ssh -o BatchMode=yes "$GEN_HOST" 'cat /tmp/hot-attach/udp-echo-summary.csv 2>/dev/null | cut -d, -f1-9')
echo "probe summary: ${summary:-MISSING}"
gaps=$(ssh -o BatchMode=yes "$GEN_HOST" 'cat /tmp/hot-attach/udp-echo-gaps.csv 2>/dev/null || echo none')
if [ "$gaps" != none ]; then
    echo "$gaps" | tail -n +2 | while IFS=, read -r seq gap closed; do
        [ -n "$gap" ] && echo ",gap,$gap,$closed," >> "$csv"
    done
fi

echo "=== gap distribution (ns) ==="
awk -F, '$2=="gap" {print $3}' "$csv" | sort -n | tee "$OUT/gap-distribution.txt"
n=$(awk -F, '$2=="gap"' "$csv" | wc -l)
echo "gaps detected: $n over $REPEAT attach and $REPEAT detach events"
echo "$csv"
