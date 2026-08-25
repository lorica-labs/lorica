#!/usr/bin/env bash
# The permanent cost of having an XDP program attached to virtio-net, paid whether
# or not there is an attack. Measures throughput, guest CPU and application
# latency with the program detached (arm A) and with a do-nothing xdp_pass
# attached natively (arm B), in both directions, arms alternated.
#
#   measure-attach-tax.sh --gen-host SSH --peer-ip IP --self-ip IP --out DIR
#                         [--repeat N] [--seconds N] [--iface NAME] [--obj PATH]
#
# Runs on VM 901 (the target). Drives VM 902 over SSH for the iperf3 peer and the
# legitimate load. self-ip is this host's test address; peer-ip is 902's.

set -uo pipefail

OUT=bench/results/attach-tax
DEV=${LORICA_IFACE:-enp6s19}
GEN_HOST=lab-gen
PEER_IP=
SELF_IP=
REPEAT=3
SECONDS_PER=10
OBJ=bench/progs/xdp_pass.o
PROBE=${LORICA_PROBE:-/tmp/latency-probe}

while [ $# -gt 0 ]; do
    case $1 in
        --out)      OUT=$2; shift 2 ;;
        --iface)    DEV=$2; shift 2 ;;
        --gen-host) GEN_HOST=$2; shift 2 ;;
        --peer-ip)  PEER_IP=$2; shift 2 ;;
        --self-ip)  SELF_IP=$2; shift 2 ;;
        --repeat)   REPEAT=$2; shift 2 ;;
        --seconds)  SECONDS_PER=$2; shift 2 ;;
        --obj)      OBJ=$2; shift 2 ;;
        --probe)    PROBE=$2; shift 2 ;;
        -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PEER_IP" ] && [ -n "$SELF_IP" ] || { echo "measure-attach-tax: --peer-ip and --self-ip are required" >&2; exit 2; }
[ -r "$OBJ" ] || { echo "measure-attach-tax: no $OBJ" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT" "$DEV")
[ -n "$env_file" ] || { echo "measure-attach-tax: capture-env produced no path" >&2; exit 2; }
csv="$OUT/attach-tax.csv"
echo "arm,direction,rep,throughput_mbps,guest_cpu_busy_pct,legit_p99_us,legit_jitter_us" > "$csv"

pin=/sys/fs/bpf/lorica-attach-tax
cleanup() { sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null; ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x iperf3' 2>/dev/null; }
trap cleanup EXIT

# Record the offload state under both arms. The plan expected XDP attach to clear
# guest offloads; on 6.8 it does not, so the diff is recorded as data and its
# emptiness is the finding, not a failure.
ethtool -k "$DEV" | sort > "$OUT/offloads-detached.txt"
sudo -n ip link set dev "$DEV" xdpdrv obj "$OBJ" sec xdp || { echo "measure-attach-tax: native attach failed" >&2; exit 1; }
mode=$(ip -d link show "$DEV" | grep -o 'xdp[a-z]*' | head -1)
[ "$mode" = xdp ] || { echo "measure-attach-tax: attach mode is $mode, not native xdp" >&2; exit 1; }
ethtool -k "$DEV" | sort > "$OUT/offloads-attached.txt"
diff "$OUT/offloads-detached.txt" "$OUT/offloads-attached.txt" > "$OUT/offloads.diff" || true
sudo -n ip link set dev "$DEV" xdpdrv off

attach() { sudo -n ip link set dev "$DEV" xdpdrv obj "$OBJ" sec xdp; }
detach() { sudo -n ip link set dev "$DEV" xdpdrv off; }

# 902 runs a persistent iperf3 server for both directions.
ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x iperf3 2>/dev/null; sleep 0.3; setsid nohup iperf3 -s >/dev/null 2>&1 < /dev/null & sleep 0.5; pgrep -x iperf3 >/dev/null && echo up' >/dev/null 2>&1

# Busy percentage of the busiest guest CPU during the transfer: an XDP program
# runs in softirq on the RX core, and averaging across four cores would dilute
# exactly the cost being measured.
cpu_busy_during() {
    local secs=$1
    mpstat -P ALL 1 "$secs" | awk '
        /^Average.*[0-9]/ && $2 ~ /^[0-9]+$/ { busy = 100 - $NF; if (busy > max) max = busy }
        END { printf "%.1f", max }'
}

# iperf3 from 901: rx = 902 sends to us (-R on our client), tx = we send to 902.
run_iperf() {
    local dir=$1 secs=$2
    local flag=""
    [ "$dir" = rx ] && flag="-R"
    iperf3 -c "$PEER_IP" -t "$secs" -J $flag 2>/dev/null \
        | jq -r '(.end.sum_received.bits_per_second // .end.sum.bits_per_second) / 1e6 | floor'
}

# A legitimate client runs on 902 against a probe server we host, in parallel with
# the bulk transfer, so the tax on application latency is measured under load.
one_measurement() {
    local arm=$1 dir=$2 rep=$3
    setsid nohup "$PROBE" serve --profile tcp-reqresp --bind "$SELF_IP:19100" >/dev/null 2>&1 < /dev/null &
    local srv=$!
    sleep 0.4

    local probe_out; probe_out=$(mktemp)
    ssh -o BatchMode=yes "$GEN_HOST" \
        "$PROBE load --profile tcp-reqresp --target $SELF_IP:19100 --duration $SECONDS_PER --out /tmp/attach-legit >/tmp/attach-legit.txt 2>&1; grep -E '^samples' /tmp/attach-legit.txt || tail -1 /tmp/attach-legit.txt" \
        > "$probe_out" 2>/dev/null &
    local legit_pid=$!

    # mpstat and iperf must overlap, so mpstat writes to a file in the background
    # while iperf runs in the foreground; a command-substitution & would lose the
    # value to a subshell.
    local cpu_file; cpu_file=$(mktemp)
    cpu_busy_during "$SECONDS_PER" > "$cpu_file" &
    local cpu_pid=$!
    local tput; tput=$(run_iperf "$dir" "$SECONDS_PER")
    wait "$cpu_pid" 2>/dev/null || true
    wait "$legit_pid" 2>/dev/null || true
    kill "$srv" 2>/dev/null
    local cpu; cpu=$(cat "$cpu_file"); rm -f "$cpu_file" "$probe_out"

    local p99 jitter
    read -r p99 jitter < <(ssh -o BatchMode=yes "$GEN_HOST" '
        awk -F, "NR==1{for(i=1;i<=NF;i++) c[\$i]=i} NR==2{print int(\$c[\"p99_ns\"]/1000), int(\$c[\"jitter_ns\"]/1000)}" \
            /tmp/attach-legit/tcp-reqresp-summary.csv 2>/dev/null' 2>/dev/null)
    echo "$arm,$dir,$rep,${tput:-NA},${cpu:-NA},${p99:-NA},${jitter:-NA}" | tee -a "$csv"
}

# Alternate A/B each rep so a drift in the machine does not land on one arm.
for rep in $(seq "$REPEAT"); do
    for dir in rx tx; do
        detach; one_measurement A "$dir" "$rep"
        attach; one_measurement B "$dir" "$rep"
        detach
    done
done

echo "measure-attach-tax: offload diff below (empty means attach cleared nothing)"
cat "$OUT/offloads.diff"
echo "$csv"
