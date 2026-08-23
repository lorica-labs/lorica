#!/usr/bin/env bash
# The three numbers without which "10 ns per packet" means nothing on this
# machine: the cost of an XDP program that does nothing, the size of its JITed
# code, and what turning the kernel's own accounting on costs per invocation.
#
#   measure-floor.sh [--out DIR] [--repeat N] [--iface NAME] [--obj PATH] [--data PATH]
#
# BPF_PROG_TEST_RUN is used rather than live traffic on purpose: it times the
# program alone, with no driver, no NAPI poll and no DMA in the number.

set -uo pipefail

OUT=bench/results
REPEAT=3
ITERATIONS=1000000
IFACE=${LORICA_IFACE:-enp6s19}
OBJ=bench/progs/xdp_pass.o
DATA=bench/data/udp64.bin

while [ $# -gt 0 ]; do
    case $1 in
        --out)        OUT=$2; shift 2 ;;
        --repeat)     REPEAT=$2; shift 2 ;;
        --iterations) ITERATIONS=$2; shift 2 ;;
        --iface)      IFACE=$2; shift 2 ;;
        --obj)        OBJ=$2; shift 2 ;;
        --data)       DATA=$2; shift 2 ;;
        -h|--help)    sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { echo "measure-floor: $*" >&2; exit 1; }

[ -r "$OBJ" ]  || die "no $OBJ: run make -C bench/progs on the build host and copy the object here"
[ -r "$DATA" ] || die "no $DATA: run make -C bench/progs"

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
env_file=$("$here/capture-env.sh" "$OUT" "$IFACE")
[ -n "$env_file" ] || die "capture-env.sh produced no path: a result without its environment is not reproducible"
result="$OUT/floor-$stamp.json"

pin=/sys/fs/bpf/lorica-floor
sudo -n rm -f "$pin"
sudo -n bpftool prog load "$OBJ" "$pin" type xdp || die "load failed"
trap 'sudo -n rm -f "$pin"; sudo -n sysctl -qw kernel.bpf_stats_enabled=0' EXIT

# bpftool 7.4 reports bytes_jited and bytes_xlated. The older jited_prog_len
# spelling still parses as JSON and yields null, so the fallback is explicit
# rather than left to whichever bpftool the machine happens to carry.
show=$(sudo -n bpftool --json prog show pinned "$pin")
jited=$(echo "$show" | jq -r '.bytes_jited // .jited_prog_len // "null"')
xlated=$(echo "$show" | jq -r '.bytes_xlated // .xlated_prog_len // "null"')
[ "$jited" != null ] || die "bpftool reported no JITed size: $show"

# One invocation of BPF_PROG_TEST_RUN, averaged by the kernel over ITERATIONS.
run_once() {
    sudo -n bpftool --json prog run pinned "$pin" data_in "$DATA" repeat "$ITERATIONS" \
        | jq -r '.duration'
}

# Alternated rather than grouped: a drift in the machine would otherwise land
# entirely on whichever arm ran last and be read as the cost of the instrument.
plain=()
instrumented=()
for _ in $(seq "$REPEAT"); do
    sudo -n sysctl -qw kernel.bpf_stats_enabled=0
    plain+=("$(run_once)")
    sudo -n sysctl -qw kernel.bpf_stats_enabled=1
    instrumented+=("$(run_once)")
done
sudo -n sysctl -qw kernel.bpf_stats_enabled=0

# Native attach is not a detail: xdpgeneric runs after skb allocation and would
# make every number on this page describe a different code path.
mode=absent
if sudo -n ip link set dev "$IFACE" xdpdrv obj "$OBJ" sec xdp 2>/dev/null; then
    mode=$(ip -d link show "$IFACE" | grep -o 'xdp[a-z]*' | head -1)
    sudo -n ip link set dev "$IFACE" xdpdrv off
else
    mode=refused
fi

median() { printf '%s\n' "$@" | sort -n | awk '{v[NR]=$1} END {print (NR%2) ? v[(NR+1)/2] : int((v[NR/2]+v[NR/2+1])/2)}'; }
join_json() { printf '%s' "$(IFS=,; echo "$*")"; }

plain_median=$(median "${plain[@]}")
instrumented_median=$(median "${instrumented[@]}")

cat > "$result" <<EOF
{
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "kernel": "$(uname -r)",
  "environment": "$(basename "$env_file")",
  "object": "$OBJ",
  "data_in": "$DATA",
  "iterations_per_run": $ITERATIONS,
  "repeats": $REPEAT,
  "jited_prog_len": $jited,
  "xlated_prog_len": $xlated,
  "attach_mode": "$mode",
  "ns_per_run": [$(join_json "${plain[@]}")],
  "ns_per_run_median": $plain_median,
  "ns_per_run_bpf_stats_enabled": [$(join_json "${instrumented[@]}")],
  "ns_per_run_bpf_stats_enabled_median": $instrumented_median,
  "instrumentation_cost_ns": $((instrumented_median - plain_median))
}
EOF

cat "$result"
echo "$result"

[ "$mode" = xdp ] || die "attach mode is '$mode', not native xdp: every later measurement would describe another code path"
