#!/usr/bin/env bash
# fsync latency and cold-read throughput on the target's virtual disk. redb's
# durability policy depends on it: on a virtual disk with no battery-backed
# cache, fsync can cost 5-20 ms instead of the 1.5 ms of NVMe, and then even a
# ten-second durable commit shows up in the tick percentiles.
#
#   measure-storage.sh --out DIR [--size MB] [--runtime S] [--cold-file-mb N]
#
# Runs on VM 901.

set -uo pipefail

OUT=bench/results/storage
SIZE_MB=64
RUNTIME=60
COLD_MB=80

while [ $# -gt 0 ]; do
    case $1 in
        --out)         OUT=$2; shift 2 ;;
        --size)        SIZE_MB=$2; shift 2 ;;
        --runtime)     RUNTIME=$2; shift 2 ;;
        --cold-file-mb) COLD_MB=$2; shift 2 ;;
        -h|--help)     sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v fio >/dev/null || { echo "measure-storage: fio not installed" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT")
[ -n "$env_file" ] || { echo "measure-storage: capture-env produced no path" >&2; exit 2; }

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

result="$OUT/storage.json"
fio_json="$OUT/fsync-fio.json"

# fsync=1: fdatasync after every 4k write, iodepth 1 — the redb Durability::Immediate
# pattern, one small durable commit at a time. The percentiles, not a mean, are
# what decides the commit cadence.
fio --name=fsync --directory="$work" --rw=write --bs=4k --iodepth=1 --fsync=1 \
    --size="${SIZE_MB}m" --runtime="$RUNTIME" --time_based --output-format=json > "$fio_json" 2>/dev/null

# Percentiles are reported by fio in nanoseconds under sync.lat_ns.
extract() { jq -r "$1" "$fio_json"; }
p50=$(extract '.jobs[0].sync.lat_ns.percentile["50.000000"] // 0')
p99=$(extract '.jobs[0].sync.lat_ns.percentile["99.000000"] // 0')
p999=$(extract '.jobs[0].sync.lat_ns.percentile["99.900000"] // 0')
mean_ns=$(extract '.jobs[0].sync.lat_ns.mean // 0')
iops=$(extract '.jobs[0].write.iops // 0')

# Cold read: write a file, drop caches, read it back, so the number is disk
# throughput and not page cache. The spec's 7.2 ms is a warm read; cold is pure
# device bandwidth and bounds blocklist load time from a cold start.
cold="$work/cold.bin"
dd if=/dev/urandom of="$cold" bs=1M count="$COLD_MB" status=none
sync
echo 3 | sudo -n tee /proc/sys/vm/drop_caches >/dev/null
cold_out=$(dd if="$cold" of=/dev/null bs=1M 2>&1 | tail -1)
# dd prints "... copied, T s, R MB/s"
cold_mbps=$(echo "$cold_out" | grep -oE '[0-9.]+ [MG]B/s' | tail -1)

cat > "$result" <<EOF
{
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "environment": "$(basename "$env_file")",
  "fsync_lat_p50_ns": $p50,
  "fsync_lat_p99_ns": $p99,
  "fsync_lat_p99_9_ns": $p999,
  "fsync_lat_p99_us": $(awk -v v="$p99" 'BEGIN{printf "%.1f", v/1000}'),
  "fsync_lat_p50_us": $(awk -v v="$p50" 'BEGIN{printf "%.1f", v/1000}'),
  "fsync_iops": $iops,
  "cold_read_${COLD_MB}mb": "$cold_mbps"
}
EOF

echo "fsync p50 $(awk -v v="$p50" 'BEGIN{printf "%.2f", v/1e6}') ms, p99 $(awk -v v="$p99" 'BEGIN{printf "%.2f", v/1e6}') ms, p99.9 $(awk -v v="$p999" 'BEGIN{printf "%.2f", v/1e6}') ms"
echo "cold read of ${COLD_MB} MB: $cold_mbps"
cat "$result"
echo "$result"
