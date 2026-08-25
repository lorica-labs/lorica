#!/usr/bin/env bash
# What a blocklist reload costs: text to binary once, then the mapped load twice.
#
#   measure-blocklist-reload.sh --entries N --out DIR [--keep]
#
# The conversion is the expensive half and it runs off the agent's startup path, so its
# peak RSS is measured and not budgeted. The load is the half the agent pays for, and it
# is measured cold and warm, because a cold mapping is the device and a warm one is the
# page cache. Both numbers are reported; neither is a substitute for the other.
#
# Runs on the machine under measurement. --entries 10000000 writes about 180 MB of text
# and 80 MB of binary, so check the disk before starting it on a shared VM. Entries are
# generated at a stride of 397 through the address space; past about 10.8 million the
# stride wraps and lorica-export refuses the duplicate, which is a real failure and not a
# limit of this script.
#
# Every extracted value is checked before it is used, and the result file is written last.
# A harness that can exit 0 without having measured invalidates every green result it ever
# gave, and this one has been on a full disk twice.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

ENTRIES=0
OUT=""
KEEP=0
STRIDE=397

while [ $# -gt 0 ]; do
    case $1 in
        --entries) ENTRIES=$2; shift 2 ;;
        --out)     OUT=$2; shift 2 ;;
        --keep)    KEEP=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

number() {
    # A guard that compares an empty string passes. Every value that reaches a comparison
    # goes through here first, and the caller says which value it was.
    case $2 in
        ''|*[!0-9]*) die "$1 is not a number: '$2'" ;;
    esac
    [ "$2" -gt 0 ] || die "$1 measured 0, so nothing was measured"
}

[ "$ENTRIES" -gt 0 ] 2>/dev/null || die "--entries needs a positive count"
[ -n "$OUT" ] || die "--out needs a directory"
for tool in awk jq stat wc; do
    command -v "$tool" >/dev/null || die "$tool is not installed"
done
[ -r /usr/bin/time ] || die "/usr/bin/time is missing, and the shell builtin reports no peak RSS"
[ -r scripts/lab/capture-env.sh ] || die "scripts/lab/capture-env.sh is missing"

mkdir -p "$OUT" || die "cannot create $OUT"

binary_bytes=$((16 + 8 * ENTRIES))
# Text at 18 bytes a line is the shape of a dotted quad plus /32 plus deny; the factor of
# two on top covers the exporter's own file and leaves the disk something.
needed_kb=$(( (binary_bytes * 2 + ENTRIES * 18) / 1024 + 524288 ))
avail_kb=$(df -Pk . | awk 'NR == 2 { print $4 }')
number "the available space on the working filesystem" "$avail_kb"
[ "$avail_kb" -ge "$needed_kb" ] \
    || die "this run needs about $needed_kb KB and the filesystem has $avail_kb KB free"

work=$(mktemp -d) || die "cannot create a working directory"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$work"; }
trap cleanup EXIT

env_file=$(scripts/lab/capture-env.sh "$OUT")
[ -n "$env_file" ] || die "capture-env.sh produced no path"

echo "building lorica-export"
cargo build --release -p lorica-export || die "the lorica-export build failed"
exporter=target/release/lorica-export
[ -r "$exporter" ] || die "$exporter was not produced by the build"

list=$work/list.txt
echo "generating $ENTRIES lines"
awk -v n="$ENTRIES" -v stride="$STRIDE" 'BEGIN {
    for (i = 0; i < n; i++) {
        a = (i * stride) % 4294967296
        o1 = int(a / 16777216)
        o2 = int(a / 65536) % 256
        o3 = int(a / 256) % 256
        o4 = a % 256
        print o1 "." o2 "." o3 "." o4 "/32 deny"
    }
}' > "$list" || die "generating the list failed"

lines=$(wc -l < "$list")
number "the generated line count" "$lines"
[ "$lines" -eq "$ENTRIES" ] || die "asked for $ENTRIES lines and the file holds $lines"
list_bytes=$(stat -c %s "$list")
number "the size of the generated list" "$list_bytes"

blocklist=$work/blocklist.bin
export_log=$work/export.log
echo "converting"
started_ns=$(date +%s%N)
/usr/bin/time -v "$exporter" --in "$list" --out "$blocklist" > "$work/export.out" 2> "$export_log"
export_status=$?
ended_ns=$(date +%s%N)
[ "$export_status" -eq 0 ] || { cat "$export_log" >&2; die "lorica-export exited $export_status"; }

export_ms=$(( (ended_ns - started_ns) / 1000000 ))
number "the conversion wall time in ms" "$export_ms"
export_peak_kb=$(awk '/Maximum resident set size/ { print $NF }' "$export_log")
number "the conversion peak RSS in KB" "$export_peak_kb"

got_bytes=$(stat -c %s "$blocklist")
number "the size of the converted file" "$got_bytes"
[ "$got_bytes" -eq "$binary_bytes" ] \
    || die "the converted file is $got_bytes bytes and the format says $binary_bytes"

# Cold first. Whether the cache was really dropped is recorded rather than assumed: a cold
# number that is not cold is worse than no number.
if sudo -n sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null; then
    dropped=true
else
    dropped=false
    echo "could not drop the page cache; the cold pass is not cold and says so" >&2
fi

cold_json=$work/cold.json
warm_json=$work/warm.json
echo "loading, cold"
"$exporter" --verify "$blocklist" > "$cold_json" || die "the cold load failed"
echo "loading, warm"
"$exporter" --verify "$blocklist" > "$warm_json" || die "the warm load failed"

read_field() {
    local value
    value=$(jq -r "$2 // empty" "$1")
    [ -n "$value" ] || die "$1 carries no $2"
    echo "$value"
}

for pass in "$cold_json" "$warm_json"; do
    seen=$(read_field "$pass" .entries)
    number "the entry count of $pass" "$seen"
    [ "$seen" -eq "$ENTRIES" ] || die "$pass loaded $seen entries out of $ENTRIES"
    [ "$(read_field "$pass" .sorted)" = true ] || die "$pass reports the file is not sorted"
    number "the mapping time of $pass" "$(read_field "$pass" .map_us)"
    number "the scan time of $pass" "$(read_field "$pass" .scan_us)"
done

cold_map_us=$(read_field "$cold_json" .map_us)
cold_scan_us=$(read_field "$cold_json" .scan_us)
warm_map_us=$(read_field "$warm_json" .map_us)
warm_scan_us=$(read_field "$warm_json" .scan_us)
warm_file_backed_growth=$(jq -r '.file_backed_kib_after - .file_backed_kib_before' "$warm_json")
number "the file-backed growth of the warm pass in KB" "$warm_file_backed_growth"
warm_dirty_growth=$(jq -r '.private_dirty_kib_after - .private_dirty_kib_before' "$warm_json")
case $warm_dirty_growth in
    ''|*[!0-9]*) die "the private-dirty growth of the warm pass is not a count: '$warm_dirty_growth'" ;;
esac

result=$OUT/blocklist-reload.json
cat > "$result" <<EOF
{
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "environment": "$(basename "$env_file")",
  "entries": $ENTRIES,
  "text_bytes": $list_bytes,
  "binary_bytes": $got_bytes,
  "convert_ms": $export_ms,
  "convert_peak_rss_kib": $export_peak_kb,
  "page_cache_dropped": $dropped,
  "cold_map_us": $cold_map_us,
  "cold_scan_us": $cold_scan_us,
  "warm_map_us": $warm_map_us,
  "warm_scan_us": $warm_scan_us,
  "warm_file_backed_growth_kib": $warm_file_backed_growth,
  "warm_private_dirty_growth_kib": $warm_dirty_growth
}
EOF
[ -s "$result" ] || die "the result file was not written"

echo "convert $ENTRIES entries: $export_ms ms, peak RSS $export_peak_kb KB"
echo "load cold: map $cold_map_us us, scan $cold_scan_us us (cache dropped: $dropped)"
echo "load warm: map $warm_map_us us, scan $warm_scan_us us"
echo "warm mapping: file_backed +$warm_file_backed_growth KB, private_dirty +$warm_dirty_growth KB"
cat "$result"
echo "$result"
