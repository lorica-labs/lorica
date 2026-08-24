#!/usr/bin/env bash
# Price the layouts of a leaky-bucket bank, and measure what each one loses. Runs ON the
# measurement VM.
#
#   bucket-bench-run.sh --object PATH --packets DIR [--repeat N] [--cpus N]
#                       [--phase cost|leak]
#
# Two phases, because the layout decision needs two numbers that no single run gives.
#
#   cost  What a layout costs, and where it stops scaling. One `bpftool prog run` with
#         `repeat` per CPU, N of them at once on N pinned CPUs, timed on the wall clock.
#         Contention shows up as aggregate throughput that stops growing with N. There is
#         no wire and no driver in this, so the ~270 kpps ceiling of the lab does not
#         apply: the offered rate is far above anything the bridge can deliver, which is
#         the point. It is a stress bound and the report says so.
#
#   leak  What a layout fails to charge. Every CPU charges the SAME bucket, and afterwards
#         the level of that bucket is read and compared with what was offered. A shared
#         bank with no guard loses updates, so it charges less than it was given. A per-CPU
#         bank charges everything on each shard but each shard only ever sees its own
#         share, and enforcement reads one shard: that ratio IS the dilution the whole
#         task exists to measure. A locked bank charges exactly.
#
# The distribution of the cost phase is chosen by the source port of the frame, because
# that is what the bench indexes its bank by. Three of them, and the middle one exists
# because the first version of this measurement got it wrong:
#
#   same      every CPU takes the frame aiming at bucket zero. The concentrated attack.
#   adjacent  CPU i takes bucket i. A bucket is sixteen bytes, so buckets zero to three
#             live in ONE 64-byte cache line: four different buckets, one line. That is
#             false sharing and not a spread distribution, and reading it as one is how
#             this script first mistook a cache line for a property of the layout. It is
#             kept because a real bank hits it: adjacent hashes land in adjacent buckets.
#   spread    CPU i takes bucket i * 64, a kilobyte apart, so different buckets really are
#             different lines. The best case a shared bank can hope for.
#
# Maps are looked up through their pinned path and never by name: several loads of this
# object leave several maps with the same name alive, and `bpftool map lookup name` then
# answers "several maps match this handle" rather than picking one.
#
# It prints CSV on stdout and nothing else, so the caller can put it in a file.

set -uo pipefail

OBJECT=""
PACKETS=""
REPEAT=5000000
CPUS=0
PHASE=cost
PIN=/sys/fs/bpf/bucket-bench

VARIANTS="xdp_bucket_percpu_entry xdp_bucket_percpu_bank xdp_bucket_global_race \
xdp_bucket_global_lock_entry xdp_bucket_global_lock_bank xdp_counter_percpu xdp_counter_shared"

# The IPv4 total length of the 64-byte frame the bench is fed, which is what `charge` adds
# to the level. Named because the leak phase divides by it, and a wrong constant there
# would turn an exact layout into a leaking one on paper.
FRAME_CHARGE=50

while [ $# -gt 0 ]; do
    case $1 in
        --object)  OBJECT=$2; shift 2 ;;
        --packets) PACKETS=$2; shift 2 ;;
        --repeat)  REPEAT=$2; shift 2 ;;
        --cpus)    CPUS=$2; shift 2 ;;
        --phase)   PHASE=$2; shift 2 ;;
        -h|--help) sed -n '2,44p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'bucket-bench-run: %s\n' "$*" >&2; exit 1; }

[ -n "$OBJECT" ] || die "no --object: this machine has no compiler, the object travels"
[ -f "$OBJECT" ] || die "no object at $OBJECT"
[ -n "$PACKETS" ] || die "no --packets directory"
[ -d "$PACKETS" ] || die "no packet directory at $PACKETS"
case $PHASE in cost|leak) ;; *) die "unknown phase $PHASE" ;; esac
sudo -n true 2>/dev/null || die "sudo needs a password; loading a program needs CAP_BPF"

[ "$CPUS" -gt 0 ] 2>/dev/null || CPUS=$(nproc)

# One frame per bucket, one per CPU, in both sets. A missing frame would silently make two
# CPUs share a bucket and turn a spread run into a concentrated one, which is the
# measurement quietly answering a different question.
cpu=0
while [ "$cpu" -lt "$CPUS" ]; do
    for prefix in p q; do
        [ -f "$PACKETS/$prefix$cpu.bin" ] \
            || die "no $PACKETS/$prefix$cpu.bin, so CPU $cpu has no bucket of its own"
    done
    cpu=$((cpu + 1))
done

work=$(mktemp -d) || die "cannot create a working directory"
trap 'rm -rf "$work"; sudo -n rm -rf "$PIN" 2>/dev/null' EXIT

load() {
    sudo -n rm -rf "$PIN" 2>/dev/null
    sudo -n mkdir -p "$PIN/maps" \
        && sudo -n bpftool prog loadall "$OBJECT" "$PIN" pinmaps "$PIN/maps" \
        || die "the verifier refused $OBJECT on $(uname -r)"
}

# `duration (average): 123ns`. An absent or non-numeric value is refused rather than
# compared: a guard that compares an empty string passes for the wrong reason.
reported_ns() {
    sed -n 's/.*duration (average): \([0-9]*\)ns.*/\1/p' "$1" | tail -1
}

# Runs $cpus copies of $prog at once, one per CPU, on the frames the distribution names.
# Leaves the per-process output in $work/out.N and sets $elapsed_ms.
run_parallel() {
    local prog=$1 cpus=$2 distribution=$3 start end i frame
    start=$(date +%s%N)
    i=0
    while [ "$i" -lt "$cpus" ]; do
        case $distribution in
            same)     frame=$PACKETS/p0.bin ;;
            adjacent) frame=$PACKETS/p$i.bin ;;
            spread)   frame=$PACKETS/q$i.bin ;;
        esac
        sudo -n taskset -c "$i" bpftool prog run pinned "$prog" \
            data_in "$frame" repeat "$REPEAT" > "$work/out.$i" 2>&1 &
        i=$((i + 1))
    done
    wait
    end=$(date +%s%N)
    elapsed_ms=$(( (end - start) / 1000000 ))
}

if [ "$PHASE" = cost ]; then
    load
    echo 'variant,cpus,distribution,repeat,reported_ns_worst,elapsed_ms,runs_per_s,scaling'

    for variant in $VARIANTS; do
        prog=$PIN/$variant
        # `sudo` to test it: bpffs is not readable by an unprivileged user, so a plain -e
        # answers "absent" for a program that is there.
        sudo -n test -e "$prog" || die "$variant was not pinned, so it is not in $OBJECT"

        for distribution in same adjacent spread; do
            one_cpu_rate=""
            cpus=1
            while [ "$cpus" -le "$CPUS" ]; do
                run_parallel "$prog" "$cpus" "$distribution"

                worst=0
                i=0
                while [ "$i" -lt "$cpus" ]; do
                    value=$(reported_ns "$work/out.$i")
                    case $value in
                        ''|*[!0-9]*) die "$variant on CPU $i reported no duration: $(tr -d '\n' < "$work/out.$i")" ;;
                    esac
                    [ "$value" -gt "$worst" ] && worst=$value
                    i=$((i + 1))
                done

                [ "$elapsed_ms" -gt 0 ] || die "$variant at $cpus CPUs finished in under a millisecond"
                rate=$(awk -v r="$REPEAT" -v c="$cpus" -v ms="$elapsed_ms" \
                    'BEGIN { printf "%.0f", (ms > 0 ? r * c * 1000 / ms : 0) }')
                [ "$cpus" -eq 1 ] && one_cpu_rate=$rate

                # Scaling against one CPU: 1.0 means the Nth core bought nothing, N means
                # it scaled perfectly. This is the column the layout decision reads.
                scaling=$(awk -v r="$rate" -v o="$one_cpu_rate" \
                    'BEGIN { printf "%.2f", (o > 0 ? r / o : 0) }')

                printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
                    "$variant" "$cpus" "$distribution" "$REPEAT" \
                    "$worst" "$elapsed_ms" "$rate" "$scaling"
                cpus=$((cpus + 1))
            done
        done
    done
    exit 0
fi

# ---- leak phase ------------------------------------------------------------------------
#
# The map is reloaded fresh for every variant: a level carried over from the previous
# variant would make the next one look exact.
#
# The offset of the level inside the value is not the same in every layout. A
# `struct bpf_spin_lock` is four bytes and the bucket that follows it is eight-aligned, so
# a locked value carries the level at offset eight.
level_of() {
    local map=$1 offset=$2
    sudo -n bpftool map lookup pinned "$map" key hex 00 00 00 00 --json \
        | python3 -c "
import json, sys
doc = json.load(sys.stdin)
off = $offset
def u64(words):
    raw = bytes(int(w, 16) for w in words)
    if len(raw) < off + 8:
        sys.exit('value is %d bytes, too short for offset %d' % (len(raw), off))
    return int.from_bytes(raw[off:off + 8], 'little')
if 'values' in doc:
    shards = [u64(v['value']) for v in doc['values']]
    print('%d %d' % (max(shards), sum(shards)))
else:
    one = u64(doc['value'])
    print('%d %d' % (one, one))
"
}

echo 'variant,cpus,repeat,offered_units,enforced_units,total_units,enforced_fraction,total_fraction'

for triple in \
    "xdp_bucket_percpu_entry:percpu_entries:0" \
    "xdp_bucket_percpu_bank:percpu_bank:0" \
    "xdp_bucket_global_race:global_racing_entries:0" \
    "xdp_bucket_global_lock_entry:global_locked_entries:8" \
    "xdp_bucket_global_lock_bank:global_locked_bank:8"; do

    variant=${triple%%:*}
    rest=${triple#*:}
    map=${rest%%:*}
    offset=${rest##*:}

    load
    sudo -n test -e "$PIN/$variant" || die "$variant was not pinned"
    # `pinmaps` names the pin after the map as the ELF declares it, not after the
    # fifteen-character name the kernel keeps, so `global_racing_entries` is not
    # `global_racing_e` here.
    sudo -n test -e "$PIN/maps/$map" || die "$map is not under $PIN/maps"

    run_parallel "$PIN/$variant" "$CPUS" same

    read -r enforced total < <(level_of "$PIN/maps/$map" "$offset")
    case $enforced$total in ''|*[!0-9]*) die "$variant: could not read a level out of $map" ;; esac

    offered=$((REPEAT * CPUS * FRAME_CHARGE))
    [ "$offered" -gt 0 ] || die "nothing was offered, so no fraction means anything"
    enforced_fraction=$(awk -v e="$enforced" -v o="$offered" \
        'BEGIN { printf "%.4f", (o > 0 ? e / o : 0) }')
    total_fraction=$(awk -v t="$total" -v o="$offered" \
        'BEGIN { printf "%.4f", (o > 0 ? t / o : 0) }')

    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$variant" "$CPUS" "$REPEAT" "$offered" \
        "$enforced" "$total" "$enforced_fraction" "$total_fraction"
done
