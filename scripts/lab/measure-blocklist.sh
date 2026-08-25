#!/usr/bin/env bash
# What the two flat blocklist tables cost, and whether they answer what the trie answered.
#
#   measure-blocklist.sh [--sizes A,B,C] [--passes N] [--repeat N] [--mhz N]
#                        [--out DIR] [--build-host H] [--target-host H]
#
# Three numbers come out, each on a line beginning "blocklist-", and none of them has a
# default: a step that did not measure kills the run instead of printing a placeholder.
#
#   blocklist-memory       kernel memory of the two tables, read off the .bss descriptor with
#                          /proc/self/fdinfo, against the trie holding the same set. Not the
#                          20 MiB the tables were declared with: a copied number goes stale in
#                          silence, and this project has already published a ceiling of 765 for
#                          a program measuring 1 317.
#   blocklist-reload       bpf() calls a full reload of both tables costs, counted by strace
#                          over two runs that differ only in how many reloads they perform.
#                          The prediction being tested is one call for the whole 20 MiB,
#                          against the BPF_MAP_UPDATE_BATCH lot the trie needed.
#   blocklist-equivalence  keys compared and the verdict.
#
# A fourth family of lines, "blocklist-cost", carries the per-packet figures, and the arm they
# are read against is named in them. The realistic arm is deep_miss_inside -- an absent key
# drawn inside a region the loaded set populates -- which cost 116 / 285 / 414 ns on the trie
# at 1 / 16384 / 1000000 entries. It is NOT shallow_miss_control, which is flat at 109 to 117
# whatever the size because it never enters the populated region; reading the tables against
# that column is how an earlier campaign concluded the tables were slower than the trie.
#
# Units. The nanoseconds are the duration field of BPF_PROG_TEST_RUN, which reports half the
# task-clock of the same work: 128 ns measured against 262, a factor of 2.06 stable over three
# levels and three campaigns. Ratios and differences survive that, absolutes do not. So the
# cycle columns are the ones to quote, and they are derived rather than read: cycles =
# duration_ns * 2.06 * MHz / 1000. The MHz is not a measurement either -- the guest exposes no
# cpufreq and the "cpu MHz" of /proc/cpuinfo is the nominal TSC cadence -- so it is reported
# under the name it came from and --mhz overrides it. No absolute nanosecond figure from here
# is a CPU time, and none of them is comparable with a number obtained any other way.
#
# The floor of 15 ns is already subtracted by the measurement binary, which takes its per
# packet cost from test_run with repeat=1e6 and never from run_time_ns, whose instrumentation
# costs 64 ns on this hardware.
#
# Where each half runs. The cost sweep runs on the measurement VM, which is the only machine
# that may be measured. The equivalence and the syscall count run there too, and not on the
# build VM, for a reason that is not about quiet: the measurement VM is the kernel floor of the
# project, and the floor is where the verifier lost the bound on the probe index and refused
# every blocklist test while 7.0 accepted them.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/blocklist
SIZES=1,16384,1000000
PASSES=25
REPEAT=1000000
MHZ=""
IFACE=${LORICA_IFACE:-enp6s19}
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run-blocklist}
MODE=campaign
ON_TARGET_DIR=""

# The factor between the duration field and the task-clock of the same work. Measured, not
# assumed, and quoted wherever a cycle figure is printed.
FACTOR=2.06

# The measurement this replaces, for the memory line to be read against.
TRIE_MIB_AT_A_MILLION=198

while [ $# -gt 0 ]; do
    case $1 in
        --sizes)       SIZES=$2; shift 2 ;;
        --passes)      PASSES=$2; shift 2 ;;
        --repeat)      REPEAT=$2; shift 2 ;;
        --mhz)         MHZ=$2; shift 2 ;;
        --out)         OUT=$2; shift 2 ;;
        --build-host)  BUILD_HOST=$2; shift 2 ;;
        --target-host) TARGET_HOST=$2; shift 2 ;;
        --iface)       IFACE=$2; shift 2 ;;
        --on-target)   MODE=on-target; shift ;;
        --run-dir)     ON_TARGET_DIR=$2; shift 2 ;;
        -h|--help)     sed -n '2,6p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-blocklist: %s\n' "$*" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

# ---------------------------------------------------------------------------
# The half that runs on the measured machine
# ---------------------------------------------------------------------------
#
# It is a mode of this script rather than a second script for one reason: a command string sent
# over ssh is re-quoted on the way, and the strace invocation below does not survive that.
if [ "$MODE" = on-target ]; then
    [ -n "$ON_TARGET_DIR" ] || die "--on-target needs --run-dir"
    root=$HOME/$ON_TARGET_DIR/target-tests
    [ -d "$root/bin" ] || die "no bin/ under $root, so nothing was shipped here"
    set -- "$root"/bin/*
    [ $# -eq 1 ] || die "expected one shipped binary under $root/bin, found $#"
    bin=$1
    [ -r "$bin" ] || die "$bin is not readable"
    command -v strace > /dev/null 2>&1 \
        || die "strace is not installed here, and the reload cost is counted rather than assumed"
    sudo -n true 2> /dev/null \
        || die "sudo needs a password; loading an XDP program needs CAP_BPF and CAP_NET_ADMIN"

    printf 'kernel %s\n' "$(uname -r)"

    printf '== equivalence\n'
    sudo -n env "LORICA_EBPF_OBJ=$root/ebpf/instrumented" \
                "LORICA_EBPF_PLAIN_OBJ=$root/ebpf/plain" \
        "$bin" --test-threads 1 --nocapture
    printf 'equivalence-exit=%d\n' "$?"

    # Two runs differing only in the number of reloads. The difference is the cost of one
    # reload; attributing calls inside a single run would mean deciding which of aya's own
    # writes belonged to the load, and the load writes .rodata and .bss itself.
    for reloads in 0 1; do
        trace=$root/strace-$reloads.txt
        printf '== reloads=%s\n' "$reloads"
        sudo -n env "LORICA_EBPF_OBJ=$root/ebpf/instrumented" \
                    "LORICA_EBPF_PLAIN_OBJ=$root/ebpf/plain" \
                    "LORICA_BLOCKLIST_RELOADS=$reloads" \
            strace -f -e trace=bpf -o "$trace" \
            "$bin" --exact a_full_reload_is_one_write_of_the_section --nocapture
        printf 'reload-exit-%s=%d\n' "$reloads" "$?"
        [ -s "$trace" ] || die "strace wrote nothing to $trace, so no call was counted"
        printf 'bpf-calls-%s=%s\n' "$reloads" "$(grep -c 'bpf(' "$trace")"
        printf 'bpf-update-elem-%s=%s\n' "$reloads" "$(grep -c 'BPF_MAP_UPDATE_ELEM' "$trace")"
    done
    exit 0
fi

# ---------------------------------------------------------------------------
# The campaign
# ---------------------------------------------------------------------------

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
cost_log=$OUT/blocklist-cost-$stamp.log
eq_log=$OUT/blocklist-equivalence-$stamp.log
csv=$OUT/blocklist-cost.csv

# The environment record is captured on the machine that is measured, not on this one.
env_remote=$(LORICA_REMOTE_DIR=$REMOTE_DIR bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh on $TARGET_HOST produced no usable path: '$env_remote'" ;;
esac
ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

if [ -z "$MHZ" ]; then
    # No single quote anywhere in a command that travels: deploy and remote wrap it in
    # bash -lc '...' and a quote of its own closes that envelope.
    MHZ=$(remote "$TARGET_HOST" "grep -m1 MHz /proc/cpuinfo | cut -d: -f2 | tr -dc 0-9.")
    MHZ_SOURCE=nominal_tsc_mhz
    [ -n "$MHZ" ] || die "no MHz line on $TARGET_HOST and no --mhz, so a cycle would be invented"
else
    MHZ_SOURCE=stated_mhz
fi

ship() {
    # $1 is the test target, $2 the directory it lands in on the measured machine.
    LORICA_REMOTE_DIR=$REMOTE_DIR bash scripts/lab/deploy.sh "$BUILD_HOST" \
        "bash scripts/lab/target-build.sh --test $1" \
        || die "the build of $1 on $BUILD_HOST failed"
    remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
        | remote "$TARGET_HOST" "rm -rf ~/$2 && mkdir -p ~/$2 && tar xf - -C ~/$2" \
        || die "could not ship $1 to $TARGET_HOST"
}

ship measure_lpm_depth "$RUN_DIR-cost"
remote "$TARGET_HOST" "bash ~/$RUN_DIR-cost/target-tests/target-run.sh \
    --sizes $SIZES --passes $PASSES --repeat $REPEAT" 2>&1 | tee "$cost_log"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the cost sweep on $TARGET_HOST failed, see $cost_log"

ship blocklist_equivalence "$RUN_DIR-eq"
LORICA_REMOTE_DIR=$REMOTE_DIR bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/measure-blocklist.sh --on-target --run-dir $RUN_DIR-eq" 2>&1 | tee "$eq_log"
[ "${PIPESTATUS[0]}" -eq 0 ] || die "the equivalence run on $TARGET_HOST failed, see $eq_log"

# --- the cost table -------------------------------------------------------

grep -E '^[0-9]+,[a-z_]+,' "$cost_log" > "$csv.rows"
[ -s "$csv.rows" ] || die "no CSV row in $cost_log, so nothing was timed"
grep -q 'flat_deep_miss_inside' "$csv.rows" \
    || die "no flat_deep_miss_inside row in $cost_log: the arm for the new structure did not run"

# One row per size, the realistic trie arm beside the flat one. The ternary trap is avoided
# on purpose: awk reads printf "%.1f", a > 0 ? x : y as a redirection into a file named 0,
# prints nothing, and a conformance check that prints nothing reads as a pass.
{
    echo "entries,realistic_ns,flat_ns,realistic_cycles,flat_cycles,ratio,trie_memlock_bytes,bss_memlock_bytes"
    awk -F, -v mhz="$MHZ" -v factor="$FACTOR" '
        $2 == "deep_miss_inside"      { real[$1] = $4; triemem[$1] = $6; order[++n] = $1 }
        $2 == "flat_deep_miss_inside" { flat[$1] = $4; bss[$1] = $6 }
        END {
            for (i = 1; i <= n; i++) {
                e = order[i]
                if (flat[e] == "") { continue }
                rc = real[e] * factor * mhz / 1000
                fc = flat[e] * factor * mhz / 1000
                ratio = 0
                if (flat[e] > 0) { ratio = real[e] / flat[e] }
                printf "%s,%s,%s,%.0f,%.0f,%.2f,%s,%s\n", \
                    e, real[e], flat[e], rc, fc, ratio, triemem[e], bss[e]
            }
        }' "$csv.rows"
} > "$csv"
[ "$(wc -l < "$csv")" -gt 1 ] || die "no size produced both arms, so there is nothing to compare"
rm -f "$csv.rows"

while IFS=, read -r entries real flat rc fc ratio triemem bss; do
    [ "$entries" = entries ] && continue
    printf 'blocklist-cost entries=%s realistic_arm=deep_miss_inside realistic_ns=%s flat_ns=%s realistic_cycles=%s flat_cycles=%s ratio=%s %s=%s duration_over_task_clock=%s\n' \
        "$entries" "$real" "$flat" "$rc" "$fc" "$ratio" "$MHZ_SOURCE" "$MHZ" "$FACTOR"
done < "$csv"

# The exit criterion is a column that does not move. It is reported as the spread of the flat
# arm over the sizes beside the spread of the trie arm over the same sizes, and not as a ratio
# at one size.
awk -F, 'NR > 1 {
        f = $3 + 0
        r = $2 + 0
        if (fmin == "" || f < fmin) { fmin = f }
        if (fmax == "" || f > fmax) { fmax = f }
        if (rmin == "" || r < rmin) { rmin = r }
        if (rmax == "" || r > rmax) { rmax = r }
        sizes++
    }
    END {
        if (sizes < 2) {
            printf "blocklist-flatness sizes=%d verdict=UNDECIDED needs at least two sizes\n", sizes
            exit
        }
        fs = 0
        rs = 0
        if (fmin > 0) { fs = fmax / fmin }
        if (rmin > 0) { rs = rmax / rmin }
        verdict = "NOT-FLAT"
        if (fs > 0 && fs < 1.2) { verdict = "FLAT" }
        printf "blocklist-flatness sizes=%d flat_min_ns=%s flat_max_ns=%s flat_spread=%.2f realistic_min_ns=%s realistic_max_ns=%s realistic_spread=%.2f verdict=%s\n", \
            sizes, fmin, fmax, fs, rmin, rmax, rs, verdict
    }' "$csv"

# --- the memory line ------------------------------------------------------

largest=$(awk -F, 'NR > 1 { e = $1 + 0; if (e > big) { big = e; row = $0 } } END { print row }' "$csv")
[ -n "$largest" ] || die "cannot find the largest size in $csv"
entries=$(echo "$largest" | cut -d, -f1)
triemem=$(echo "$largest" | cut -d, -f7)
bss=$(echo "$largest" | cut -d, -f8)
case $bss in ""|0) die "the .bss memlock read back as '$bss', so the kernel memory of the two tables was not measured" ;; esac
case $triemem in ""|0) die "the trie memlock read back as '$triemem'" ;; esac
printf 'blocklist-memory entries=%s bss_memlock_bytes=%s bss_mib=%s trie_memlock_bytes=%s trie_mib=%s recorded_trie_mib_at_1e6=%s source=/proc/self/fdinfo/memlock\n' \
    "$entries" "$bss" "$(awk -v b="$bss" 'BEGIN { printf "%.2f", b / 1048576 }')" \
    "$triemem" "$(awk -v b="$triemem" 'BEGIN { printf "%.2f", b / 1048576 }')" \
    "$TRIE_MIB_AT_A_MILLION"

# --- the reload line ------------------------------------------------------

field() { grep -m1 "^$1=" "$eq_log" | cut -d= -f2; }
zero=$(field bpf-calls-0)
one=$(field bpf-calls-1)
uzero=$(field bpf-update-elem-0)
uone=$(field bpf-update-elem-1)
section=$(grep -m1 'blocklist-reload ' "$eq_log" | tr ' ' '\n' | grep '^section_bytes=' | cut -d= -f2)
[ -n "$zero" ] || die "no bpf-calls-0 line in $eq_log, so the baseline run counted nothing"
[ -n "$one" ] || die "no bpf-calls-1 line in $eq_log, so the reload run counted nothing"
[ -n "$uzero" ] || die "no bpf-update-elem-0 line in $eq_log"
[ -n "$uone" ] || die "no bpf-update-elem-1 line in $eq_log"
[ -n "$section" ] || die "no section_bytes in $eq_log, so the size of what a reload writes is unknown"
[ "$one" -ge "$zero" ] || die "the traced run with a reload made fewer bpf calls ($one) than the one without ($zero)"
printf 'blocklist-reload section_bytes=%s bpf_calls_without=%s bpf_calls_with_one=%s calls_per_reload=%s update_elem_per_reload=%s counted_by=strace-e-trace-bpf\n' \
    "$section" "$zero" "$one" "$((one - zero))" "$((uone - uzero))"

# --- the equivalence line -------------------------------------------------

eq_status=$(grep -m1 '^equivalence-exit=' "$eq_log" | cut -d= -f2)
[ -n "$eq_status" ] || die "no equivalence-exit line in $eq_log"
keys=$(grep 'blocklist-equivalence set=' "$eq_log" | tr ' ' '\n' | grep '^keys=' | cut -d= -f2 \
    | awk '{ total += $1 } END { print total + 0 }')
sets=$(grep -c 'blocklist-equivalence set=' "$eq_log")
diverged=$(grep 'blocklist-equivalence set=' "$eq_log" | tr ' ' '\n' | grep '^diverged=' | cut -d= -f2 \
    | awk '{ total += $1 } END { print total + 0 }')
case $keys in ""|0) die "the equivalence run compared 0 keys, which invalidates any verdict it printed" ;; esac
verdict=FAIL
if [ "$eq_status" = 0 ] && [ "$diverged" = 0 ]; then verdict=EQUIVALENT; fi
printf 'blocklist-equivalence subsets=%s keys=%s diverged=%s verdict=%s\n' \
    "$sets" "$keys" "$diverged" "$verdict"

printf '\ncost table  %s\ncost log    %s\nequiv log   %s\nenvironment %s\n' \
    "$csv" "$cost_log" "$eq_log" "$OUT/$(basename "$env_remote")"

[ "$verdict" = EQUIVALENT ] || die "the equivalence verdict is $verdict, so nothing here authorises the replacement"
