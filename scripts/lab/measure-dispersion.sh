#!/bin/sh
# What CLASS24 costs when the traffic does not read the same line twice.
#
#   measure-dispersion.sh [--out DIR] [--seconds S] [--pps N] [--passes N]
#                         [--group A|B|D] [--iface NAME]
#
# `CLASS24` is 4 MiB of flat table read at a random offset on every IPv4 packet. Every figure
# this project has published about it was taken under `BPF_PROG_TEST_RUN`, which replays one
# buffer and therefore **one source address**: always the same line, always hot in L1. Under a
# flood with spoofed sources that single access walks the whole 4 MiB. Nothing had measured it.
#
# Two arms, identical in every respect but one:
#
#   spread   all four source octets random -> 2^24 distinct /24 -> the whole table
#   single   one source address            -> one /24           -> one line, always hot
#
# Same rate, same packet count, same frame, same program, same session. The difference is the
# memory cost of that one access. Everything else -- driver, NAPI, XDP dispatch, the rest of the
# pipeline -- is common to both arms and subtracts out, which is the same subtraction
# measure-stage-cost.sh applies to the *stage* axis, applied here to the *address* axis.
#
# ---------------------------------------------------------------------------------------------
# Four things this script does that are not obvious, and each of them cost a wrong reading first
# ---------------------------------------------------------------------------------------------
#
# **The packets are later IPv4 fragments, and that is load-bearing.** The first attempt sent
# ordinary UDP, which the program passes and the *stack* then handles -- and the stack's work
# depends heavily on source dispersion: route lookups, the neighbour table, ICMP unreachables to
# 65 000 destinations. That run reported the two arms differing by **25 % in instructions**,
# which is impossible for a program whose control flow does not read the source address. It was
# measuring Linux, not `CLASS24`.
#
# A later fragment has offset != 0, so `parse` marks it `FragState::Later`, stage 3 reads
# `CLASS24` for it exactly as for any IPv4 packet, and **stage 4 drops it under the default
# policy** -- before the buckets, before the stack. Nothing downstream of the measured access
# runs at all. With that change the two arms agree to within 1 % of instructions, which is the
# validity check this script prints and the reason to trust the cycle figure beside it.
#
# **One RX queue.** With four combined queues the two arms steer differently -- dispersed sources
# spread across four CPUs, one source lands on one -- so the arms would differ in how many cores
# were warm, not in memory locality. `ethtool -L <if> combined 1` for the campaign, restored on
# exit including on interrupt.
#
# **trafgen needs `--rate`.** Without it the TX ring fills faster than virtio drains it, every
# flush returns `EAGAIN`, one packet leaves and the run still reports success. The count is
# derived from the rate so both arms send the same number of packets.
#
# **`instructions` is the control, not the result.** A load hoist or a cache effect changes zero
# instructions; that is the whole reason this campaign exists. The instruction column is here to
# prove the two arms ran the same code, and a spread above a percent invalidates the run.
#
# ---------------------------------------------------------------------------------------------
# Counters, and the multiplexing rule
# ---------------------------------------------------------------------------------------------
#
# The PMU has four general counters. Ten events do not fit, so they are measured in groups, one
# group per pass, with `cycles` in every group as the common normaliser:
#
#   A  cycles, instructions, cache-misses, L1-dcache-load-misses
#   B  cycles, instructions, cycle_activity.stalls_ldm_pending, cycle_activity.stalls_l2_pending
#   D  cycles, instructions, mem_load_uops_l3_hit_retired.xsnp_hitm, L1-icache-load-misses
#
# **A group is refused unless every event reads 100 % enabled.** perf scales a multiplexed
# counter and reports the estimate as if it were a count; a scaled number in a column beside an
# unscaled one is how a campaign publishes a ratio of two different things. Field 5 of the
# `-x,` form is the enabled percentage -- not field 6, which is the IPC and reads 0.43.
#
# **Group C is not offered, and its absence is the point.** The MLP pair
# `l1d_pend_miss.pending` and `l1d_pend_miss.pending_cycles` share a counter on Haswell with
# different cmasks and multiplex against each other: 74 % and 25 % on this host. MLP is the one
# number that says whether a load hoist bought anything and neither Beeswax nor XNET publishes
# it, so this is a gap worth naming rather than a column worth faking. It needs a PMU where the
# pair coexists, or two passes and an argument that the load is stationary between them.
#
# An event the PMU does not have is written `absent` in the CSV. It is never omitted and never
# a zero, and the reduction prints `absent` for that row rather than a difference of two
# nothings.
#
# **The stall events are named for Haswell and the names are not portable.**
# `cycle_activity.stalls_l3_miss` and `cycle_activity.stalls_mem_any` are Skylake and later;
# this host answers `event syntax error` for both. Its equivalents are
# `stalls_ldm_pending` -- stalled with a load miss outstanding -- and `stalls_l2_pending`,
# which is stalled on something the L2 could not answer and is the nearest thing here to a
# stall on an L3 miss. A campaign on another machine has to check the names again, and the
# check has to look for `syntax error` and `Unable to find` and not only for `not supported`:
# probing for the wrong words is how this script first reported four events present that its
# PMU does not have.
#
# `bpf_stats_enabled` must be 0 and the script refuses to run otherwise: it costs 64 ns a run,
# measured, and would land in the arms unequally if it were toggled between them.
#
# ---------------------------------------------------------------------------------------------
# What this measures and what it does not
# ---------------------------------------------------------------------------------------------
#
# The cycles here are the **whole receive path** for one packet, not the eBPF program alone:
# `perf stat -a` counts the driver, NAPI and the XDP dispatcher too. That is correct for a
# *difference* between two arms that share all of it, and wrong for any absolute. The absolute
# per-packet cost of the program is `measure-stage-cost.sh`'s figure and not this one.
#
# The idle baseline is subtracted so the per-packet figures are traffic work. It cancels in the
# difference either way; it is there so the absolute columns mean something.

set -u

cd "$(dirname "$0")/../.." || exit 1

OUT=bench/results/dispersion
SECONDS_RUN=8
PPS=200000
PASSES=3
GROUP=A
IFACE=${LORICA_IFACE:-enp6s19}
BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
GEN_HOST=${LORICA_GEN_HOST:-lab-gen}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-disp}
# Features the measured eBPF object is built with, so a variant behind a flag is measured with
# the same instrument and in the same session as its baseline. Empty measures what ships.
EBPF_EXTRA=${EBPF_EXTRA:-}

# The single source address of arm B. Inside a documentation range on purpose: it is a bogon,
# so it can never collide with a rule an operator might have loaded, and the arm is about the
# address being *one* address rather than about which one.
SINGLE_SRC='203, 0, 113, 7'

while [ $# -gt 0 ]; do
    case $1 in
        --out)     OUT=$2; shift 2 ;;
        --seconds) SECONDS_RUN=$2; shift 2 ;;
        --pps)     PPS=$2; shift 2 ;;
        --passes)  PASSES=$2; shift 2 ;;
        --group)   GROUP=$2; shift 2 ;;
        --iface)   IFACE=$2; shift 2 ;;
        -h|--help) sed -n '2,90p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'measure-dispersion: %s\n' "$*" >&2; exit 1; }
on_target() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" "$1"; }
on_gen() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$GEN_HOST" "$1"; }

case $GROUP in
    A) EVENTS=cycles,instructions,cache-misses,L1-dcache-load-misses ;;
    B) EVENTS=cycles,instructions,cycle_activity.stalls_ldm_pending,cycle_activity.stalls_l2_pending ;;
    D) EVENTS=cycles,instructions,mem_load_uops_l3_hit_retired.xsnp_hitm,L1-icache-load-misses ;;
    *) die "group must be A, B or D -- see the header for why there is no C" ;;
esac

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
csv="$OUT/dispersion-$GROUP.csv"
log="$OUT/run-$GROUP-$stamp.txt"

# ---------------------------------------------------------------------------------------------
# The environment record, captured on the machine that is measured.
# ---------------------------------------------------------------------------------------------
env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh $OUT $IFACE" | tail -1)
case $env_remote in
    "" | *[!-a-zA-Z0-9_./]*) die "capture-env.sh produced no usable path: '$env_remote'" ;;
esac
on_target "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
    || die "cannot bring the environment record back from $TARGET_HOST"

# ---------------------------------------------------------------------------------------------
# Refusals, before anything is built or attached.
# ---------------------------------------------------------------------------------------------
stats=$(on_target 'cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null')
[ "$stats" = 0 ] || die "bpf_stats_enabled is '$stats' on $TARGET_HOST; it costs 64 ns a run and this campaign is about a smaller effect than that"

dst_mac=$(on_target "cat /sys/class/net/$IFACE/address") \
    || die "cannot read the MAC of $IFACE on $TARGET_HOST"
dst_ip=$(on_target "ip -4 -br addr show $IFACE | awk '{print \$3}' | cut -d/ -f1")
[ -n "$dst_ip" ] || die "$IFACE on $TARGET_HOST carries no IPv4 address"

# ---------------------------------------------------------------------------------------------
# Build on the build host, run on the target. Static musl, because the target has no toolchain
# and its glibc is behind: the same reason target-tests.sh gives.
# ---------------------------------------------------------------------------------------------
bash scripts/lab/deploy.sh "$BUILD_HOST" \
    'export PATH=$HOME/.cargo/bin:$PATH; cd $HOME/'"$REMOTE_DIR"' \
     && cargo build --release --target x86_64-unknown-linux-musl -p loricad \
     && cd crates/lorica-ebpf && cargo +nightly build --release'"${EBPF_EXTRA:+ --features $EBPF_EXTRA}" \
    || die "the build on $BUILD_HOST failed"

on_target "mkdir -p ~/$RUN_DIR"
ssh -o BatchMode=yes "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/x86_64-unknown-linux-musl/release/loricad" \
    | on_target "cat > ~/$RUN_DIR/loricad && chmod +x ~/$RUN_DIR/loricad" \
    || die "cannot ship the agent to $TARGET_HOST"
ssh -o BatchMode=yes "$BUILD_HOST" "cat ~/$REMOTE_DIR/crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf" \
    | on_target "cat > ~/$RUN_DIR/lorica-ebpf" \
    || die "cannot ship the eBPF object to $TARGET_HOST"

# ---------------------------------------------------------------------------------------------
# One RX queue for the campaign, restored on every exit path.
# ---------------------------------------------------------------------------------------------
# Any agent already on the hook is stopped first. The XDP hook takes one program and refuses
# the second, so a leftover from an interrupted run makes this campaign fail at the attach with
# a message about the attach rather than about the leftover.
on_target 'sudo -n pkill -x loricad 2>/dev/null; sleep 1' >/dev/null 2>&1

# Read as found and restored to what was found. An interrupted run leaves the interface pinned,
# so this is not necessarily the driver's default -- which is why the log records the number.
queues=$(on_target "ethtool -l $IFACE | awk '/^Current/,0 { if (\$1 == \"Combined:\") print \$2 }'")
case $queues in ''|*[!0-9]*) die "cannot read the queue count of $IFACE" ;; esac

restore() {
    on_target "sudo -n pkill -x loricad 2>/dev/null; sudo -n ethtool -L $IFACE combined $queues 2>/dev/null" >/dev/null 2>&1
}
trap 'restore; exit 130' INT TERM
on_target "sudo -n ethtool -L $IFACE combined 1" || die "cannot pin $IFACE to one RX queue"

# ---------------------------------------------------------------------------------------------
# The two trafgen configurations, written on the generator. They differ on one line.
# ---------------------------------------------------------------------------------------------
macb() { echo "$1" | tr ':' ' ' | tr 'a-f' 'A-F' | sed 's/\([0-9A-F][0-9A-F]\)/0x\1,/g'; }
gen_mac=$(on_gen "cat /sys/class/net/$IFACE/address") || die "cannot read the generator MAC"
IFS=. read -r d1 d2 d3 d4 <<EOF
$dst_ip
EOF

write_conf() {
    arm=$1; src=$2
    on_gen "cat > /tmp/disp-$arm.trafgen" <<EOF
{
  $(macb "$dst_mac")
  $(macb "$gen_mac")
  const16(0x0800),
  0x45, 0, const16(46),
  const16(0x0000), const16(0x00b9),
  64, 17, const16(0),
  $src,
  $d1, $d2, $d3, $d4,
  const16(40000), const16(19000), const16(26), const16(0),
  fill(0x00, 18)
}
EOF
}
# Fragment offset 185 with MF clear: `ipv4::frag_state` reads any non-zero offset as `Later`,
# which stage 4 drops. See the header.
write_conf spread 'drnd(1), drnd(1), drnd(1), drnd(1)'
write_conf single "$SINGLE_SRC"

# ---------------------------------------------------------------------------------------------
# The agent, attached for the whole campaign so no arm pays an attach.
# ---------------------------------------------------------------------------------------------
window=$(( (PASSES * 2 + 2) * (SECONDS_RUN + 8) + 60 ))
# `ssh -n -f`, and the reason is worth a line because it cost two wrong diagnoses. A plain ssh
# waits for the channel to close, and a backgrounded job on the far side holds it open even with
# all three descriptors redirected: the launch then blocks for the agent's whole window, the
# attach check runs after it has exited, and the script reports "did not attach" about an agent
# that attached, ran and left. `-f` backgrounds ssh itself once authenticated; `-n` keeps it off
# stdin. The same pattern the flood uses below, for the same reason.
ssh -n -f -o BatchMode=yes -o ConnectTimeout=25 "$TARGET_HOST" \
    "cd ~/$RUN_DIR && rm -f /tmp/disp-agent.log && setsid nohup sudo -n ./loricad \
     --object ./lorica-ebpf --iface $IFACE --seconds $window --metrics off \
     --socket /tmp/disp.sock > /tmp/disp-agent.log 2>&1 < /dev/null"
sleep 8
attached=$(on_target "ip -d link show $IFACE | grep -c 'prog/xdp id'")
[ "$attached" = 1 ] || { restore; die "the agent did not attach; see /tmp/disp-agent.log on $TARGET_HOST"; }

# ---------------------------------------------------------------------------------------------
# One reading. Prints: packets,<one field per event>,enabled_ok
# ---------------------------------------------------------------------------------------------
read_arm() {
    on_target "
        rx() { cat /sys/class/net/$IFACE/statistics/rx_packets; }
        before=\$(rx)
        out=\$(sudo -n perf stat -a -x, -e $EVENTS -- sleep $SECONDS_RUN 2>&1)
        after=\$(rx)
        printf '%s\n' \"\$out\" | awk -F, -v pk=\$((after - before)) '
            \$3 != \"\" { v[\$3] = \$1; if (\$5 != \"\" && \$5 + 0 < 99.5) bad = bad \" \" \$3 \"=\" \$5 }
            END {
                n = split(\"$EVENTS\", want, \",\")
                line = pk
                for (i = 1; i <= n; i++) line = line \",\" (want[i] in v ? v[want[i]] : \"absent\")
                print line \",\" (bad == \"\" ? \"ok\" : \"multiplexed:\" bad)
            }'
    "
}

# **Any previous flood is stopped first, and the count is sized to one arm.** A run whose packet
# count outlives its arm overlaps the next one, and overlapping trafgens contend for the single
# TX ring and each slow down: a campaign that began at 200 kpps an arm was delivering 67 kpps by
# its third, the arms no longer comparable and nothing in the output saying so. `check_delivered`
# catches the symptom; this removes the cause.
flood() {
    ssh -o BatchMode=yes -o ConnectTimeout=25 "$GEN_HOST" 'sudo -n pkill -x trafgen 2>/dev/null; sleep 1' >/dev/null 2>&1
    ssh -n -f -o BatchMode=yes "$GEN_HOST" \
        "sudo -n trafgen --dev $IFACE --conf /tmp/disp-$1.trafgen --cpus 1 --no-sock-mem \
         --rate ${PPS}pps --num $(( PPS * (SECONDS_RUN + 4) )) > /tmp/disp-gen.log 2>&1"
}

# The flood has to have arrived. Every figure below divides by this number, so an arm that got a
# tenth of what was offered still produces a plausible per-packet reading -- about a machine that
# was mostly idle.
check_delivered() {
    got=${2%%,*}
    want=$(( PPS * SECONDS_RUN ))
    floor=$(( want * 4 / 5 ))
    case $got in ''|*[!0-9]*) restore; die "arm $1 reported no packet count" ;; esac
    [ "$got" -ge "$floor" ] || { restore; die "arm $1 received $got packets against a floor of $floor for $PPS pps over ${SECONDS_RUN}s: the flood did not arrive, and the per-packet figures would be about an idle machine"; }
}

# ---------------------------------------------------------------------------------------------
# The campaign. Arms alternate order between passes so a machine that drifts one way over the
# session does not hand the whole drift to one arm.
# ---------------------------------------------------------------------------------------------
{
    printf 'group,%s\nevents,%s\nseconds,%s\npps,%s\npasses,%s\nqueues,1 (restored to %s)\nebpf_features,%s\n' \
        "$GROUP" "$EVENTS" "$SECONDS_RUN" "$PPS" "$PASSES" "$queues" "${EBPF_EXTRA:-none}"
} > "$log"

printf 'pass,arm,packets,%s,enabled\n' "$EVENTS" > "$csv"

printf '\n--- idle baseline, no traffic\n' | tee -a "$log"
row=$(read_arm)
printf '0,idle,%s\n' "$row" >> "$csv"
printf '%s\n' "$row" | tee -a "$log"

# **One warm-up reading, kept in the CSV and excluded from the reduction.** The interface was
# re-pinned to a single queue moments ago and the agent attached moments before that; the first
# flood after both reads about 25 % low, consistently, and then the machine settles. Discarding
# it silently would make the campaign depend on a step nobody could see in the data, so it is
# labelled `warmup` and the reduction below sums only `spread` and `single`.
printf '
--- warm-up, discarded from the reduction
' | tee -a "$log"
flood spread
sleep 2
row=$(read_arm)
printf '0,warmup,%s
' "$row" >> "$csv"
printf '%s
' "$row" | tee -a "$log"
sleep 3

pass=1
while [ "$pass" -le "$PASSES" ]; do
    if [ $(( pass % 2 )) -eq 1 ]; then order="spread single"; else order="single spread"; fi
    for arm in $order; do
        printf '\n--- pass %s, arm %s\n' "$pass" "$arm" | tee -a "$log"
        flood "$arm"
        sleep 2
        row=$(read_arm)
        check_delivered "$arm" "$row"
        printf '%s,%s,%s\n' "$pass" "$arm" "$row" >> "$csv"
        printf '%s\n' "$row" | tee -a "$log"
        sleep 3
    done
    pass=$((pass + 1))
done

restore

# ---------------------------------------------------------------------------------------------
# The reduction, printed rather than left to a reader with a calculator. Per-packet figures with
# the idle baseline subtracted, per arm, and the difference that is the answer.
# ---------------------------------------------------------------------------------------------
printf '\n' | tee -a "$log"
awk -F, -v ev="$EVENTS" '
    NR == 1 { next }
    $2 == "idle" { for (i = 4; i <= NF - 1; i++) base[i] = $3 > 0 ? 0 : $i; next }
    $2 == "spread" || $2 == "single" {
        n[$2]++; pk[$2] += $3
        for (i = 4; i <= NF - 1; i++) { if ($i == "absent") gone[i] = 1; else sum[$2, i] += $i }
        if ($NF != "ok") flag = flag " " $2 ":" $NF
    }
    END {
        split(ev, name, ",")
        printf "%-26s %14s %14s %14s\n", "per packet", "spread", "single", "difference"
        for (i = 4; i <= NF - 1; i++) {
            if (gone[i]) { printf "%-26s %14s %14s %14s\n", name[i - 3], "absent", "absent", "absent"; continue }
            s = (sum["spread", i] - base[i] * n["spread"]) / pk["spread"]
            u = (sum["single", i] - base[i] * n["single"]) / pk["single"]
            printf "%-26s %14.4f %14.4f %14.4f\n", name[i - 3], s, u, s - u
        }
        if (flag != "") printf "\nREFUSED, counters were scaled:%s\n", flag
    }' "$csv" | tee -a "$log"

printf '\nCSV         %s\nlog         %s\nenvironment %s\n' \
    "$csv" "$log" "$OUT/$(basename "$env_remote")"
