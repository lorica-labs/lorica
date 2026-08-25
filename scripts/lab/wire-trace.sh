#!/usr/bin/env bash
# Replay the legitimate reference capture on the lab wire and read what the program decided.
#
#   wire-trace.sh [--pcap FILE] [--window-ms N] [--iface NAME] [--engine tcpreplay|trafgen]
#                 [--out DIR]
#
# Runs on the development host and drives both lab machines, because the criterion has two
# halves on two machines and neither half is worth anything alone.
#
# The sender's half is `replay-legit.sh` on the generator: the whole trace left the wire,
# at the capture's own inter-packet timing. A trace the generator failed to send would make
# the target's zero mean nothing.
#
# The receiver's half is the `wire_trace` test on the target: it holds the program attached
# natively for a window, then reports every drop counter, every signature counter, and
# `xdp:xdp_exception`. `bpftool` cannot load this repository's object, so holding it is a
# Rust test and not a command.
#
# The two are sequenced rather than raced. The holder prints a ready line the moment the
# program is attached and the tracepoint is armed, and this script waits for that line
# before it lets the generator send: a replay into a window that has not opened yet reads
# as a trace that arrived and was not judged.
#
# What this measures that the offline half cannot. `legit_trace.rs` runs the same 44 packets
# through `BPF_PROG_TEST_RUN`, which honours no timestamp: the packets go through back to
# back and the leaky buckets see the whole trace inside a jiffy or two. Here the frames
# cross a real driver at the pacing they were captured at. That is the only place the
# seventh stage is judged on timing rather than on volume, and it is why `tcpreplay` was
# installed on the generator.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
GEN_HOST=${LORICA_GEN_HOST:-lab-gen}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run}

PCAP=bench/traces/legit-ref.pcap
# The default trace spans 28 s, and 45000 was not enough for it: a run of this script with
# every default delivered 39 of the 44 frames, because the window opens before the generator
# is built and shipped and closes on the tail of the replay. It refused rather than reporting
# the drops=0 it had, which is what the guard is for -- but a default that cannot hold the
# default input is a trap for whoever runs it next. 75000 holds it with room; a longer trace
# still needs --window-ms.
WINDOW_MS=75000
IFACE=${LORICA_IFACE:-enp6s19}
ENGINE=tcpreplay
OUT=bench/results/wire-trace

while [ $# -gt 0 ]; do
    case $1 in
        --pcap)      PCAP=$2; shift 2 ;;
        --window-ms) WINDOW_MS=$2; shift 2 ;;
        --iface)     IFACE=$2; shift 2 ;;
        --engine)    ENGINE=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

[ -r "$PCAP" ] || die "cannot read $PCAP"

mkdir -p "$OUT"

# The environment that matters is the target's, not this host's: the target is where the
# program ran and where the interface is. So it is captured there and fetched, the way the
# stage-cost campaign does it.
env_remote=$(bash scripts/lab/deploy.sh "$TARGET_HOST" \
    "bash scripts/lab/capture-env.sh . $IFACE" 2>/dev/null | tail -1)
if [ -n "$env_remote" ]; then
    remote "$TARGET_HOST" "cat ~/$REMOTE_DIR/$env_remote" > "$OUT/$(basename "$env_remote")" \
        && echo "wire-trace: environment $OUT/$(basename "$env_remote")"
else
    echo "wire-trace: capture-env produced no path on $TARGET_HOST, continuing without it" >&2
fi

holder=$OUT/holder.log
sender=$OUT/sender.log
: > "$holder"
: > "$sender"

# The holder is built on the build VM and shipped, like every other measurement: the target
# has the kernel and no toolchain. Built here rather than inside the background job so a
# build failure is a failure of this script and not a window that never opens.
echo "wire-trace: building and shipping the holder"
LORICA_IFACE=$IFACE LORICA_WIRE_WINDOW_MS=$WINDOW_MS \
    bash scripts/lab/deploy.sh "$BUILD_HOST" \
        "bash scripts/lab/target-build.sh --test wire_trace --plain" \
    || die "the holder build on $BUILD_HOST failed"

remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
    | remote "$TARGET_HOST" "rm -rf ~/$RUN_DIR && mkdir -p ~/$RUN_DIR && tar xf - -C ~/$RUN_DIR" \
    || die "could not ship the holder to $TARGET_HOST"

# --nocapture, without which libtest holds the ready line until the test ends and the
# window would always be missed.
echo "wire-trace: holding the program on $TARGET_HOST:$IFACE for ${WINDOW_MS}ms"
remote "$TARGET_HOST" \
    "LORICA_IFACE=$IFACE LORICA_WIRE_WINDOW_MS=$WINDOW_MS bash ~/$RUN_DIR/target-tests/target-run.sh --nocapture" \
    > "$holder" 2>&1 &
holder_pid=$!

# Wait for the window to open rather than sleeping a guessed amount. A fixed sleep is how a
# campaign silently measures an empty window on a day the target is slow.
# The phase is part of the pattern, and that is not pedantry. The holder binary also runs a
# self-check on a veth of its own, which prints its own ready line first; waiting for any
# ready line let the replay start against the self-check's window and the campaign window
# then opened afterwards. It passed, by luck, and a campaign that synchronises by luck is
# not a campaign.
waited=0
while ! grep -q 'LORICA_WIRE_READY.*phase=replay' "$holder"; do
    kill -0 "$holder_pid" 2>/dev/null \
        || die "the holder exited before the replay window opened; see $holder"
    [ "$waited" -lt 180 ] || die "the replay window never opened; see $holder"
    sleep 1
    waited=$((waited + 1))
done
grep 'LORICA_WIRE_READY.*phase=replay' "$holder" | tail -1

echo "wire-trace: replaying $(basename "$PCAP") from $GEN_HOST"
LORICA_REMOTE_DIR=$REMOTE_DIR bash scripts/lab/deploy.sh "$GEN_HOST" \
    "bash scripts/lab/replay-legit.sh --pcap $PCAP --engine $ENGINE --dev $IFACE --assert-zero-drop --out /tmp/wire-trace" \
    > "$sender" 2>&1
sender_status=$?
grep -E '^replay-legit:' "$sender" || cat "$sender"

wait "$holder_pid"
holder_status=$?

verdict_line=$(grep -E '^LORICA_WIRE ' "$holder" | grep 'phase=replay' | tail -1)
[ -n "$verdict_line" ] || die "the holder printed no verdict line; see $holder"
echo "$verdict_line"

record=$OUT/wire-trace.txt
{
    echo "pcap=$(basename "$PCAP") iface=$IFACE engine=$ENGINE window_ms=$WINDOW_MS"
    grep -E '^replay-legit:' "$sender"
    grep -E '^LORICA_WIRE' "$holder"
} > "$record"
echo "$record"

# Both halves have to pass, and the sender's is checked first because a short send makes the
# receiver's zero meaningless rather than reassuring.
[ "$sender_status" -eq 0 ] || die "the generator did not put the whole trace on the wire; see $sender"
case $verdict_line in
    *verdict=pass*) ;;
    *) die "the program did not pass the whole trace: $verdict_line" ;;
esac
[ "$holder_status" -eq 0 ] || die "the holder reported a failure; see $holder"

# Zero drops beside too few arrivals is a window that missed the replay, and it reads
# exactly like a pass. The holder asserts only that something arrived, because it cannot
# know what was sent; this script knows both, so this is where the two are compared. The
# comparison is one-sided: GRO can coalesce arrivals, and the interface also carries ARP and
# neighbour discovery of its own, so the count is not expected to match.
sent=$(grep -E '^replay-legit:' "$sender" | tr ' ' '\n' | grep '^sent=' | cut -d= -f2 | tail -1)
arrived=$(echo "$verdict_line" | tr ' ' '\n' | grep '^rx_packets=' | cut -d= -f2)
[ -n "$sent" ] && [ -n "$arrived" ] \
    || die "could not read what was sent ($sent) against what arrived ($arrived)"
[ "$arrived" -ge "$sent" ] \
    || die "$arrived frames arrived where $sent were sent, so the window did not hold the whole replay"
echo "wire-trace: $sent frames sent, $arrived arrived, none refused"

echo "wire-trace: zero legitimate drop on the wire, both halves agree"
