#!/usr/bin/env bash
# Put a legitimate reference capture back on the lab wire, at a stated rate, so the
# target can be asked whether its XDP program dropped any of it.
#
#   replay-legit.sh --pcap FILE | --all [--rate PPS] [--out DIR] [--dev NAME]
#                   [--engine tcpreplay|trafgen] [--assert-zero-drop]
#
# Runs on VM 902 (generator). It attaches nothing. bpftool cannot load this
# repository's object — aya emits legacy map definitions libbpf dropped in 1.0 — and
# the only code here that attaches to a real interface is the kernel-test harness,
# which runs on the target. So the receiver's half of the criterion, every drop
# counter at zero and xdp:xdp_exception at zero, is read on the target by a Rust test
# holding the program, and this script owns the one drop the sender can see: a packet
# that never left. A trace the generator failed to send would make the target's zero
# mean nothing at all.
#
# The rate is always printed with the result, and which engine paced it, because the two
# engines here do not pace the same way at all.
#
# tcpreplay replays a capture with its own inter-packet timing and is the default. That
# matters for one reason and it is not fidelity for its own sake: the leaky buckets are a
# rate limiter, so a legitimate capture replayed at a constant high rate trips them and
# produces drops that are not false positives of the signatures. An instrument that
# manufactures the drops it is measuring measures nothing.
#
# trafgen stays reachable behind --engine trafgen. It needs the .cfg that netsniff-ng
# writes, and that conversion keeps the packet bytes and discards the inter-packet
# timing, so the replay is paced at a constant rate. Four of the seven stages are
# stateless and indifferent to pacing; stage 7 is not. Without --rate the constant rate
# defaults to the trace's own packets-divided-by-span, never to a round number.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

DEV=${LORICA_IFACE:-enp6s19}
OUT=bench/results/legit-replay
TRACES=bench/traces
PCAP=
ALL=0
RATE=
ASSERT=0
ENGINE=tcpreplay

# One CPU, not a flag. trafgen splits its packet list across the CPUs it is given and
# sends the parts in parallel, which reorders the trace; a capture whose order is
# scrambled is no longer the capture, and a handshake that arrives after its own data
# is a packet sequence the trace never contained.
CPUS=1

while [ $# -gt 0 ]; do
    case $1 in
        --pcap)             PCAP=$2; shift 2 ;;
        --all)              ALL=1; shift ;;
        --rate)             RATE=$2; shift 2 ;;
        --out)              OUT=$2; shift 2 ;;
        --dev)              DEV=$2; shift 2 ;;
        --traces)           TRACES=$2; shift 2 ;;
        --engine)           ENGINE=$2; shift 2 ;;
        --assert-zero-drop) ASSERT=1; shift ;;
        -h|--help)          sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'replay-legit: %s\n' "$1" >&2; exit 2; }

[ -n "$PCAP" ] || [ "$ALL" = 1 ] || die "one of --pcap FILE or --all is required"
[ -z "$PCAP" ] || [ "$ALL" = 0 ] || die "--pcap and --all are mutually exclusive"
command -v python3 >/dev/null || die "no python3: the trace scan that derives the default rate needs it"

case $ENGINE in
    tcpreplay)
        command -v tcpreplay >/dev/null \
            || die "no tcpreplay: it is what preserves the capture inter-packet timing. Pass --engine trafgen to pace at a constant rate instead, and read what that costs in the header of this script" ;;
    trafgen)
        command -v netsniff-ng >/dev/null || die "no netsniff-ng: the pcap to trafgen conversion needs it"
        command -v trafgen >/dev/null || die "no trafgen" ;;
    *) die "unknown engine $ENGINE: expected tcpreplay or trafgen" ;;
esac

# The 902 has a second, live NIC — enp6s18 on the house LAN — and generated traffic on
# it leaks onto a real network. So the interface is not warned about, it is verified:
# only a device addressed inside the lab test subnet is accepted, which leaves the LAN
# NIC no way to be passed here by mistake.
subnet=${LORICA_TEST_SUBNET:-10.90.1.}
addr=$(ip -4 -o addr show dev "$DEV" 2>/dev/null | awk 'NR==1 {print $4}')
[ -n "$addr" ] || die "$DEV has no IPv4 address, so it cannot be checked against the test subnet $subnet"
case $addr in
    "$subnet"*) ;;
    *) die "$DEV is $addr, outside the test subnet $subnet. Refusing: this would put generated traffic on a live network" ;;
esac

# Packets, span in seconds, and the rate derived from the two. The refusals matter more
# than the numbers: a magic this scan does not know, a record running past the end of
# the file or a trailing tail would all otherwise produce a plausible packet count for
# a file that was never read to the end, and trafgen would replay a truncated trace.
scan_pcap() {
    python3 - "$1" <<'PY'
import struct, sys

raw = open(sys.argv[1], "rb").read()
if len(raw) < 24:
    sys.exit("%s is not even a pcap global header" % sys.argv[1])
magic, = struct.unpack("<I", raw[:4])
if magic == 0xa1b2c3d4:
    end = "<"
elif magic == 0xd4c3b2a1:
    end = ">"
else:
    sys.exit("%s opens with %#010x, not a classic pcap magic" % (sys.argv[1], magic))
link, = struct.unpack(end + "I", raw[20:24])
if link != 1:
    sys.exit("%s is linktype %d, not Ethernet" % (sys.argv[1], link))

at, n, first, last = 24, 0, None, None
while at + 16 <= len(raw):
    sec, usec, cap, orig = struct.unpack(end + "IIII", raw[at:at + 16])
    at += 16
    if at + cap > len(raw):
        sys.exit("record %d of %s runs past the end of the file" % (n + 1, sys.argv[1]))
    at += cap
    n += 1
    stamp = sec + usec / 1e6
    first = stamp if first is None else first
    last = stamp
if at != len(raw):
    sys.exit("%d bytes trail the last record of %s" % (len(raw) - at, sys.argv[1]))
if n == 0:
    sys.exit("%s holds no packet" % sys.argv[1])

span = last - first
rate = max(1, round(n / span)) if span > 0 else 0
print("%d %.6f %d" % (n, span, rate))
PY
}

stat_of() { cat "/sys/class/net/$DEV/statistics/$1"; }

mkdir -p "$OUT"
env_file=$(scripts/lab/capture-env.sh "$OUT" "$DEV")
[ -n "$env_file" ] || die "capture-env produced no path"
csv="$OUT/legit-replay.csv"
echo "trace,engine,packets,span_s,rate_pps,sent,tx_dropped,tx_errors,verdict" > "$csv"

cfg=$(mktemp --suffix=.trafgen)
log=$(mktemp)
trap 'rm -f "$cfg" "$log"' EXIT

if [ "$ALL" = 1 ]; then
    traces=("$TRACES"/*.pcap)
    [ -e "${traces[0]}" ] || die "no *.pcap in $TRACES"
else
    [ -r "$PCAP" ] || die "cannot read $PCAP"
    traces=("$PCAP")
fi

status=0
for pcap in "${traces[@]}"; do
    scan=$(scan_pcap "$pcap") || die "$pcap did not scan as a classic pcap (above)"
    read -r packets span derived <<EOF
$scan
EOF
    [ -n "${packets:-}" ] && [ -n "${derived:-}" ] || die "the scan of $pcap produced no packet count"

    if [ -n "$RATE" ]; then
        rate=${RATE%pps}
    elif [ "$derived" = 0 ]; then
        die "$pcap spans no time, so no rate can be derived from it: pass --rate"
    else
        rate=$derived
    fi

    if [ "$ENGINE" = trafgen ]; then
        netsniff-ng --in "$pcap" --out "$cfg" --silent \
            || die "netsniff-ng could not convert $pcap"
    fi

    before_dropped=$(stat_of tx_dropped)
    before_errors=$(stat_of tx_errors)
    if [ "$ENGINE" = tcpreplay ]; then
        # No --pps unless one was asked for: the point of this engine is that the pacing
        # comes from the capture. --pps overrides it, so passing --rate here means asking
        # for a rate the trace never had, deliberately.
        pace=()
        [ -z "$RATE" ] || pace=(--pps="$rate")
        sudo -n tcpreplay --intf1="$DEV" --stats=1 "${pace[@]}" "$pcap" > "$log" 2>&1
    else
        sudo -n trafgen --in "$cfg" --out "$DEV" --rate "${rate}pps" --cpus "$CPUS" \
            --num "$packets" --no-sock-mem > "$log" 2>&1
    fi
    after_dropped=$(stat_of tx_dropped)
    after_errors=$(stat_of tx_errors)

    # The engine's own count of what it put on the wire, taken from the saved log rather
    # than from a pipeline: `trafgen | grep -q` under pipefail returns 141 because grep
    # exits first and trafgen dies of SIGPIPE.
    if [ "$ENGINE" = tcpreplay ]; then
        sent=$(awk '/^Actual:/ { n = $2 } END { print n }' "$log")
    else
        sent=$(awk '/packets outgoing/ { n = $1 } END { print n }' "$log")
    fi
    dropped=$(( after_dropped - before_dropped ))
    errors=$(( after_errors - before_errors ))

    if [ -z "$sent" ]; then
        verdict=no-send-report
    elif [ "$sent" != "$packets" ]; then
        verdict=short-send
    elif [ "$dropped" != 0 ] || [ "$errors" != 0 ]; then
        verdict=tx-loss
    else
        verdict=sent-whole
    fi

    # With tcpreplay and no --rate the pacing is the trace's own, packet by packet, and
    # the figure printed is its average. Naming it "mean" rather than "rate" keeps it from
    # being read as a rate that was imposed.
    if [ "$ENGINE" = tcpreplay ] && [ -z "$RATE" ]; then label=mean; else label=rate; fi
    printf 'replay-legit: trace=%s engine=%s dev=%s packets=%s span=%ss %s=%spps sent=%s tx_dropped=%s tx_errors=%s -> %s\n' \
        "$(basename "$pcap")" "$ENGINE" "$DEV" "$packets" "$span" "$label" "$rate" "${sent:-none}" "$dropped" "$errors" "$verdict"
    echo "$(basename "$pcap"),$ENGINE,$packets,$span,$rate,${sent:-NA},$dropped,$errors,$verdict" >> "$csv"

    # The flag decides the exit status, never what is measured or printed: a number that
    # only appears when it is being asserted on is a number nobody can compare against.
    [ "$verdict" = sent-whole ] || [ "$ASSERT" = 0 ] || status=1
done

echo "$csv"
exit "$status"
