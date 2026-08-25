#!/usr/bin/env bash
# What the agent writes to the journal at rest and under a flood, measured on both sides.
#
#   flood-log-volume.sh [--duration S] [--out DIR] [--agent PATH] [--object PATH]
#                       [--gen-host HOST] [--dst-ip IP] [--dst-port PORT]
#                       [--rate PPS] [--hz N] [--counters N] [--no-flood]
#
# Runs on VM 901 (the target). It drives VM 902 over SSH for the flood, because the claim
# is that the line count does not move with the packet rate and only a real flood can
# falsify that.
#
# The agent runs as a transient unit so its stderr is attributed to a unit in the journal:
# journald rate-limits per service, so a count that is not per service is a count of
# something else.
#
# Two numbers come out of the same window and neither is derived from the other: the lines
# journald stored for the unit, and the events the agent itself reported accounting in that
# window. The second one is what says the flood arrived. A run where it is zero has not
# measured the load phase, and this script then refuses to give a verdict rather than
# reporting the ratio it would have got from an idle link. That failure has shipped green
# twice here on a full disk, which is also why the free space of the journal filesystem is
# checked before anything starts: journald scales its rate-limit burst by that free space,
# so a full disk both breaks the run and silently lowers the ceiling being tested.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

DURATION=120
OUT=bench/results/log-volume
AGENT=target/release/loricad
OBJECT=crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf
GEN_HOST=lab-gen
GEN_SCRIPT='~/src/scripts/lab/gen-syn-flood.sh'
DST_IP=
DST_PORT=443
RATE=1000000
HZ=10
COUNTERS=50000
FLOOD=yes
UNIT=lorica-log-volume
# One gibibyte. Below this the journal filesystem is the variable under test instead of a
# constant of it.
MIN_FREE_KIB=1048576

while [ $# -gt 0 ]; do
    case $1 in
        --duration)  DURATION=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        --agent)     AGENT=$2; shift 2 ;;
        --object)    OBJECT=$2; shift 2 ;;
        --gen-host)  GEN_HOST=$2; shift 2 ;;
        --gen-script) GEN_SCRIPT=$2; shift 2 ;;
        --dst-ip)    DST_IP=$2; shift 2 ;;
        --dst-port)  DST_PORT=$2; shift 2 ;;
        --rate)      RATE=$2; shift 2 ;;
        --hz)        HZ=$2; shift 2 ;;
        --counters)  COUNTERS=$2; shift 2 ;;
        --no-flood)  FLOOD=no; shift ;;
        -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die()     { printf 'FAIL    %s\n' "$1" >&2; exit 1; }
# Exit 3 and never 0: a phase that was not measured is not a pass and not a failure of the
# agent, and the two must not be reported with the same code.
refuse()  { printf 'NO VERDICT  %s\n' "$1" >&2; exit 3; }

[ "$DURATION" -ge 20 ] || die "--duration under 20 s leaves each phase fewer than ten aggregate lines"
[ -r "$AGENT" ]  || die "--agent must be readable, got '$AGENT'"
[ -r "$OBJECT" ] || die "--object must be readable, got '$OBJECT'"
command -v systemd-run >/dev/null || die "systemd-run is missing, so the agent cannot be a unit"
command -v journalctl  >/dev/null || die "journalctl is missing, so the journal cannot be read"
sudo -n true 2>/dev/null || die "sudo requires a password; loading an XDP program needs CAP_BPF"

journal_dir=/var/log/journal
[ -d "$journal_dir" ] || journal_dir=/run/log/journal
free_kib=$(df --output=avail -k "$journal_dir" 2>/dev/null | tail -1 | tr -d ' ')
[ -n "$free_kib" ] || refuse "cannot read the free space of $journal_dir"
[ "$free_kib" -ge "$MIN_FREE_KIB" ] \
    || refuse "$free_kib KiB free on $journal_dir, under the $MIN_FREE_KIB KiB floor: journald scales its rate-limit burst by this number, so the ceiling under test would be the disk"

mkdir -p "$OUT" || die "cannot create $OUT"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
report=$OUT/log-volume-$stamp.txt
rest_log=$OUT/log-volume-$stamp.rest.log
load_log=$OUT/log-volume-$stamp.load.log

half=$((DURATION / 2))

cleanup() {
    sudo -n systemctl stop "$UNIT.service" 2>/dev/null
    [ "$FLOOD" = yes ] && ssh -o BatchMode=yes -o ConnectTimeout=10 "$GEN_HOST" 'pkill -f trafgen' 2>/dev/null
    return 0
}
trap cleanup EXIT

sudo -n systemctl reset-failed "$UNIT.service" 2>/dev/null

# --seconds is the agent stopping itself, so a run that loses its SSH still ends.
sudo -n systemd-run --unit="$UNIT" --collect --quiet \
    "$PWD/$AGENT" --object "$PWD/$OBJECT" --counters "$COUNTERS" --hz "$HZ" \
    --seconds $((DURATION + 10)) --metrics off --socket "/run/$UNIT.sock" \
    || die "the agent did not start as a unit"

# The first tick and the eBPF load are startup and belong to neither phase.
sleep 5

rest_from=$(date +%s)
sleep "$half"
rest_to=$(date +%s)

if [ "$FLOOD" = yes ]; then
    [ -n "$DST_IP" ] || refuse "--dst-ip is required to flood; pass --no-flood to say the load phase is deliberately not measured"
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$GEN_HOST" \
        "nohup bash $GEN_SCRIPT --dst-ip $DST_IP --dst-port $DST_PORT --rate $RATE --duration $((half + 5)) >/dev/null 2>&1 &" \
        || refuse "cannot start the flood on $GEN_HOST, so the load phase was not measured"
    sleep 2
fi

load_from=$(date +%s)
sleep "$half"
load_to=$(date +%s)

# Let journald settle, then read each window once into a file. Read from the file and never
# through a pipe into grep -q: grep exits at the first match, the upstream dies of SIGPIPE,
# and under pipefail the condition reads false with the pattern present.
sleep 3
sudo -n journalctl -u "$UNIT" --since "@$rest_from" --until "@$rest_to" --no-pager -o cat > "$rest_log"
sudo -n journalctl -u "$UNIT" --since "@$load_from" --until "@$load_to" --no-pager -o cat > "$load_log"

rest_lines=$(wc -l < "$rest_log" | tr -d ' ')
load_lines=$(wc -l < "$load_log" | tr -d ' ')
suppressed=$(grep -c 'Suppressed' "$rest_log" "$load_log" 2>/dev/null | awk -F: '{n += $2} END {print n + 0}')

# The events the agent reported accounting in the load window. Read out of its own digest
# lines, which is the only evidence available here that the flood reached the interface.
load_events=$(awk '{for (i = 1; i <= NF; i++) if (index($i, "events=") == 1) { split($i, kv, "="); n += kv[2] } } END {print n + 0}' "$load_log")
rest_events=$(awk '{for (i = 1; i <= NF; i++) if (index($i, "events=") == 1) { split($i, kv, "="); n += kv[2] } } END {print n + 0}' "$rest_log")
lost=$(awk '{for (i = 1; i <= NF; i++) if (index($i, "lost=") == 1) { split($i, kv, "="); v = kv[2] } } END {print v + 0}' "$load_log")

{
    echo "flood-log-volume $stamp"
    echo "host=$(hostname)  kernel=$(uname -r)  systemd=$(systemctl --version | head -1)"
    echo "journal_dir=$journal_dir  free_kib=$free_kib"
    echo "duration=$DURATION  half=$half  hz=$HZ  counters=$COUNTERS  rate=$RATE  flood=$FLOOD"
    echo "rest_window=$rest_from..$rest_to  lines=$rest_lines  events=$rest_events"
    echo "load_window=$load_from..$load_to  lines=$load_lines  events=$load_events"
    echo "suppressed=$suppressed  lost_reported_by_agent=$lost"
} | tee "$report"

[ "$rest_lines" -gt 0 ] \
    || refuse "the unit wrote no line in the rest window: the agent was not logging, so there is no denominator"
if [ "$FLOOD" = yes ]; then
    [ "$load_events" -gt 0 ] \
        || refuse "the agent accounted no event in the load window: the flood did not reach it, so the load phase was not measured"
else
    refuse "--no-flood was passed: the rest phase above is real and the load phase does not exist, so no ratio is reported"
fi

status=0
# Three, and the three are named: detected, mitigating, cleared. Anything the packet rate
# adds lands past this.
if [ "$load_lines" -gt $((rest_lines + 3)) ]; then
    printf 'FAIL    %s lines under load against %s at rest: the emission follows the traffic\n' \
        "$load_lines" "$rest_lines" >&2
    status=1
fi
if [ "$suppressed" -gt 0 ]; then
    printf 'FAIL    journald reported suppressing messages from %s\n' "$UNIT" >&2
    status=1
fi
if [ "$lost" -gt 0 ]; then
    printf 'FAIL    the agent reported %s writes it could not hand to the journal\n' "$lost" >&2
    status=1
fi

[ "$status" -eq 0 ] && printf 'PASS    %s lines under load against %s at rest, %s events accounted, 0 suppressed\n' \
    "$load_lines" "$rest_lines" "$load_events"
echo "report: $report"
exit "$status"
