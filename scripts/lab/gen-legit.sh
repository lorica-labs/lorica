#!/usr/bin/env bash
# The legitimate client, run alongside an attack. A thin wrapper over
# latency-probe load so campaign scripts have one name for "well-behaved traffic"
# and the probe binary lives in one place.
#
#   gen-legit.sh --profile {tcp-reqresp,udp-echo} --target ADDR --out DIR
#                [--duration S] [--rate PPS] [--gap-detect] [--env FILE]
#
# Runs on VM 902.

set -uo pipefail

PROBE=${CARAPACE_PROBE:-/tmp/latency-probe}
PROFILE=
TARGET=
OUT=
DURATION=30
RATE=
GAP=
ENV=

while [ $# -gt 0 ]; do
    case $1 in
        --profile)   PROFILE=$2; shift 2 ;;
        --target)    TARGET=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        --duration)  DURATION=$2; shift 2 ;;
        --rate)      RATE=$2; shift 2 ;;
        --gap-detect) GAP=--gap-detect; shift ;;
        --env)       ENV=$2; shift 2 ;;
        --probe)     PROBE=$2; shift 2 ;;
        -h|--help)   sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PROFILE" ] && [ -n "$TARGET" ] && [ -n "$OUT" ] \
    || { echo "gen-legit: --profile, --target and --out are required" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "gen-legit: no probe at $PROBE, deploy the latency-probe binary or pass --probe" >&2; exit 2; }

cmd=("$PROBE" load --profile "$PROFILE" --target "$TARGET" --duration "$DURATION" --out "$OUT" $GAP)
[ -n "$RATE" ] && cmd+=(--rate "$RATE")
[ -n "$ENV" ] && cmd+=(--env "$ENV")

exec "${cmd[@]}"
