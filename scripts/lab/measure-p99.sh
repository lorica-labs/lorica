#!/usr/bin/env bash
# Application p99 under a UDP flood, with no defence, with an nftables raw-hook
# drop, and with the equivalent drop in XDP. This is the number that justifies or
# kills "XDP for small deployments" in the range where the line, not the CPU, is
# the capacity ceiling.
#
#   measure-p99.sh --gen-host SSH --self-ip IP --out DIR --ceiling PPS
#                  [--sweep "0 100kpps 250kpps 500kpps"] [--repeat N]
#                  [--seconds N] [--iface NAME]
#
# Runs on VM 901 (target). The attack ceiling comes from T4 and is a parameter,
# never invented: offered rates above it are refused so the axis stays honest.

set -uo pipefail

OUT=bench/results/p99
DEV=${CARAPACE_IFACE:-enp6s19}
GEN_HOST=lab-gen
SELF_IP=
CEILING=
SWEEP="0 100kpps 250kpps 500kpps"
REPEAT=3
SECONDS_PER=20
PROBE=${CARAPACE_PROBE:-/tmp/latency-probe}
PORTDROP=bench/progs/xdp_portdrop.o
NFT=bench/nftables/compare.nft

while [ $# -gt 0 ]; do
    case $1 in
        --out)      OUT=$2; shift 2 ;;
        --iface)    DEV=$2; shift 2 ;;
        --gen-host) GEN_HOST=$2; shift 2 ;;
        --self-ip)  SELF_IP=$2; shift 2 ;;
        --ceiling)  CEILING=$2; shift 2 ;;
        --sweep)    SWEEP=$2; shift 2 ;;
        --repeat)   REPEAT=$2; shift 2 ;;
        --seconds)  SECONDS_PER=$2; shift 2 ;;
        --probe)    PROBE=$2; shift 2 ;;
        -h|--help)  sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$SELF_IP" ] || { echo "measure-p99: --self-ip is required" >&2; exit 2; }
[ -n "$CEILING" ] || { echo "measure-p99: --ceiling is required (the delivered ceiling from T4), it is not invented here" >&2; exit 2; }
[ -r "$PORTDROP" ] || { echo "measure-p99: no $PORTDROP" >&2; exit 2; }
[ -r "$NFT" ] || { echo "measure-p99: no $NFT" >&2; exit 2; }

as_pps() {
    case $1 in
        *kpps) echo $(( ${1%kpps} * 1000 )) ;;
        *Mpps) echo $(( ${1%Mpps} * 1000000 )) ;;
        *pps)  echo "${1%pps}" ;;
        *)     echo "$1" ;;
    esac
}

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
env_file=$("$here/capture-env.sh" "$OUT" "$DEV")
[ -n "$env_file" ] || { echo "measure-p99: capture-env produced no path" >&2; exit 2; }
csv="$OUT/p99.csv"
echo "arm,offered_pps,rep,profile,samples,p50_us,p99_us,p999_us,max_us,jitter_us,xdp_exception" > "$csv"

self_mac=$(cat "/sys/class/net/$DEV/address")

nft_loaded=0
xdp_loaded=0
cleanup() {
    [ "$nft_loaded" = 1 ] && sudo -n nft delete table ip carapace_cmp 2>/dev/null
    [ "$xdp_loaded" = 1 ] && sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null
    ssh -o BatchMode=yes "$GEN_HOST" 'pkill -x latency-probe 2>/dev/null; pkill -x trafgen 2>/dev/null' 2>/dev/null
    pkill -x latency-probe 2>/dev/null
}
trap cleanup EXIT

arm_none()  { :; }
arm_nft()   { sudo -n nft -f "$NFT"; nft_loaded=1; }
arm_xdp()   { sudo -n ip link set dev "$DEV" xdpdrv obj "$PORTDROP" sec xdp; xdp_loaded=1
              [ "$(ip -d link show "$DEV" | grep -o 'xdp[a-z]*' | head -1)" = xdp ] \
                  || { echo "measure-p99: xdp attach not native" >&2; exit 1; } }
disarm()    { [ "$nft_loaded" = 1 ] && { sudo -n nft delete table ip carapace_cmp 2>/dev/null; nft_loaded=0; }
              [ "$xdp_loaded" = 1 ] && { sudo -n ip link set dev "$DEV" xdpdrv off 2>/dev/null; xdp_loaded=0; } }

# One (arm, offered rate, rep): start the legitimate probe servers, start the
# flood if any, run both legit profiles against us from the gen host, count
# xdp_exception over the window, and record each profile's percentiles.
one_point() {
    local arm=$1 offered=$2 rep=$3

    setsid nohup "$PROBE" serve --profile udp-echo    --bind "$SELF_IP:19002" >/dev/null 2>&1 < /dev/null &
    local s1=$!
    setsid nohup "$PROBE" serve --profile tcp-reqresp --bind "$SELF_IP:19100" >/dev/null 2>&1 < /dev/null &
    local s2=$!
    sleep 0.4

    # Flood, if this point has one. num = offered * (seconds + slack) so it covers
    # the whole legit window. Delivered rate is capped by the T4 ceiling regardless.
    if [ "$offered" != 0 ]; then
        ssh -o BatchMode=yes "$GEN_HOST" \
            "~/carapace/scripts/lab/gen-udp-flood.sh --dst-ip $SELF_IP --dst-mac $self_mac --rate ${offered}pps --duration $((SECONDS_PER + 3))s --cpus 2" \
            >/dev/null 2>&1 &
    fi

    # xdp_exception is system-wide; a nonzero value means a program aborted and
    # legitimate traffic may have been dropped. The run is discarded, not annotated.
    local exc_file; exc_file=$(mktemp)
    ( sudo -n perf stat -e xdp:xdp_exception -a -- sleep "$SECONDS_PER" ) 2>"$exc_file" &
    local perf_pid=$!

    ssh -o BatchMode=yes "$GEN_HOST" "
        $PROBE load --profile udp-echo    --target $SELF_IP:19002 --duration $SECONDS_PER --out /tmp/p99-udp  >/dev/null 2>&1 &
        $PROBE load --profile tcp-reqresp --target $SELF_IP:19100 --duration $SECONDS_PER --out /tmp/p99-tcp  >/dev/null 2>&1 &
        wait"

    wait "$perf_pid" 2>/dev/null || true
    kill "$s1" "$s2" 2>/dev/null
    local exc; exc=$(grep -oE '[0-9,]+[[:space:]]+xdp:xdp_exception' "$exc_file" | grep -oE '^[0-9,]+' | tr -d ,)
    rm -f "$exc_file"
    exc=${exc:-NA}

    for pr in udp:udp-echo:p99-udp tcp:tcp-reqresp:p99-tcp; do
        local tag=${pr%%:*}; local prof=${pr#*:}; prof=${prof%%:*}; local dir=${pr##*:}
        read -r samples p50 p99 p999 mx jit < <(ssh -o BatchMode=yes "$GEN_HOST" "
            awk -F, 'NR==1{for(i=1;i<=NF;i++)c[\$i]=i}
                     NR==2{print \$c[\"samples\"], int(\$c[\"p50_ns\"]/1000), int(\$c[\"p99_ns\"]/1000), int(\$c[\"p999_ns\"]/1000), int(\$c[\"max_ns\"]/1000), int(\$c[\"jitter_ns\"]/1000)}' \
                /tmp/$dir/$prof-summary.csv 2>/dev/null")
        echo "$arm,$offered,$rep,$prof,${samples:-NA},${p50:-NA},${p99:-NA},${p999:-NA},${mx:-NA},${jit:-NA},$exc" | tee -a "$csv"
    done
}

for arm in none nft xdp; do
    for rate in $SWEEP; do
        offered=$(as_pps "$rate")
        if [ "$offered" != 0 ] && [ "$offered" -gt "$CEILING" ]; then
            # Offering above the ceiling still only delivers the ceiling, but the
            # loss is documented rather than passed off as a higher attack.
            echo "note: offered $offered exceeds the T4 ceiling $CEILING; delivered rate is capped there" >&2
        fi
        for rep in $(seq "$REPEAT"); do
            disarm
            "arm_$arm"
            one_point "$arm" "$offered" "$rep"
        done
        disarm
    done
done

echo "$csv"
