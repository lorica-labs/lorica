#!/usr/bin/env bash
# Check the CPU topology against the hypotheses the oploy-pve-02 partitioning plan rests on.
#
#   check-topology.sh
#
# Read-only. It runs lscpu, and qm on a Proxmox host. It writes nothing, changes nothing,
# and takes no argument: it is the gate in front of the pinning, never a part of it.
#
# Why this one gates all the others. The plan keeps the measurement islands away from the
# machine's own load by leaving the SMT siblings of those islands empty. Which CPUs those
# siblings are is an assumption -- the sibling of N is N+28 -- and if that assumption is
# wrong the lists below do the exact opposite of what they exist for: they park the islands
# on the siblings of the load they are supposed to be fleeing. That is why a mismatch here
# is a failure and not a warning, and why nothing downstream may be applied until it is
# resolved.
#
# Where the numbers come from. Every CPU list is transcribed from the measurement journal,
# docs/mesures/hyperviseur-recommandations.md section 2, table "Plan applique le 27 aout"
# (option B, vNUMA 2x10) -- not the mono-socket option A of section 3, which was tried and
# killed by the OOM killer. A number copied out of a document into a script goes stale in
# silence, so the transcription is made recheckable rather than trusted: the three sibling
# lists are recomputed from the offset and compared against the literals the document
# states, and the seven role lists must partition 0..55 exactly, each CPU exactly once. A
# stale copy then surfaces here as a failure instead of as a quiet mispinning later.
#
# What it cannot do from a guest. The emptiness of the twelve sibling CPUs is a statement
# about VMs, and only the Proxmox host can read that. On a host the script crosses the
# lists with qm; anywhere else it prints the table and the pairs to check by hand and says
# so on the closing line, because a guest that answered "empty" would be inventing it.

set -uo pipefail

case ${1:-} in
    '') ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "check-topology.sh takes no argument: it only reads" >&2; exit 2 ;;
esac

ok()   { printf 'ok    %s\n' "$1"; }
note() { printf 'note  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n      fix: %s\n' "$1" "$2" >&2; exit 1; }

# --- the plan, transcribed ----------------------------------------------------
# Source: hyperviseur-recommandations.md section 2, table "Plan applique le 27 aout".
# The order of the two arrays is load-bearing: index i of PLAN_LABELS describes index i
# of PLAN_CPUS. They are two arrays rather than one "label:cpus" string because a label
# holds spaces and splitting it back out is one more thing to get wrong.
SIBLING_OFFSET=28

PLAN_LABELS=(
    "VM 104 k3s, vNUMA 2x10"
    "VM 900 build"
    "VM 901 measurement"
    "VM 902 generator"
    "host measurement island"
    "host housekeeping and IRQ"
    "left empty: siblings of the three islands"
)
PLAN_CPUS=(
    "0,2,4,6,8,28,30,32,34,36,9,11,13,15,17,37,39,41,43,45"
    "10,12,14,16,38,40,42,44"
    "20,22,24,26"
    "1,3,5,7"
    "21,23,25,27"
    "18,19,46,47"
    "48,50,52,54,29,31,33,35,49,51,53,55"
)

# The three islands and the sibling lists the document states for them. The script does not
# take these last three on trust: it derives them from SIBLING_OFFSET and compares.
ISLAND_LABELS=("VM 901" "VM 902" "host island")
ISLAND_CPUS=("20,22,24,26" "1,3,5,7" "21,23,25,27")
ISLAND_SIBLINGS_DOC=("48,50,52,54" "29,31,33,35" "49,51,53,55")

# --- helpers ------------------------------------------------------------------

# "0-3,8,10-11" -> "0 1 2 3 8 10 11". Proxmox writes affinity as a cpuset string, where a
# range is legal, so a plain tr ',' ' ' would read 0-9 as one bogus CPU and match nothing.
expand_list() {
    printf '%s\n' "$1" | tr ',' '\n' \
        | awk -F- 'NF == 2 && $1 != "" { for (i = $1; i <= $2; i++) print i; next }
                   NF == 1 && $1 != "" { print $1 }'
}

# Sorted, deduplicated, comma-joined. Both sides of every list comparison go through it,
# so "48,50,52,54" and "54,50,48,52" compare equal and only a real difference fails.
normalise() {
    expand_list "$1" | sort -n -u | paste -sd, -
}

# A wrong topology is wrong for all 28 cores at once, and 28 findings on one line hide the
# fix under the evidence. Three and a count say the same thing: the table above holds the
# rest, which is the other reason it is printed unconditionally.
summarise() {
    total=$(printf '%s\n' "$1" | wc -l | tr -d ' ')
    head=$(printf '%s\n' "$1" | head -3 | tr '\n' ';')
    if [ "$total" -gt 3 ]; then
        printf '%s and %d more, see the table above' "$head" "$((total - 3))"
    else
        printf '%s' "$head"
    fi
}

# The CPUs of $1 that also appear in $2, space separated, empty when they are disjoint.
intersect() {
    # Membership through awk rather than `comm`, and the reason is a real failure this script
    # produced on its first run against the hypervisor: `comm` compares byte by byte and wants
    # its input sorted the same way, while `sort -n` orders 2 before 10 and the collating order
    # puts "10" before "2". `comm` then printed `input is not in sorted order` on stderr, kept
    # going, and returned a result nobody could trust -- under which the emptiness of the twelve
    # sibling CPUs came back "ok" from a comparison the tool had just disowned. awk holds one
    # side in a hash and asks about the other, so no ordering is assumed anywhere.
    expand_list "$1" | sort -n -u > "$TMP/a"
    expand_list "$2" | sort -n -u \
        | awk 'NR == FNR { seen[$1]; next } $1 in seen' "$TMP/a" - \
        | tr '\n' ' ' | sed 's/ *$//'
}

TMP=$(mktemp -d) || { echo "cannot create a temporary directory" >&2; exit 2; }
trap 'rm -rf "$TMP"' EXIT

# sudo only where it is needed, and not at all when we are already root. qm reads the
# cluster config under /etc/pve and needs privilege; lscpu does not, and asking for sudo
# to run it would make the script refuse to work on a guest for no reason.
if [ "$(id -u)" = 0 ]; then
    qm_read() { qm "$@"; }
else
    qm_read() { sudo -n qm "$@"; }
fi

# --- read the topology --------------------------------------------------------

command -v lscpu >/dev/null 2>&1 \
    || fail "lscpu is not installed" "apt install util-linux"

# -e=CPU,NODE,CORE and nothing else: the wide form of lscpu -e reorders and renames columns
# between util-linux releases, and a positional read of it breaks silently. Asking for the
# three columns by name pins their order.
TOPO=$(lscpu -e=CPU,NODE,CORE 2>/dev/null | sed 1d)
[ -n "$TOPO" ] \
    || fail "lscpu -e=CPU,NODE,CORE returned nothing" \
            "run it by hand: this host exposes no per-CPU topology and the plan cannot be checked"

printf '%s\n' "$TOPO" > "$TMP/topo"

NCPU=$(wc -l < "$TMP/topo" | tr -d ' ')
NNODE=$(awk '{ print $2 }' "$TMP/topo" | sort -u | wc -l | tr -d ' ')
NODES=$(awk '{ print $2 }' "$TMP/topo" | sort -n -u | paste -sd, -)

printf 'check-topology: host=%s\n' "$(uname -n)"
printf 'topo.cpus=%s\n' "$NCPU"
printf 'topo.nodes=%s\n' "$NODES"
printf 'topo.sibling_offset_assumed=%s\n' "$SIBLING_OFFSET"

# The table is printed unconditionally, before any verdict. Every claim below is read off
# it, and a reader who disagrees with a verdict needs the evidence in the same output --
# on a machine that fails the first control it is the only useful thing the script has.
echo
echo "CPU NODE CORE"
cat "$TMP/topo"
echo

# --- the plan's own consistency ----------------------------------------------
# Checked before anything is read off the hardware, because it is a check on the
# transcription and not on the machine: it must fail identically on a laptop.

for i in "${!ISLAND_CPUS[@]}"; do
    derived=$(expand_list "${ISLAND_CPUS[$i]}" \
        | awk -v off="$SIBLING_OFFSET" '{ print $1 + off }' | sort -n -u | paste -sd, -)
    stated=$(normalise "${ISLAND_SIBLINGS_DOC[$i]}")
    [ "$derived" = "$stated" ] \
        || fail "the plan's sibling list for ${ISLAND_LABELS[$i]} is $stated, but ${ISLAND_CPUS[$i]} plus $SIBLING_OFFSET gives $derived" \
                "one of the two was mistyped when the table was transcribed: reread hyperviseur-recommandations.md section 2 and fix this script"
done
ok "the three stated sibling lists match the islands plus $SIBLING_OFFSET"

: > "$TMP/plan"
for i in "${!PLAN_CPUS[@]}"; do
    expand_list "${PLAN_CPUS[$i]}" >> "$TMP/plan"
done
PLAN_N=$(wc -l < "$TMP/plan" | tr -d ' ')
PLAN_UNIQUE=$(sort -n -u "$TMP/plan" | wc -l | tr -d ' ')
[ "$PLAN_N" = "$PLAN_UNIQUE" ] \
    || fail "the plan assigns $PLAN_N CPU slots but only $PLAN_UNIQUE distinct CPUs: $(sort -n "$TMP/plan" | uniq -d | tr '\n' ' ')is in two roles" \
            "a CPU in two roles means one of the two lists is wrong: reread hyperviseur-recommandations.md section 2"

EXPECTED_CPUS=$PLAN_UNIQUE
CONTIGUOUS=$(sort -n -u "$TMP/plan" | awk 'NR - 1 != $1 { bad = 1 } END { print bad + 0 }')
[ "$CONTIGUOUS" = 0 ] \
    || fail "the plan's $EXPECTED_CPUS CPUs are not 0..$((EXPECTED_CPUS - 1))" \
            "the roles must partition the machine with no hole: reread hyperviseur-recommandations.md section 2"
ok "the plan partitions 0..$((EXPECTED_CPUS - 1)), each CPU in exactly one role"

# --- the machine matches the plan's shape -------------------------------------

[ "$NCPU" = "$EXPECTED_CPUS" ] \
    || fail "this machine has $NCPU CPUs, the plan describes $EXPECTED_CPUS" \
            "the plan is for the hypervisor oploy-pve-02 and its 56 threads; on any other machine there is nothing here to check, and none of its CPU lists apply"

[ "$NNODE" = 2 ] \
    || fail "this machine reports $NNODE NUMA node(s): $NODES" \
            "the plan assumes two nodes, even CPUs on node 0 and odd on node 1"

# --- hypothesis 1: the sibling of N is N+28 -----------------------------------
# Two CPUs share a CORE if and only if their numbers differ by SIBLING_OFFSET. Both
# directions matter: a core with three threads, or a pair 0/1 instead of 0/28, each break
# the plan in its own way, and both come out of the same pass.
BAD=$(awk -v off="$SIBLING_OFFSET" '
    { members[$3] = members[$3] " " $1; n[$3]++ }
    END {
        for (c in n) {
            if (n[c] != 2) {
                printf "core %s holds %d CPUs (%s )\n", c, n[c], members[c]
                continue
            }
            split(members[c], m, " ")
            d = m[2] - m[1]
            if (d < 0) d = -d
            if (d != off) printf "core %s pairs CPU %s with CPU %s, a distance of %d\n", c, m[1], m[2], d
        }
    }' "$TMP/topo")
[ -z "$BAD" ] \
    || fail "the SMT sibling of N is not N+$SIBLING_OFFSET: $(summarise "$BAD")" \
            "STOP. Every CPU list in the plan is built on this offset, so the islands are currently pinned onto the siblings of the load they exist to avoid. Recompute the plan from this lscpu output before applying anything"
ok "every core holds exactly two CPUs, N and N+$SIBLING_OFFSET"

# --- hypothesis 2: even CPUs on node 0, odd on node 1 -------------------------
# node == cpu % 2 is the whole rule, which is why it is one awk expression rather than a
# table: the plan sorts its roles by parity and by nothing else.
BAD=$(awk '$1 % 2 != $2 { printf "CPU %s is on node %s, not node %d\n", $1, $2, $1 % 2 }' "$TMP/topo")
[ -z "$BAD" ] \
    || fail "the node of a CPU is not its parity: $(summarise "$BAD")" \
            "STOP. The plan splits its roles by parity, so on this machine they do not land on the nodes the table claims. Recompute the plan from this lscpu output"
ok "even CPUs on node 0, odd CPUs on node 1"

# --- hypothesis 3: the siblings of the islands carry no VM --------------------
# The one that the whole partitioning is for, and the one a guest cannot answer.

FORBIDDEN=$(normalise "${ISLAND_SIBLINGS_DOC[0]},${ISLAND_SIBLINGS_DOC[1]},${ISLAND_SIBLINGS_DOC[2]}")
printf 'topo.siblings_to_keep_empty=%s\n' "$FORBIDDEN"

CROSSCHECKED=no
if command -v qm >/dev/null 2>&1; then
    if VMIDS=$(qm_read list 2>/dev/null | awk 'NR > 1 && $1 ~ /^[0-9]+$/ { print $1 }') && [ -n "$VMIDS" ]; then
        CROSSCHECKED=yes
        OFFENDERS=""
        UNCONFINED=""
        for vmid in $VMIDS; do
            config=$(qm_read config "$vmid" 2>/dev/null)
            affinity=$(printf '%s\n' "$config" | sed -n 's/^affinity: *//p')
            if [ -n "$affinity" ]; then
                hit=$(intersect "$affinity" "$FORBIDDEN")
                [ -n "$hit" ] && OFFENDERS="$OFFENDERS $vmid:$hit"
                continue
            fi
            # No affinity: line. That is not automatically a finding -- the hookscripts of
            # deploy/proxmox confine a VM by cgroup cpuset instead, and a cpuset covers more
            # than affinity does. So read the scope's effective cpuset before accusing it.
            # A running VM with neither is the section 0(a) case: it floats, and by
            # intermittence it lands on 48,50,52,54.
            scope=/sys/fs/cgroup/qemu.slice/$vmid.scope/cpuset.cpus.effective
            if [ -r "$scope" ]; then
                cpuset=$(cat "$scope")
                hit=$(intersect "$cpuset" "$FORBIDDEN")
                [ -n "$hit" ] && OFFENDERS="$OFFENDERS $vmid:$hit"
            else
                UNCONFINED="$UNCONFINED $vmid"
            fi
        done
        [ -z "$OFFENDERS" ] \
            || fail "VMs may run on the siblings that must stay empty:$OFFENDERS" \
                    "STOP. Every measurement taken while this holds shares a core with that VM. Set the affinity of each VM listed, or arm its hookscript (see deploy/proxmox/README.md), then rerun"
        ok "no VM affinity or cpuset covers $FORBIDDEN"
        [ -z "$UNCONFINED" ] \
            && ok "every VM declares an affinity or runs under a cpuset" \
            || note "stopped or unconfined, no affinity and no scope to read:$UNCONFINED -- if one of these starts without an affinity it can be scheduled anywhere, including the empty siblings"
    else
        note "qm is installed but its VM list could not be read, so the siblings were not crosschecked; rerun as root or with a NOPASSWD sudo"
    fi
fi

if [ "$CROSSCHECKED" = no ]; then
    # A guest has no qm and cannot see the other VMs. Printing the pairs is the honest
    # substitute for a verdict: it is the list to read on the host, not an answer.
    note "no qm here: this is not the Proxmox host, and whether those twelve CPUs are empty cannot be seen from a guest"
    echo
    echo "island CPU -> sibling to keep empty, to check on the host with 'qm config <vmid>'"
    for i in "${!ISLAND_CPUS[@]}"; do
        for cpu in $(expand_list "${ISLAND_CPUS[$i]}"); do
            printf '  %-14s %3s -> %3s\n' "${ISLAND_LABELS[$i]}" "$cpu" "$((cpu + SIBLING_OFFSET))"
        done
    done
    echo
fi

# --- closing ------------------------------------------------------------------
# The closing line says which of the three hypotheses were actually tested. A script that
# printed the same "all controls passed" from a guest as from the host would be claiming
# the one thing it did not check.
if [ "$CROSSCHECKED" = yes ]; then
    echo "check-topology: all controls passed, the plan of section 2 may be applied"
else
    echo "check-topology: topology controls passed; the emptiness of $FORBIDDEN was NOT checked here and must be confirmed on the Proxmox host"
fi
