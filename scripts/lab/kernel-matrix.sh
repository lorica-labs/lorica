#!/usr/bin/env bash
# Does the program load and behave on every kernel the matrix claims support for?
#
#   kernel-matrix.sh [--ebpf-features LIST] [--floor VERSION] VERSION[=KERNEL] ...
#
# VERSION is a version prefix — v6.8, 6.12, 7.0 — exercised on the running kernel when
# it matches, and under virtme-ng otherwise. virtme-ng takes a version straight from
# the Ubuntu mainline archive, so no kernel tree is built here; KERNEL overrides that
# with an installed version name or a path to a vmlinuz. A version that is neither the
# running kernel nor bootable is DECLARED, not skipped: a kernel nobody could hand us
# is a missing parameter, not a pass.
#
# The test binaries are built once, here, statically against musl, because a virtme-ng
# guest has the host filesystem read-only and no toolchain — the same reason the
# measurement VM has none. That is what target-build.sh and target-run.sh already do.
#
# Exit  0 every requested version exercised and green
#       1 the floor kernel failed — blocking, the floor is the audience
#       2 usage
#       3 a kernel other than the floor failed
#       4 a version could not be obtained, or a check could not be run

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

EBPF_FEATURES=${LORICA_EBPF_FEATURES:-parse-probe,count-helpers}
FLOOR=${LORICA_KERNEL_FLOOR:-6.8}
STAGE=$PWD/target/target-tests
EXERCISE=""
VERSIONS=()

while [ $# -gt 0 ]; do
    case $1 in
        --ebpf-features) EBPF_FEATURES=$2; shift 2 ;;
        --floor)         FLOOR=${2#v}; shift 2 ;;
        # Re-entry inside the guest: run the checks, the resolution already happened.
        --exercise)      EXERCISE=${2#v}; shift 2 ;;
        -h|--help)       sed -n '2,21p' "$0"; exit 0 ;;
        -*) echo "unknown argument: $1" >&2; exit 2 ;;
        *)  VERSIONS+=("$1"); shift ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

# Version prefixes, so 7.0 matches 7.0.0-30-generic. A dot is literal in a glob, so
# 6.1 does not match 6.12 the way a regular expression would.
matches() {
    case $1 in $2|$2.*|$2-*) return 0 ;; esac
    return 1
}

# Everything that has to happen on the kernel itself: here when the running kernel is
# the one asked for, inside the guest otherwise.
exercise() {
    local want=$1 release status=0 exc_file exc
    release=$(uname -r)
    # virtme-ng boots the host kernel when it is given no version, so without this a
    # download that silently did nothing would report a pass for a kernel never booted.
    matches "$release" "$want" \
        || { printf 'FAIL  asked for %s, running on %s\n' "$want" "$release" >&2; return 1; }
    # Readable and not executable, because the line below runs it with bash and never
    # needed the bit. It used to test -x, which passed in the lab and failed on a Linux
    # checkout: this tree is developed on Windows, where git does not track the mode, so
    # twelve of these scripts sit at 644 in the index and cp carries that into the staged
    # copy. The message said nothing staged, which was false — the staging was fine and a
    # permission bit was not.
    [ -r "$STAGE/target-run.sh" ] \
        || { printf 'FAIL  %s/target-run.sh is missing or unreadable\n' "$STAGE" >&2; return 1; }

    printf '\n=== %s on %s\n' "$want" "$release"

    # xdp:xdp_exception is system-wide and counted over the whole run: an XDP_ABORTED
    # is a correctness bug wearing a statistic as a disguise.
    # perf's own stderr rather than perf --output: given an existing file, perf refuses
    # it with "Permission denied" even as root, and mktemp's whole point is that the
    # file already exists.
    exc_file=$(mktemp)
    { sudo -n perf stat -e xdp:xdp_exception -a -- bash "$STAGE/target-run.sh"; } \
        2>"$exc_file" || status=1
    cat "$exc_file" >&2
    exc=$(awk '/xdp:xdp_exception/ {gsub(/,/, "", $1); print $1; exit}' "$exc_file")
    rm -f "$exc_file"

    # An empty or non-numeric count is refused rather than compared: a window that was
    # never measured must not read as a zero.
    case $exc in
        0) printf 'ok    xdp:xdp_exception 0\n' ;;
        "") printf 'FAIL  perf reported no xdp:xdp_exception count\n' >&2; status=1 ;;
        *[!0-9]*) printf 'FAIL  xdp:xdp_exception unreadable: %s\n' "$exc" >&2; status=1 ;;
        *) printf 'FAIL  xdp:xdp_exception is %s: the program aborted a packet\n' "$exc" >&2
           status=1 ;;
    esac

    # The plan also asks for an attach on a veth. Nothing in the tree can attach yet:
    # the loader is a stub, and no libbpf tool will even open the object, because aya
    # emits its map definitions in a legacy 'maps' section that libbpf 1.0+ refuses —
    # bpftool and ip both fail before the kernel is reached. So the zero above attests
    # that nothing aborted a packet, not that the program survived a real hook. The
    # plan puts that attach in tests/attach.rs, which target-build.sh stages as soon as
    # it exists; until then the kernel is reported incomplete rather than green.
    if [ ! -r crates/lorica-dataplane/tests/attach.rs ]; then
        printf 'INCOMPLETE  %s: no attach on a veth, %s\n' "$want" \
            "crates/lorica-dataplane/tests/attach.rs does not exist yet, so xdp:xdp_exception was counted over a run where nothing was attached" >&2
        [ $status -eq 0 ] && status=4
    fi
    return $status
}

if [ -n "$EXERCISE" ]; then
    exercise "$EXERCISE"
    exit $?
fi

[ ${#VERSIONS[@]} -gt 0 ] || {
    echo "usage: kernel-matrix.sh [--ebpf-features LIST] [--floor VERSION] VERSION[=KERNEL] ..." >&2
    exit 2
}

bash scripts/lab/target-build.sh --ebpf-features "$EBPF_FEATURES" \
    || die "the build produced nothing to run on any kernel"

release=$(uname -r)
have_vng=0
command -v vng >/dev/null 2>&1 && have_vng=1
lines=()
reason=""
# 0 green, 1 a version was not obtained, 2 a kernel failed, 3 the floor failed.
worst=0

for spec in "${VERSIONS[@]}"; do
    want=${spec%%=*}; want=${want#v}
    # No KERNEL given: the archive, under the name virtme-ng expects.
    case $spec in *=*) given=${spec#*=} ;; *) given="" ;; esac

    if [ -z "$given" ] && matches "$release" "$want"; then
        exercise "$want"; rc=$?
    elif [ "$have_vng" -eq 0 ]; then
        rc=5
        reason="the running kernel is $release and virtme-ng is not installed: apt install virtme-ng"
    else
        boot=${given:-v$want}
        printf '\n=== booting %s under virtme-ng\n' "$boot"
        vng --run "$boot" --exec "bash $PWD/scripts/lab/kernel-matrix.sh --ebpf-features $EBPF_FEATURES --exercise $want"
        rc=$?
        # virtme-ng exits nonzero both when the guest command failed and when it had no
        # kernel to boot, so a failure here is reported as a failure, never as a pass.
    fi

    if [ $rc -eq 0 ]; then
        lines+=("ok           $want")
    elif [ $rc -eq 5 ]; then
        lines+=("UNOBTAINED   $want — $reason")
        [ $worst -lt 1 ] && worst=1
    elif [ $rc -eq 4 ]; then
        lines+=("INCOMPLETE   $want — a check could not be run, see above")
        [ $worst -lt 1 ] && worst=1
    elif [ "$want" = "$FLOOR" ]; then
        lines+=("FAILED       $want — the floor, this is blocking")
        worst=3
    else
        lines+=("FAILED       $want")
        [ $worst -lt 2 ] && worst=2
    fi
done

printf '\n=== kernel matrix, from %s\n' "$release"
printf '%s\n' "${lines[@]}"

case $worst in
    0) exit 0 ;;
    1) exit 4 ;;
    2) exit 3 ;;
    *) exit 1 ;;
esac
