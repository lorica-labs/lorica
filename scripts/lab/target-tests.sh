#!/usr/bin/env bash
# Build the kernel tests on the build VM and run them on the measurement VM.
#
#   target-tests.sh [--crate NAME] [--test NAME] [--features LIST]
#                   [--ebpf-features LIST] [--plain] [--no-ebpf] [--] [args for the test]
#
# Runs on the development host. The measurement VM is the only machine with the target
# kernel and the only one that may be measured, and it has no toolchain: building there
# is impossible, and a glibc binary from the build VM does not start there. So the
# build happens on the build VM against static musl and the binary travels.
#
# The tar is streamed through this host rather than copied VM to VM, because the build
# VM has no credentials for the measurement VM and giving it some is a change to the
# lab that this script does not need.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

BUILD_HOST=${LORICA_BUILD_HOST:-lab-dev}
TARGET_HOST=${LORICA_TARGET_HOST:-lab-target}
REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
RUN_DIR=${LORICA_RUN_DIR:-run}

BUILD_ARGS=()
PASS_THROUGH=()
while [ $# -gt 0 ]; do
    case $1 in
        --crate|--test|--features|--ebpf-features) BUILD_ARGS+=("$1" "$2"); shift 2 ;;
        --plain|--no-ebpf) BUILD_ARGS+=("$1"); shift ;;
        --)        shift; PASS_THROUGH=("$@"); break ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

die() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
remote() { ssh -o BatchMode=yes -o ConnectTimeout=25 "$1" "bash -lc '$2'"; }

bash scripts/lab/deploy.sh "$BUILD_HOST" \
    "bash scripts/lab/target-build.sh ${BUILD_ARGS[*]}" \
    || die "the build on $BUILD_HOST failed"

remote "$BUILD_HOST" "cat ~/$REMOTE_DIR/target/target-tests.tar" \
    | remote "$TARGET_HOST" "rm -rf ~/$RUN_DIR && mkdir -p ~/$RUN_DIR && tar xf - -C ~/$RUN_DIR" \
    || die "could not ship the test binaries to $TARGET_HOST"

# The knobs travel with the command, because an environment does not cross an ssh session.
# Values are interface names, window lengths and level counts, so none of them carries a
# space or an apostrophe — an apostrophe here would break the quoting envelope of the remote
# command rather than anything inside it, and the error would point at the last line of the
# script it was wrapped in.
knobs=
for name in $(env | cut -d= -f1 | grep '^LORICA_'); do
    knobs="$knobs $name=${!name}"
done

remote "$TARGET_HOST" "$knobs bash ~/$RUN_DIR/target-tests/target-run.sh ${PASS_THROUGH[*]}"
