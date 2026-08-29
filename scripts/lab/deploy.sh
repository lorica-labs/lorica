#!/usr/bin/env bash
# Copy the working tree to a lab machine and run a command there.
#
#   deploy.sh <host> [command...]
#
# Runs on the development host, not on a VM. It ships the working tree rather than a
# pushed commit so a task can be verified before it is committed, which is the order
# the method asks for.
#
# The retry loop is not defensive programming: the overlay the lab is reached through
# drops a connection every few minutes, and a failed copy that looks like a failed
# build costs more than the loop.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

HOST=${1:-}
[ -n "$HOST" ] || { echo "usage: deploy.sh <host> [command...]" >&2; exit 2; }
shift

REMOTE_DIR=${LORICA_REMOTE_DIR:-src}
ATTEMPTS=${LORICA_SSH_ATTEMPTS:-4}

# target/ is excluded so the remote build cache survives, and .git so the remote
# checkout is not rewritten under a running build.
# docs is here because a test reads docs/limits.md: the capability table on that page
# restates seven names and seven kernel releases from the code, and the test is what stops
# them drifting. Without the directory in the tar the test cannot find the page and fails on
# the lab for a reason that has nothing to do with what it checks.
# examples is here for the same reason: a test compiles examples/lorica.toml, because an
# annotated configuration that does not parse is worse than no example at all.
paths=(crates scripts bench docs examples Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml)
existing=()
for path in "${paths[@]}"; do
    [ -e "$path" ] && existing+=("$path")
done

attempt=1
while [ "$attempt" -le "$ATTEMPTS" ]; do
    if tar cf - --exclude=target --exclude='*.o' "${existing[@]}" \
        | ssh -o BatchMode=yes -o ConnectTimeout=25 "$HOST" \
            "mkdir -p ~/$REMOTE_DIR && tar xf - -C ~/$REMOTE_DIR"; then
        break
    fi
    printf 'deploy attempt %d of %d failed\n' "$attempt" "$ATTEMPTS" >&2
    attempt=$((attempt + 1))
done
[ "$attempt" -le "$ATTEMPTS" ] || { echo "could not copy the tree to $HOST" >&2; exit 1; }

[ $# -eq 0 ] && exit 0

attempt=1
while [ "$attempt" -le "$ATTEMPTS" ]; do
    ssh -o BatchMode=yes -o ConnectTimeout=25 "$HOST" \
        "bash -lc 'cd ~/$REMOTE_DIR && $*'"
    status=$?
    # 255 is ssh itself failing. Any other code is the remote command speaking, and
    # retrying it would hide a real failure.
    [ "$status" -ne 255 ] && exit "$status"
    printf 'connection to %s dropped, retrying\n' "$HOST" >&2
    attempt=$((attempt + 1))
done
echo "could not reach $HOST" >&2
exit 1
