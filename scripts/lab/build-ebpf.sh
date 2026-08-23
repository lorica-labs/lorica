#!/usr/bin/env bash
# Builds the two eBPF objects and names them. Sourced from the repository root, not
# executed.
#
#   . scripts/lab/build-ebpf.sh
#   build_ebpf "parse-probe,count-helpers"   # sets EBPF_PLAIN_OBJ and EBPF_OBJ
#
# Two objects in two target directories. The instrumented one adds a map write per
# counted call, so a static call budget read from it would be measuring the
# instrumentation. Both callers need that separation, and writing it twice is exactly
# how the static guard and the instrumented one start disagreeing.

build_ebpf() {
    local features=${1:-}
    local root=$PWD

    echo 'building the eBPF object that ships' >&2
    (cd crates/lorica-ebpf && cargo +nightly build --release) || return 1
    EBPF_PLAIN_OBJ=$root/crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf
    if [ ! -f "$EBPF_PLAIN_OBJ" ]; then
        echo "no object at $EBPF_PLAIN_OBJ after a successful build" >&2
        return 1
    fi

    if [ -z "$features" ]; then
        EBPF_OBJ=$EBPF_PLAIN_OBJ
        return 0
    fi

    printf 'building the instrumented eBPF object with features: %s\n' "$features" >&2
    local dir=$root/crates/lorica-ebpf/target/instrumented
    (cd crates/lorica-ebpf \
        && CARGO_TARGET_DIR=$dir cargo +nightly build --release --features "$features") \
        || return 1
    EBPF_OBJ=$dir/bpfel-unknown-none/release/lorica-ebpf
    if [ ! -f "$EBPF_OBJ" ]; then
        echo "no object at $EBPF_OBJ after a successful build" >&2
        return 1
    fi
}
