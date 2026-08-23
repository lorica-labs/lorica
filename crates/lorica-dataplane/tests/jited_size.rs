//! Assertion 2: the size of the JIT-compiled program, held under a ceiling.
//!
//! The invisibility contract is a promise about cost, and the size of the code the CPU
//! actually runs is one of the two numbers behind it. It is recorded here rather than in
//! a document so that growth breaks a build instead of surprising a reader.
//!
//! **Why not `bpftool prog show --json`, which the plan prescribes.** bpftool cannot load
//! this program at all: aya emits legacy `bpf_map_def` entries in a `maps` section and
//! libbpf dropped support for those in 1.0, so every libbpf tool answers
//! `elf: legacy map definitions in 'maps' section are not supported`. Only a binary from
//! this tree can load the object. The number read here is `bpf_prog_info.jited_prog_len`,
//! which is the very field bpftool renders as `bytes_jited`, taken from the kernel
//! directly — so the version hazard the plan worried about, `bytes_jited` against
//! `jited_prog_len`, cannot arise. Neither of those names exists in this path.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::DEFAULT_SETTINGS;
use support::run::{load_raw, plain_object_path, xdp_program};

/// Measured with four stages implemented and three still stubs: **5 321 bytes** on
/// 7.0.0-30 (Haswell, VM 900) and **5 283 bytes** on 6.8.0-138 (VM 901). The two kernels
/// differ by 38 bytes, 0.7 %, from the same bytecode.
///
/// The plan asks for "+10 % against master", which on a shared runner compares two
/// different machines and reports noise. A checked-in ceiling with declared headroom
/// catches the same thing — code growing without anyone deciding to — and is the same
/// shape as the helper-call budget next door. Raising it is a deliberate line in a diff.
///
/// Headroom is 10 % over the larger of the two measurements. The observed spread between
/// kernels is under 1 %, so 10 % leaves room for a kernel this has not run on without
/// leaving room for a stage to be added unnoticed.
const JITED_CEILING: u32 = 5_853;

#[test]
fn the_jited_program_stays_under_its_ceiling() {
    let mut ebpf = load_raw(&plain_object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let info = program.info().expect("reading the program info failed");
    let jited = info.size_jitted();

    // A zero here is the false pass this assertion exists to avoid: it does not mean a
    // tiny program, it means the JIT is off, and comparing against it would let any
    // amount of growth through.
    assert!(
        jited > 0,
        "jited_prog_len is 0, so the JIT is disabled and this assertion measures \
         nothing. Check /proc/sys/net/core/bpf_jit_enable."
    );
    println!(
        "{} on {}: {jited} bytes JITed, {} bytes translated, ceiling {JITED_CEILING}",
        support::PROGRAM,
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim(),
        info.size_translated().unwrap_or(0),
    );
    assert!(
        jited <= JITED_CEILING,
        "the JITed program is {jited} bytes against a ceiling of {JITED_CEILING}. \
         Either the growth is intended, in which case raise the ceiling in this file and \
         say why, or it is not."
    );
}
