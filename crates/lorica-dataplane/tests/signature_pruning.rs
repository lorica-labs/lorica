//! Assertion: the vectors a configuration leaves out are not in the program the kernel
//! ran.
//!
//! This is a claim about the loaded program and not about the source, so it cannot be made
//! by counting instructions in the object: the elimination happens in the verifier, which
//! reads the activation word out of `.rodata`, knows it cannot change, and physically
//! removes the branches behind a clear bit. The observable that comes from *after*
//! verification is `bpf_prog_info.xlated_prog_len`, so that is what is compared here. The
//! JITed length is printed beside it because the margin under the size ceiling is the other
//! half of why the lever exists.
//!
//! `bpftool prog dump xlated` would show the removed branches one by one, and cannot be
//! used for the reason `jited_size` gives: aya emits legacy map definitions libbpf 1.0
//! dropped, so no libbpf tool can load this object. A Rust test over a program aya loaded
//! is how this repository proves things about the program.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{DEFAULT_SETTINGS, SIGNATURE_VECTORS_ALL};
use lorica_policy::compile::signature::vectors_word;
use support::run::{load_raw_vectors, plain_object_path, xdp_program};

/// The four vectors that are facts about a single packet. True of every host, no port and
/// no threshold in them, and what an operator who serves no UDP asks for.
const FACTS: [&str; 4] = [
    "loopy_port_pair",
    "frag_abuse",
    "impossible_tcp_flags",
    "length_mismatch",
];

/// A configuration named the way the operator names it, through the policy compiler rather
/// than as a bit pattern: a catalogue reordered on one side of the gap would otherwise move
/// which vectors this measures without moving the literal.
fn catalogue(names: &[&str]) -> u32 {
    let owned: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    vectors_word(Some(&owned)).expect("the catalogue did not compile")
}

/// The translated and JITed lengths of the program as this catalogue loads it.
fn sizes(vectors: u32) -> (u32, u32) {
    let mut ebpf = load_raw_vectors(&plain_object_path(), DEFAULT_SETTINGS, Some(vectors));
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let info = program.info().expect("reading the program info failed");
    (
        info.size_translated().expect("no translated length"),
        info.size_jitted(),
    )
}

/// The floor the difference has to clear.
///
/// Measured on 7.0.0-30: **13 152 translated bytes with the whole catalogue and 10 664 with
/// none of it**, a difference of 2 488, and 7 572 against 6 152 JITed. The floor is set at
/// a third of the measurement rather than at it, because what this test has to catch is the
/// mechanism failing — a folded read, an unpatched symbol, a mask LLVM decided it knew —
/// and that failure mode is worth a handful of bytes, not two thousand. Pinning the
/// measurement would instead break on the first kernel that inlines differently.
const PRUNED_FLOOR: u32 = 800;

#[test]
fn the_vectors_a_configuration_leaves_out_are_not_in_the_loaded_program() {
    let (all_xlated, all_jited) = sizes(SIGNATURE_VECTORS_ALL);
    let (none_xlated, none_jited) = sizes(0);
    // A game host: the facts, plus the two reflectors whose ports it has anything to do
    // with. Six of ten, and the configuration the margin under the size ceiling is worth
    // reading for.
    let mut game = FACTS.to_vec();
    game.extend(["amp_dns", "amp_raknet"]);
    let (some_xlated, some_jited) = sizes(catalogue(&game));
    let (facts_xlated, facts_jited) = sizes(catalogue(&FACTS));

    println!(
        "whole catalogue: {all_xlated} translated, {all_jited} JITed\n\
         six of ten:      {some_xlated} translated, {some_jited} JITed\n\
         the four facts:  {facts_xlated} translated, {facts_jited} JITed\n\
         nothing armed:   {none_xlated} translated, {none_jited} JITed"
    );

    assert!(
        all_xlated >= none_xlated + PRUNED_FLOOR,
        "the whole catalogue translates to {all_xlated} bytes and an empty one to \
         {none_xlated}, a difference of {}. Under {PRUNED_FLOOR} the verifier did not \
         propagate the activation word and the branches are still in the program: check \
         that the loader patched SIGNATURE_VECTORS and that nothing folded the read.",
        all_xlated - none_xlated
    );

    // Monotone in between, which is the half that says the *configuration* is what is
    // being paid for. A program that only shrank when the catalogue was empty would be a
    // program with one gate around the stage, and that is not this lever.
    assert!(
        all_xlated > some_xlated && some_xlated > none_xlated,
        "six of ten translates to {some_xlated} bytes, between {none_xlated} and \
         {all_xlated} it is not"
    );
}
