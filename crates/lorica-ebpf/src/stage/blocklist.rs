//! Stage 3, the operator blocklist: two flat tables read with no helper call at all.
//!
//! **What this replaces, with the number that forced it.** The same verdict used to come out
//! of the `LPM_TRIE` next door, which `BPF_F_NO_PREALLOC` makes one allocation per level: an
//! absent key inside a populated `/16` cost 116 ns at one entry and **414 ns at one million**,
//! for 198 MiB of kernel memory. The tables here cost the same at one entry and at ten
//! million, for 20 MiB fixed, and the reason is not the layout but the addressing: a `.bss`
//! global is an `LDX` off a pointer the verifier materialises with `ld_imm64` /
//! `BPF_PSEUDO_MAP_VALUE`, so this stage adds **zero** helper calls to a packet path already
//! spending two lookups and one clock read. Nothing here is free — an inlined array access
//! with its bounds check and its Spectre mask is published at 3.9 +/- 0.8 ns, and
//! `lorica_common::blocklist` reserves 4 to 5 ns per access rather than rounding it away.
//!
//! The path is [`lorica_common::blocklist`]'s and not this file's. `CLASS24` resolves every
//! IPv4 prefix at or shorter than `/24` in one access, and only its fourth code sends the
//! address on to the open-addressed table. IPv6 is not asked at all: `CLASS24` indexes 24
//! bits of a 32-bit address and a slot key is a `u32`, so an IPv6 source falls through to the
//! trie, which is now most of what the trie is for.
//!
//! **What the unrolling costs, measured on the object that ships.** 9 537 JITed bytes with the
//! whole signature catalogue armed and the trie kept, 8 995 with the trie dropped, against
//! 7 572 recorded for the program before this stage and a ceiling of 8 330 in
//! `tests/jited_size.rs`. So sixteen unrolled steps put the largest reachable program over
//! that ceiling by 1 207 bytes and the common configuration over it by 665. The ceiling is
//! left standing red on purpose: it is a line somebody decides in a diff, not one this stage
//! raises for itself.
//!
//! **The probe sequence is written out and never looped.** Sixteen steps, one per
//! [`OA_PROBES`], because a loop bounded by anything the verifier reads as a variable
//! multiplies its state space by the trip count for a bound that is known at build time
//! anyway — and the one loop this program tried over an attacker-chosen index was refused
//! with `var_off=(0x0; 0xff)` after LLVM moved the mask that made it safe.

use lorica_common::{
    Action, CLASS24_BYTES, Class24, Family, OA_PROBES, OaSlot, PacketView,
    blocklist::{
        OA_INDEX_MASK, class24_get, oa_action, oa_fingerprint, oa_index, oa_occupied, oa_psl,
        oa_step, oa_tag_fingerprint,
    },
};

use crate::{
    maps::{CLASS24, OA_TABLE},
    stage::Outcome,
};

#[inline(never)]
pub fn run(view: &PacketView) -> Outcome {
    if view.family() != Family::V4 {
        return Outcome::Continue;
    }
    // The parser stores IPv4 in the v4-mapped form, and the tables are indexed in host
    // order because that is the order a prefix compares in.
    let addr = u32::from_be_bytes([view.src[12], view.src[13], view.src[14], view.src[15]]);

    // SAFETY: a shared slice over the whole of a global this program only ever reads. The
    // loader wrote these bytes before the program was verified, and the length is the
    // constant the array was declared with, so the bound `class24_get` checks is the real
    // one and folds away.
    let table =
        unsafe { core::slice::from_raw_parts((&raw const CLASS24).cast::<u8>(), CLASS24_BYTES) };
    let class = class24_get(table, addr);

    match class {
        // The 94 % case with a million scattered `/32` loaded, and the whole of it is the
        // one access above.
        Class24::None => Outcome::Continue,
        Class24::Deny => Outcome::Drop,
        Class24::Allow => Outcome::Pass,
        Class24::Table => verdict(probe(addr)),
    }
}

/// Turns what a tag carried into what the pipeline routes.
///
/// **A miss falls back on nothing, and that is a property of the snapshot rather than a
/// choice made here.** Marking a `/24` `Table` destroys the only copy of the verdict a
/// shorter prefix gave it, so the builder writes a key for every address in that `/24` that
/// still carries one — up to 255 filling keys beside the exception that caused the mark. The
/// probe result is therefore the whole answer: no re-reading of the `/24` code, no second
/// probe on the base address, and no `CLASS24` code kept alive across the unrolled sequence.
///
/// That is also why the verdict lives in the tag rather than a membership bit: `deny
/// 10.0.0.0/8` with `allow 10.1.2.3/32` is two keys with opposite answers, resolved at
/// construction, and the equivalent bug of splitting the decision across two structures
/// exists in production elsewhere (Cilium issue #41121).
///
/// `RateLimit` and `Mark` can only arrive from here and never from `CLASS24`, whose two bits
/// spell four codes: the builder refuses a prefix at or shorter than `/24` carrying a verdict
/// it cannot write, while the three tag bits of a `/25` to `/32` can hold one.
const fn verdict(action: Option<Action>) -> Outcome {
    match action {
        Some(Action::Drop) => Outcome::Drop,
        Some(Action::Allow) => Outcome::Pass,
        // Rate limiting and marking are verdicts the later stages own, as in `lpm`. `None`
        // is a tag whose three verdict bits decode to no `Action` at all, which is a corrupt
        // snapshot rather than a configuration choice, and the direction that cannot be
        // taken back is the one not taken here.
        Some(Action::Continue | Action::RateLimit | Action::Mark) | None => Outcome::Continue,
    }
}

/// The unrolled form of [`lorica_common::blocklist::oa_lookup`], step for step.
///
/// **The masking is this function's own.** A manual access through a map-value pointer has
/// none of the bound checking `bpf_map_lookup_elem` performs, and one `AND` with
/// [`OA_INDEX_MASK`] is all that is needed because the slot count is a power of two — a mask
/// that is *structural*, unlike the one LLVM deleted from the IP-option walk, because the
/// size it derives from is a compile-time constant rather than a bound the optimiser had to
/// be trusted to remember.
//
// Both lints fire on a degenerate end of the unrolled sequence and on nothing else, which is
// why they are `expect` and not `allow`: the day the shape changes and one of them stops
// firing, the build says so. `unused_comparisons` is the first step, where the Robin Hood
// test is `psl < 0` and correctly always false; `unused_assignments` is the last, where the
// index is advanced to a slot no step reads. Restructuring either away would mean writing the
// step body twice or replacing `oa_step` with arithmetic of this file's own, and the frozen
// definition is worth more than two warnings.
#[expect(unused_comparisons, unused_assignments)]
#[inline(always)]
fn probe(key: u32) -> Option<Action> {
    let table = &raw const OA_TABLE as *const OaSlot;

    // The barrier is the whole difference between loading on the 6.8 floor and not, and it is
    // here because the mask alone was **measured** to be insufficient rather than assumed to
    // be enough. LLVM folds `oa_index` into `(h >> 11) ^ (h >> 27)`, proves the result is
    // under 2^21, and deletes the `AND` that made it safe — trap 3 of this program's history,
    // again. 7.0 follows the reasoning; 6.8 loses the bound at that final `XOR`, reports the
    // register as `scalar()` and refuses with `math between map_value pointer and register
    // with unbounded min value is not allowed`. A volatile read through the stack is what
    // LLVM may not see across, so the literal `AND` survives into the object and the verifier
    // reads a bound off it. One store and one load, once, ahead of sixteen steps that need no
    // barrier of their own: `oa_step` adds one before masking, so its `AND` is never provably
    // redundant.
    let home = oa_index(key);
    // SAFETY: a volatile read of a live local of this frame.
    let mut index = unsafe { core::ptr::read_volatile(&home) } & OA_INDEX_MASK;

    // The low byte of the same hash, so it is free to obtain. What it costs is one comparison
    // per step below, and what it buys is that a slot torn by a snapshot copy answers "no
    // verdict" instead of the previous snapshot's verdict —
    // `lorica_common::blocklist::oa_fingerprint` carries the whole argument.
    let fingerprint = oa_fingerprint(key);

    // One step per literal, and the count checked against the constant the builder
    // enforces: a sequence shorter than OA_PROBES would silently miss keys the builder
    // placed at the far end of a probe run it was allowed to produce.
    macro_rules! probe_sequence {
        ($($distance:literal),+ $(,)?) => {
            const _: () = assert!(
                [$($distance),+].len() as u32 == OA_PROBES,
                "the unrolled probe sequence is no longer OA_PROBES steps long"
            );
            $(
                // SAFETY: the mask takes the index to `0 ..= OA_SLOTS - 1`, which is the
                // whole of the global, and `OaSlot` is `repr(C)` with no padding so slot
                // `i` starts at `i * 8` bytes into it.
                let slot = unsafe { *table.add((index & OA_INDEX_MASK) as usize) };
                if !oa_occupied(slot.tag) {
                    return None;
                }
                // The fingerprint gates the key comparison, in that order, for the two reasons
                // the shared `oa_lookup` states: 255 of 256 occupied slots stop here without
                // reading the key, and a slot whose tag came from a different snapshot than its
                // key reads as somebody else's rather than as a verdict.
                if fingerprint == oa_tag_fingerprint(slot.tag) && slot.key == key {
                    return oa_action(slot.tag);
                }
                // The Robin Hood invariant: a slot sitting closer to its home than we have
                // walked cannot be followed by our key, because insertion would have
                // displaced it. This is what bounds a miss to the maximum probe length
                // instead of to the load factor.
                if (oa_psl(slot.tag) as u32) < $distance {
                    return None;
                }
                index = oa_step(index);
            )+
        };
    }

    probe_sequence!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    None
}
