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
//! **What the unrolling costs, measured on the object that ships.** On 6.8.0-138, whole
//! signature catalogue armed and the trie kept: **9 995 JITed bytes and 17 056 xlated**, under
//! the 10 491 ceiling `tests/jited_size.rs` carries. It was 9 537 before the counter map became
//! mappable and before the slot fingerprint; those two added 52 and 441 bytes respectively, and
//! each says so where it is made.
//!
//! **The cuckoo variant below measures 8 387 JITed and 14 536 xlated on the same kernel** —
//! 1 608 bytes and 315 instructions less than the sixteen probes, and it loads on the 6.8
//! verifier, which was the open question. That is two of the three numbers the switch needs;
//! the third is cycles per packet on traffic that actually reaches the table, and it is not
//! here.
//!
//! **The probe sequence is written out and never looped.** Sixteen steps, one per
//! [`OA_PROBES`], because a loop bounded by anything the verifier reads as a variable
//! multiplies its state space by the trip count for a bound that is known at build time
//! anyway — and the one loop this program tried over an attacker-chosen index was refused
//! with `var_off=(0x0; 0xff)` after LLVM moved the mask that made it safe.

use lorica_common::{
    Action, CLASS24_BYTES, Class24, CounterId, Family, PacketView, blocklist::class24_get,
};
#[cfg(feature = "blocklist-cuckoo")]
use lorica_common::blocklist::cuckoo::{
    CUCKOO_BUCKET_MASK, CUCKOO_LANES, CuckooBucket, cuckoo_alt, cuckoo_delta, cuckoo_hash,
    cuckoo_home, cuckoo_lane, cuckoo_match, cuckoo_sig,
};
#[cfg(not(feature = "blocklist-cuckoo"))]
use lorica_common::{
    OA_PROBES, OaSlot,
    blocklist::{
        OA_INDEX_MASK, oa_action, oa_fingerprint, oa_index, oa_occupied, oa_psl, oa_step,
        oa_tag_fingerprint,
    },
};

use crate::maps::CLASS24;
#[cfg(feature = "blocklist-cuckoo")]
use crate::maps::CUCKOO_TABLE;
#[cfg(not(feature = "blocklist-cuckoo"))]
use crate::maps::OA_TABLE;
use crate::{helpers, stage::Outcome};

#[inline(never)]
/// The `CLASS24` access on its own, so a caller can issue it earlier than it consumes it.
///
/// **Why this is separable and `probe` is not.** This is a slice index with no `read_volatile`
/// between the bound and the load, so nothing pins where it is emitted. `probe` carries a
/// deliberate barrier that keeps the 6.8 verifier from losing the bound at the final `XOR`, and
/// moving it would cost the program its ability to load. Nothing here touches `probe`.
///
/// Returns `None` for anything that is not IPv4, which is the same early exit `run` makes.
#[cfg(feature = "hoist-class24")]
#[inline(always)]
pub fn class_of(view: &PacketView) -> Option<(u32, Class24)> {
    if view.family() != Family::V4 {
        return None;
    }
    let addr = u32::from_be_bytes([view.src[12], view.src[13], view.src[14], view.src[15]]);
    // SAFETY: as in `run`.
    let table =
        unsafe { core::slice::from_raw_parts((&raw const CLASS24).cast::<u8>(), CLASS24_BYTES) };
    Some((addr, class24_get(table, addr)))
}

/// Stage 3a from a verdict the caller already has.
#[cfg(feature = "hoist-class24")]
pub fn run_hoisted(hoisted: Option<(u32, Class24)>) -> Outcome {
    let Some((addr, class)) = hoisted else {
        return Outcome::Continue;
    };
    match class {
        Class24::None => Outcome::Continue,
        Class24::Deny => {
            helpers::bump(CounterId::LpmDropHit);
            Outcome::Drop
        }
        Class24::Allow => {
            helpers::bump(CounterId::LpmAllowExit);
            Outcome::Pass
        }
        Class24::Table => verdict(probe(addr)),
    }
}

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

    // **The counters are the trie's, and that is the point.** Both halves of stage 3 answer
    // the same question about the same traffic, so an operator reading `lpm_drop_hit` gets the
    // number of sources the source list refused whichever table held the verdict. A pair of
    // names per table would make a dashboard depend on which structure a rule compiled into,
    // which is a decision the operator did not make and cannot see.
    //
    // Nothing is bumped on the common path. `Class24::None` is the 94 % case with a million
    // scattered `/32` loaded and it stays one memory access and a branch.
    match class {
        // The 94 % case with a million scattered `/32` loaded, and the whole of it is the
        // one access above.
        Class24::None => Outcome::Continue,
        Class24::Deny => {
            helpers::bump(CounterId::LpmDropHit);
            Outcome::Drop
        }
        Class24::Allow => {
            helpers::bump(CounterId::LpmAllowExit);
            Outcome::Pass
        }
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
fn verdict(action: Option<Action>) -> Outcome {
    match action {
        Some(Action::Drop) => {
            helpers::bump(CounterId::LpmDropHit);
            Outcome::Drop
        }
        Some(Action::Allow) => {
            helpers::bump(CounterId::LpmAllowExit);
            Outcome::Pass
        }
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
#[cfg(not(feature = "blocklist-cuckoo"))]
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

/// The bucketised cuckoo form of [`lorica_common::blocklist::cuckoo::cuckoo_lookup`], step for
/// step, behind the `blocklist-cuckoo` feature.
///
/// **This is an experiment with an output, not a replacement.** What it exists to produce is
/// three numbers against the sixteen-probe form above — xlated instructions, JITed bytes and
/// instructions per packet — and the switch is decided on the third of those under attack
/// traffic, in the lab, not here. The simulation that authorised writing it is
/// `lorica-policy/tests/blocklist_sim.rs`: zero insertion failures over 2.1 billion insertions
/// at the maximum load, worst displacement chain six, and an equivalence against
/// `oa_lookup` over all 4 294 967 296 addresses.
///
/// **What it costs, measured on the object rather than counted in the source.** On 6.8.0-138:
/// **8 387 JITed bytes and 14 536 xlated against 9 995 and 17 056** for the sixteen probes —
/// 1 608 bytes and **315 instructions** less over the whole program, 16.1 % and 14.8 %. The
/// design note estimated the *probe alone* at ~100 instructions against 147; the whole-program
/// delta is larger because replacing the sequence also removes the Robin Hood tail — the probe
/// length decode, the early exit, the index stepping — and the slot fingerprint's sixteen
/// comparisons with it.
///
/// **And it loads.** That was the open question: the alternate bucket is derived by `XOR`, the
/// pattern the 6.8 verifier loses a bound on, and the two barriers below are what keep it. The
/// third number the switch needs — cycles per packet on traffic that reaches the table — is
/// not measured, because the fixtures that reach it are a campaign and not a test.
///
/// **Two barriers, one per bucket, and the second is the one that forced this shape.** 6.8
/// propagates a bound through a shift and **loses it at an `XOR`** — that is exactly what
/// happens to `oa_index`, and the alternate bucket here is `home ^ delta`, the same pattern
/// one step worse. So each index gets its own `read_volatile` through the stack before its
/// `AND`, which is what LLVM may not see across, so the literal mask survives into the object
/// and the verifier reads a bound off it. Without them the expected refusal is
/// `math between map_value pointer and register with unbounded min value is not allowed`,
/// which is the message this program has already collected twice.
///
/// **The lane index needs a mask of its own, and it is structural.** A manual access through a
/// map-value pointer has none of the bound checking `bpf_map_lookup_elem` performs, and the
/// decode hands back a lane in `0..8` by construction — but "by construction" is exactly what
/// the verifier will not take, so `& (CUCKOO_LANES - 1)` is written out. The lane count is a
/// compile-time power of two, so the mask is the same kind of structural one as
/// `OA_INDEX_MASK` and not the kind LLVM deleted from the IP-option walk.
#[cfg(feature = "blocklist-cuckoo")]
#[inline(always)]
fn probe(key: u32) -> Option<Action> {
    let table = &raw const CUCKOO_TABLE as *const CuckooBucket;

    // One hash for both fields: the top eighteen bits are the bucket and the low byte is the
    // signature, so the packet path computes `fmix32` once.
    let hash = cuckoo_hash(key);
    let sig = cuckoo_sig(hash);

    let home = cuckoo_home(hash);
    // SAFETY: a volatile read of a live local of this frame. See the note above for why it is
    // not optional on the 6.8 floor.
    let home = unsafe { core::ptr::read_volatile(&home) } & CUCKOO_BUCKET_MASK;
    if let Some(action) = lane(table, home, key, sig) {
        return Some(action);
    }

    let alt = cuckoo_alt(home, cuckoo_delta(key));
    // SAFETY: as above, and this is the index derived by `XOR` — the barrier matters more here
    // than for the first one.
    let alt = unsafe { core::ptr::read_volatile(&alt) } & CUCKOO_BUCKET_MASK;
    lane(table, alt, key, sig)
}

/// One bucket: one cache line, one signature search, one key comparison at most.
///
/// Written once and called twice rather than unrolled by hand, so the two buckets cannot drift
/// apart — the sixteen Robin Hood steps are a macro for the same reason.
#[cfg(feature = "blocklist-cuckoo")]
#[inline(always)]
fn lane(table: *const CuckooBucket, bucket: u32, key: u32, sig: u8) -> Option<Action> {
    // SAFETY: the mask takes the index to `0 ..= CUCKOO_BUCKETS - 1`, which is the whole of the
    // global, and `CuckooBucket` is `repr(C, align(64))` with its padding named, so bucket `i`
    // starts at `i * 64` bytes into it.
    let bucket = unsafe { &*table.add((bucket & CUCKOO_BUCKET_MASK) as usize) };

    // Eight signatures compared in one arithmetic sequence, and the builder's
    // one-signature-per-bucket invariant is what makes the lowest set bit the whole answer:
    // there is nothing to iterate and therefore no loop for the verifier to unroll.
    let lane = cuckoo_lane(cuckoo_match(bucket.sigs, sig))? & (CUCKOO_LANES - 1);

    // The key is read only here, which is the whole point of a signature: 255 of 256 occupied
    // lanes never reach this load. And the comparison is exact, so a signature collision costs
    // a load and never a wrong verdict.
    if bucket.keys[lane] != key {
        return None;
    }
    Action::from_u8(bucket.tags[lane])
}
