//! The candidate replacement for the Robin Hood table: bucketised cuckoo, two buckets of
//! eight lanes, eight-bit signatures compared eight at a time.
//!
//! **Nothing routes here yet.** The shipped packet path is the sixteen unrolled Robin Hood
//! probes in [`super`], and it stays that way until a cycles campaign says otherwise. What
//! this module is for is the two things that campaign needs first: a simulation that can be
//! run rather than an estimate that can be quoted, and a lookup written once so the eBPF
//! variant is a transcription and not a second implementation. `lorica-policy`'s
//! `blocklist_sim` measures it; `cuckoo_equivalence` compares it against
//! [`oa_lookup`](super::oa_lookup) verdict for verdict.
//!
//! # Why this shape and not another
//!
//! **Reducing `OA_PROBES` is dead, and simulation is what killed it.** Sixteen probes are
//! ~147 static instructions and 48 branches, and the obvious saving was a shorter sequence. But
//! the maximum probe length at a load factor of 0.5 is a *distribution*, not a bound. A thousand
//! draws per shape, from `lorica-policy/tests/blocklist_sim.rs`:
//!
//! ```text
//! worst probe length      8    9   10   11   12   13   14   15   16
//! scattered /32           5  170  438  253   92   26   14    2    -
//! whole /24 blocks        2  162  441  258   99   26    9    1    2
//! ```
//!
//! `P(worst >= 12)` is 13.4 % and 13.7 %, so K = 12 refuses one configuration in seven to save
//! ~34 instructions. The hash is not keyed, so that refusal is deterministic per configuration:
//! an operator whose key set draws 13 is refused for ever with no re-seed to try.
//!
//! **And the same table shows the current constant is not a bound either.** `P(worst >= 16)` is
//! 0.2 % on the whole-`/24` blocks the builder actually emits, so about one configuration in
//! five hundred at full load produces a Robin Hood table the compiled probe sequence cannot
//! read, and the builder refuses it. That is what makes this candidate a candidate rather than
//! an optimisation: the structure it would replace has a cliff, not just a longer path.
//!
//! **What a bucketised cuckoo buys is the absence of the cliff.** Two buckets by construction,
//! and a load factor of 0.5 into buckets of eight is nowhere near the threshold: **zero
//! insertion failures over 2.1 billion insertions** across those same two thousand key sets,
//! with a worst displacement chain of **six** against a bound of five hundred, and 0.0002
//! evictions per key forced by the signature invariant below. Those are the numbers that decide
//! whether this can replace a structure whose selling point was that insertion cannot fail.
//!
//! **Signatures are the transfer from `rte_hash`, and full-key SWAR is not.** DPDK's table
//! compares sixteen-bit signatures with SIMD and reads a key only on a candidate. Comparing
//! sixteen full `u32` keys without branches costs ~13 instructions per `u64` word times eight
//! words — about the 147 it would replace, so it was discarded at the counting stage. Eight
//! *signature* bytes in one `u64` is one `LDX` and one arithmetic sequence, and the key is read
//! only where a signature matched.
//!
//! **Hopscotch is infeasible here and that is proved rather than argued.** H=8 requires every
//! key to sit within `[home, home + 8)`, and the table above has **no draw at all** below 8 in
//! two thousand: five scattered sets and two block sets reach exactly 8 and every other one
//! goes past it. The assignment Hopscotch needs does not exist for any key set at this load.
//!
//! # The layout, and the two properties it is built around
//!
//! ```text
//! bucket, 64 bytes = one cache line
//!   sigs: u64        eight 8-bit signatures, lane i in byte i. Zero means the lane is free.
//!   keys: [u32; 8]   the full address, read only where a signature matched
//!   tags: [u8; 8]    the verdict. No probe sequence length: there is no probe sequence.
//!   16 bytes of padding
//! ```
//!
//! 2^18 buckets is 16 MiB, the same as the Robin Hood table it would replace, so the 20 MiB
//! the whole flat-table design exists for is untouched.
//!
//! **What eight bits cost at lookup, measured.** A signature that matches a lane holding
//! another key costs one key comparison and no wrong verdict. Over twenty million absent keys
//! per shape the rate is **0.031 per lookup** against 0.031 predicted for eight bits over two
//! buckets at half occupancy, so the filter behaves exactly as arithmetic says and sixteen-bit
//! signatures — which would halve the lanes per cache line — would be buying 0.03 of a
//! comparison.
//!
//! **A signature is never zero.** That is what lets one `u64` carry both the signatures and
//! the occupancy: a query signature is nonzero, so it cannot match a free lane, and a match
//! therefore *implies* an occupied lane with no separate occupancy test. It is also what makes
//! the classic zero-byte search applicable at all.
//!
//! **No two occupied lanes of one bucket share a signature.** The builder enforces it — see
//! [`cuckoo_insert`] — and it is what makes the decode branchless: at most one lane of a
//! bucket can match, so there is nothing to iterate. A structure that allowed duplicates would
//! need a loop over candidates, which is the shape the verifier and the unrolling both hate.
//! The simulation counts how often the invariant forces an eviction it would not otherwise
//! have made, because that cost is the price of the branchlessness.

use crate::Action;
use core::mem::{align_of, size_of};

use super::{OA_INDEX_BITS, OA_MULTIPLIER, fmix32};

/// Lanes in a bucket. Eight, so the signatures are one `u64` and the bucket is one cache line.
pub const CUCKOO_LANES: usize = 8;

/// Log2 of the bucket count: the slot count of the Robin Hood table divided by the lane count,
/// so the two tables hold the same number of keys in the same 16 MiB.
pub const CUCKOO_BUCKET_BITS: u32 = OA_INDEX_BITS - 3;

pub const CUCKOO_BUCKETS: usize = 1 << CUCKOO_BUCKET_BITS;

/// Mask taking any `u32` to a valid bucket index.
pub const CUCKOO_BUCKET_MASK: u32 = (CUCKOO_BUCKETS - 1) as u32;

/// One bucket, on a cache line of its own.
///
/// The alignment is not hygiene: a bucket straddling two lines would double the loads of every
/// lookup that reaches the table, and the whole argument for signatures is that a probe touches
/// one line.
#[repr(C, align(64))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CuckooBucket {
    /// Eight signatures, lane `i` in byte `i`. Zero means free.
    pub sigs: u64,
    /// The full address, host order. Meaningful only where the signature is nonzero.
    pub keys: [u32; CUCKOO_LANES],
    /// The verdict, as an [`Action`] discriminant. Read only where a signature matched, so a
    /// free lane's zero is never decoded.
    pub tags: [u8; CUCKOO_LANES],
    /// To the cache line. Named rather than implicit so `size_of` is a decision.
    pub pad: [u8; 16],
}

impl Default for CuckooBucket {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl CuckooBucket {
    pub const EMPTY: Self = Self {
        sigs: 0,
        keys: [0; CUCKOO_LANES],
        tags: [0; CUCKOO_LANES],
        pad: [0; 16],
    };
}

/// Size of the table, and it is the size of the one it would replace.
pub const CUCKOO_BYTES: usize = CUCKOO_BUCKETS * size_of::<CuckooBucket>();

/// Symbol of the `.bss` global carrying [`CUCKOO_BUCKETS`] buckets.
///
/// It **replaces** [`OA_TABLE_SYMBOL`](super::OA_TABLE_SYMBOL) rather than joining it: both
/// tables in one object would be 36 MiB of `.bss` against the 20 MiB the whole flat-table
/// design exists for. So the two are the same 16 MiB under two names, selected by the
/// `blocklist-cuckoo` feature of `lorica-ebpf`, and a loader patches whichever the object it
/// holds declares.
pub const CUCKOO_TABLE_SYMBOL: &str = "CUCKOO_TABLE";

/// The second multiplier, for the alternate bucket.
///
/// A different odd constant and a second finalizer rather than bits of the first hash: the
/// alternate bucket has to spread independently of the home one or the two choices are one
/// choice. This is the constant the simulation this design came out of used, kept so the
/// numbers stay comparable.
pub const CUCKOO_DELTA_MULTIPLIER: u32 = 0x85eb_ca77;

/// The one hash. Same function and same multiplier as
/// [`oa_index`](super::oa_index), so a key's bucket and its Robin Hood slot are derived from
/// one arithmetic sequence and the packet path computes it once.
pub const fn cuckoo_hash(key: u32) -> u32 {
    fmix32(key.wrapping_mul(OA_MULTIPLIER))
}

/// The home bucket: the top [`CUCKOO_BUCKET_BITS`] of the hash.
pub const fn cuckoo_home(hash: u32) -> u32 {
    hash >> (32 - CUCKOO_BUCKET_BITS)
}

/// The signature: the low byte of the same hash, forced nonzero.
///
/// Low byte against top bits for the bucket, so the two fields come from independent parts of
/// the word — keys sharing a bucket share the top eighteen bits and nothing else.
///
/// **Forced nonzero and not reduced modulo 255.** Zero is the free marker, so it has to be
/// unreachable; a modulo would be a division, and the packet path is asserted to contain none.
/// One value of 256 is therefore twice as likely as the rest, which costs a negligible amount
/// of signature entropy and no correctness at all: the key is still compared exactly.
pub const fn cuckoo_sig(hash: u32) -> u8 {
    let sig = hash as u8;
    if sig == 0 { 1 } else { sig }
}

/// The XOR offset between a key's two buckets, forced nonzero.
///
/// **An XOR and not a second independent index, because the alternate has to be an
/// involution**: `alt(alt(b)) == b`, so a displaced key can be moved back without the table
/// remembering where it came from. Forced nonzero so the two buckets are never the same
/// bucket, which would halve the capacity available to that key with nothing reporting it.
pub const fn cuckoo_delta(key: u32) -> u32 {
    (fmix32(key.wrapping_mul(CUCKOO_DELTA_MULTIPLIER)) & CUCKOO_BUCKET_MASK) | 1
}

/// The other bucket of a key, from either of them.
pub const fn cuckoo_alt(bucket: u32, delta: u32) -> u32 {
    (bucket ^ delta) & CUCKOO_BUCKET_MASK
}

/// One per lane byte.
const LANE_ONES: u64 = 0x0101_0101_0101_0101;

/// The high bit of every lane byte.
const LANE_HIGH: u64 = 0x8080_8080_8080_8080;

/// Lanes whose signature is `sig`, as the high bit of each matching lane byte.
///
/// The classic zero-byte search: broadcast the signature, XOR it into the lane word so a
/// matching lane becomes zero, then `(x - ones) & !x & highs`.
///
/// **It reports the lowest matching lane exactly and lanes above it approximately, which is
/// why the caller must take the lowest set bit.** The subtraction borrows out of a zero byte
/// into the byte above it, so a lane holding `sig ^ 1` immediately above a match is flagged
/// too. Borrow only propagates upward, and a lane is flagged without a borrow only when it
/// genuinely holds `sig`, so the lowest flagged lane is always a true match.
///
/// There is at most one true match per bucket, because the builder refuses to put two keys
/// with the same signature in one bucket. So the lowest set bit is the answer and there is
/// nothing to iterate.
pub const fn cuckoo_match(sigs: u64, sig: u8) -> u64 {
    let x = sigs ^ LANE_ONES.wrapping_mul(sig as u64);
    x.wrapping_sub(LANE_ONES) & !x & LANE_HIGH
}

/// Maps `1 << (8 * i)` to `i`, for `i` in `0..8`.
///
/// One multiply and one shift instead of a count-trailing-zeros, because **the BPF ISA has no
/// such instruction** — RFC 9669 lists no `ctz`, and LLVM lowers `cttz` to either a lookup
/// table in `.rodata` or a loop, one of which is an extra load on the packet path and the
/// other a verifier problem.
///
/// The constant is built by placing the three-bit answer for lane `i` at bits
/// `61 - 8i ..= 63 - 8i`, so that shifting it left by `8i` brings that field to the top. The
/// fields are three bits apart by eight, so none of them overlaps another, and bits below the
/// field cannot reach the top three. `the_lane_decoder_is_exact_over_its_whole_domain` checks
/// all eight.
const LANE_DECODE: u64 =
    (1 << 53) | (2 << 45) | (3 << 37) | (4 << 29) | (5 << 21) | (6 << 13) | (7 << 5);

/// The lane a match mask points at, or `None` when nothing matched.
pub const fn cuckoo_lane(mask: u64) -> Option<usize> {
    if mask == 0 {
        return None;
    }
    // The lowest set bit, which is the lane that genuinely matched. See [`cuckoo_match`].
    let lowest = mask & mask.wrapping_neg();
    // `lowest` is `0x80 << 8i`; the shift takes it to `1 << 8i`, which is what the decoder
    // constant is built for.
    let one = lowest >> 7;
    Some((one.wrapping_mul(LANE_DECODE) >> 61) as usize)
}

/// The lookup, in the form the eBPF variant has to transcribe.
///
/// Two buckets, one cache line each, and the key is read only where a signature matched. There
/// is no probe sequence and therefore no Robin Hood exit and no maximum probe length: a key is
/// in one of its two buckets or it is not in the table.
///
/// **What the eBPF version has to add and this one cannot show.** The alternate bucket is
/// derived by XOR, which is exactly the pattern the 6.8 verifier loses the bound on — it
/// propagates a bound through a shift and drops it at an `XOR`, the way it already does for
/// [`oa_index`](super::oa_index). Both bucket indices therefore need their own
/// `read_volatile` barrier before the `AND`, which is the same trick the shipped probe uses and
/// for the same measured reason.
pub fn cuckoo_lookup(table: &[CuckooBucket], key: u32) -> Option<Action> {
    let hash = cuckoo_hash(key);
    let sig = cuckoo_sig(hash);
    let home = cuckoo_home(hash) & CUCKOO_BUCKET_MASK;
    if let Some(action) = probe(table, home, key, sig) {
        return Some(action);
    }
    let alt = cuckoo_alt(home, cuckoo_delta(key));
    probe(table, alt, key, sig)
}

/// One bucket of a lookup. Inlined on purpose: the eBPF form writes this out twice with a
/// barrier of its own each time, and keeping it one function here is what makes the two
/// transcriptions of it comparable.
#[inline(always)]
fn probe(table: &[CuckooBucket], bucket: u32, key: u32, sig: u8) -> Option<Action> {
    let bucket = &table[(bucket & CUCKOO_BUCKET_MASK) as usize];
    let lane = cuckoo_lane(cuckoo_match(bucket.sigs, sig))?;
    // The key comparison is what makes a signature collision cost a probe and never a wrong
    // verdict, exactly as in the Robin Hood table.
    if bucket.keys[lane & (CUCKOO_LANES - 1)] != key {
        return None;
    }
    Action::from_u8(bucket.tags[lane & (CUCKOO_LANES - 1)])
}

/// Why an insertion could not be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CuckooFull {
    /// The displacement chain reached [`CUCKOO_MAX_KICKS`] without finding a free lane. The
    /// table is not necessarily full; this is the signal to rebuild with different constants,
    /// and it is the failure mode Robin Hood does not have.
    Kicked,
}

/// What one insertion cost.
///
/// The two numbers are reported rather than summed because they answer different questions.
/// `kicks` is the cuckoo property: how long a displacement chain got, which is what decides
/// whether a load factor is reachable at all. `sig_evictions` is the price of the branchless
/// decode: a lane displaced only because leaving it would have put two identical signatures in
/// one bucket, which a structure willing to loop over candidates would not have paid.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Placement {
    pub kicks: u32,
    pub sig_evictions: u32,
}

/// Displacements one insertion is allowed to make before the table is declared unusable.
///
/// Five hundred, which is far above anything the simulation reaches at a load factor of 0.5 —
/// the point of the bound is to terminate a cycle, not to be tight. The number the design is
/// judged on is the *observed* maximum, which `blocklist_sim` prints.
pub const CUCKOO_MAX_KICKS: u32 = 500;

/// Inserts one key, displacing others as needed. Returns the displacements it made.
///
/// **The signature invariant is maintained by choosing the victim rather than by checking
/// afterwards.** If a lane of the target bucket already holds the incoming signature, that lane
/// is the one evicted: the bucket then has room for the incoming key with a signature nothing
/// else in it shares. Only when no signature collides is the victim drawn at random, which is
/// what keeps the walk from cycling.
///
/// `random` is a caller-supplied stream so a build is reproducible: a table whose shape depends
/// on the clock is a table a failure cannot be re-run against.
pub fn cuckoo_insert(
    table: &mut [CuckooBucket],
    key: u32,
    action: Action,
    random: &mut impl FnMut() -> u32,
) -> Result<Placement, CuckooFull> {
    let mut carried_key = key;
    let mut carried_action = action;
    let mut carried_hash = cuckoo_hash(carried_key);
    let mut bucket = cuckoo_home(carried_hash) & CUCKOO_BUCKET_MASK;
    let mut cost = Placement::default();

    loop {
        let sig = cuckoo_sig(carried_hash);
        let alt = cuckoo_alt(bucket, cuckoo_delta(carried_key));

        // Both buckets, and the key's own first: a key already in the table is replaced rather
        // than duplicated, which is what makes a rebuild idempotent over a key set.
        for candidate in [bucket, alt] {
            if let Some(lane) = place(table, candidate, carried_key, sig) {
                let slot = &mut table[candidate as usize];
                slot.sigs = (slot.sigs & !(0xffu64 << (8 * lane))) | (u64::from(sig) << (8 * lane));
                slot.keys[lane] = carried_key;
                slot.tags[lane] = carried_action as u8;
                return Ok(cost);
            }
        }

        if cost.kicks >= CUCKOO_MAX_KICKS {
            return Err(CuckooFull::Kicked);
        }

        // Nothing free and no signature to reuse: evict. A lane whose signature equals the
        // incoming one is chosen when there is one, because leaving it in place would break the
        // invariant the branchless decode rests on; otherwise the choice is random, which is
        // what stops the walk from retracing its own steps.
        let slot = table[bucket as usize];
        let lane = match colliding_lane(slot.sigs, sig) {
            Some(lane) => {
                cost.sig_evictions += 1;
                lane
            }
            None => (random() as usize) & (CUCKOO_LANES - 1),
        };

        let victim_key = slot.keys[lane];
        let victim_action = slot.tags[lane];

        let target = &mut table[bucket as usize];
        target.sigs = (target.sigs & !(0xffu64 << (8 * lane))) | (u64::from(sig) << (8 * lane));
        target.keys[lane] = carried_key;
        target.tags[lane] = carried_action as u8;

        carried_key = victim_key;
        carried_action = Action::from_u8(victim_action).unwrap_or(Action::Continue);
        carried_hash = cuckoo_hash(carried_key);
        // The displaced key goes to its *other* bucket, which is this one XOR its delta — the
        // involution is what makes that computable without remembering anything.
        bucket = cuckoo_alt(bucket, cuckoo_delta(carried_key));
        cost.kicks += 1;
    }
}

/// A lane of `bucket` this key may occupy: a free one, or the one already holding this exact
/// key. `None` when neither exists — including when the bucket has a free lane but another
/// lane already carries this signature, because putting the key there would break the
/// invariant.
fn place(table: &[CuckooBucket], bucket: u32, key: u32, sig: u8) -> Option<usize> {
    let slot = &table[(bucket & CUCKOO_BUCKET_MASK) as usize];
    let mut free = None;
    for lane in 0..CUCKOO_LANES {
        let lane_sig = (slot.sigs >> (8 * lane)) as u8;
        if lane_sig == 0 {
            if free.is_none() {
                free = Some(lane);
            }
            continue;
        }
        if lane_sig == sig {
            // The same key: replace it, which is the only case where a signature may repeat.
            return if slot.keys[lane] == key {
                Some(lane)
            } else {
                None
            };
        }
    }
    free
}

/// The occupied lane of `sigs` carrying `sig`, if any. The straightforward loop and not
/// [`cuckoo_match`]: this is the builder, where clarity is worth more than five instructions,
/// and the two are compared in the simulation rather than assumed equal.
fn colliding_lane(sigs: u64, sig: u8) -> Option<usize> {
    (0..CUCKOO_LANES).find(|&lane| (sigs >> (8 * lane)) as u8 == sig)
}

/// Occupied lanes of a bucket.
pub const fn cuckoo_occupancy(sigs: u64) -> u32 {
    let mut lane = 0;
    let mut count = 0;
    while lane < CUCKOO_LANES {
        if (sigs >> (8 * lane)) as u8 != 0 {
            count += 1;
        }
        lane += 1;
    }
    count
}

// A bucket is a cache line and the table is the size of the one it would replace. Both are
// load-bearing: the first is the whole argument for signatures, the second is what keeps the
// 20 MiB budget the flat tables exist for.
const _: () = assert!(size_of::<CuckooBucket>() == 64);
const _: () = assert!(align_of::<CuckooBucket>() == 64);
const _: () = assert!(CUCKOO_BYTES == super::OA_BYTES);
const _: () = assert!(CUCKOO_BUCKETS * CUCKOO_LANES == super::OA_SLOTS);
