//! The two global tables the packet path reads instead of walking a trie.
//!
//! **What this replaces, with the number that forced it.** The unified list is an
//! `LPM_TRIE`, and `BPF_F_NO_PREALLOC` is not optional on that map type: every level is a
//! dereference to a separately allocated node, so depth *is* cost. Measured on the 901 with
//! an absent key drawn inside a `/16` the loaded set actually populates, the legitimate path
//! costs 116 ns at one entry, 285 at 16 384 and **414 at one million**, while the number of
//! bits shared with a real entry climbs from 16 to 27. A million entries also cost **198 MiB**
//! of kernel memory. Nothing about that is a defect of the trie; it is what a trie does.
//!
//! What is here instead is two flat tables that cost the same at one entry and at ten
//! million, and 20 MiB fixed:
//!
//! ```text
//! CLASS24  2^24 x 2 bits =  4 MiB   00 nothing . 01 deny . 10 allow . 11 consult the table
//! OA_TABLE 2^21 x 8 B    = 16 MiB   u32 key + u32 tag, Robin Hood, open addressing
//! ```
//!
//! **The lever is that these are `.bss` globals and not maps.** A global is reached by one
//! `LDX` — no `bpf_map_lookup_elem`, not even the eight instructions of
//! `array_map_gen_lookup`. Measured on the shipped object: the stage adds zero helper calls,
//! and `helper_budget` still reads five static calls against a ceiling of six with
//! `KFUNC_BUDGET == 0`. The "three map lookups per packet" budget stops being the binding
//! constraint for this stage.
//!
//! **`aya` does not create `.bss` maps `BPF_F_MMAPABLE`, and the reload works anyway.** This
//! module used to claim it did, on the strength of the design note this came from; `aya-obj`
//! 0.3 maps `EbpfSectionKind::Bss` to `map_flags: 0` and gives a read-only flag to `.rodata`
//! alone. What it does instead is materialise the whole section as an `ARRAY` of **one** entry
//! whose value is the section — so both tables live in a single 20 MiB value at offsets 0 and
//! `CLASS24_BYTES`, and a full reload is **one** `bpf_map_update_elem` rather than one per
//! entry. The exit criterion the flat tables were for is met, by a different mechanism than
//! the one that was predicted.
//!
//! Twenty MiB of `.bss` is accepted: `bpftool map create … value 20971520 entries 1` succeeds
//! on 6.8.0-138 and on 7.0.0-30, and the loaded program shows
//! `map_value(map=.bss,ks=4,vs=20971520)` in the verifier log. The `-E2BIG` from
//! `array_map_alloc_check` past `KMALLOC_MAX_SIZE` does not materialise; 32 MiB is accepted
//! too.
//!
//! **What is still open, and it is not a lookup problem.** One `bpf_map_update_elem` over a
//! live 20 MiB value is a copy the packet path can read halfway through, and an eight-byte
//! slot torn between its key and its tag is a verdict neither snapshot holds. Writing whole
//! immutable snapshots, which the builder does, does not by itself make publishing them
//! atomic. Two fixed tables plus an active index would be 40 MiB and past the budget the
//! whole design is for; `ARRAY_OF_MAPS` turns the map pointer into a variable and loses the
//! inlining that is the point. The candidate answer is **re-attachment** — a second program
//! instance with fresh `.bss`, swapped with `XDP_FLAGS_REPLACE`, whose cost is already
//! measured — and it is a decision to take with a number, not here.
//!
//! **Not free, and the calibration reserve is written here so nobody rounds it to zero.**
//! The bounds check and the Spectre mask survive; an inlined array access has been published
//! at 3.9 +/- 0.8 ns. Budget **4 to 5 ns per access**, not "almost nothing".
//!
//! # Which structure answers which question
//!
//! | Key | Answered by |
//! |---|---|
//! | IPv4 prefix `<= /24`, any length | `CLASS24` alone, in one access |
//! | IPv4 `/25` to `/32` | `CLASS24` says `Table`, then `OA_TABLE` |
//! | IPv6, any length | the surviving `LPM_TRIE` |
//! | An exact key detection wrote, carrying a deadline | the surviving `LPM_TRIE` |
//!
//! The last row is the one that is easy to get wrong. These two tables are **immutable
//! snapshots the agent rebuilds**, and a tag is 32 bits with no room for a deadline: giving
//! one to every slot would make it 16 bytes and 32 MiB, past the whole budget. Entries the
//! detection loop writes need a per-entry deadline and a single-entry update, which is what
//! the trie already does well and what it keeps doing. The split is by lifetime, not by
//! address family: operator blocklists are large, static and rebuilt; detection entries are
//! few, short-lived and expire on their own.
//!
//! # A table miss is not a verdict, and it falls back to nothing
//!
//! This is the one rule the two sides could disagree about while both looking correct, so it
//! is written here rather than in either of them.
//!
//! [`Class24::Table`] replaces the code of the **whole** `/24`. So the moment one `/32`
//! inside a denied `/8` needs the opposite verdict, the `/8`'s answer for the other 255
//! addresses has nowhere left to live. The builder therefore writes those 255 keys out: in a
//! `Table` block, **every address carrying a verdict has its own key**. A miss means no
//! verdict was configured for that address, and the packet path continues exactly as it does
//! on [`Class24::None`] — it does not re-read the block code, does not probe a second time
//! with the block's base address, and does not fall back to anything.
//!
//! The alternative was a third code bit carrying the fallback, which is 8 MiB instead of 4 and
//! breaks the 20 MiB the whole design is for. The price paid instead is that one exception
//! inside a short prefix costs a full block of keys, which the builder charges against its
//! expansion bound and refuses rather than truncates.
//!
//! # What two bits cannot spell
//!
//! [`Class24`] holds four codes and all four are taken, so a prefix at most `/24` long can
//! carry deny or allow and nothing else. [`Action::Continue`], [`Action::RateLimit`] and
//! [`Action::Mark`] on such a prefix are **refused at construction** — rounding them to the
//! nearest verdict would silently change what the rule does. The same verdicts on a `/25` to
//! `/32` are fine, because [`oa_tag`] has three bits for them. The escape hatch for an
//! operator who genuinely needs to rate-limit a `/16` is the surviving `LPM_TRIE`, which
//! carries a whole [`LpmValue`](crate::LpmValue); nothing routes there today, and this is a
//! limit to publish rather than a gap to fill speculatively.
//!
//! # Why `CLASS24` is not a filter
//!
//! With a million `/32` scattered over roughly a million distinct `/24`, only about 6 % of the
//! 16.7 M `/24` carry the `Table` mark, so a legitimate address leaves in **one access** 94 %
//! of the time. That is a pleasant consequence and not the reason it exists. The reason is
//! that it resolves longest-prefix-match for *every* prefix `<= /24` without a second
//! structure, which is what removes the need for a trie at all. As a filter it would earn
//! almost nothing: Robin Hood misses in 1.33 probes on average, so there is little left to
//! save.
//!
//! # Why Robin Hood and not cuckoo
//!
//! Insertion cannot fail and the maximum probe length is **observable at construction**,
//! where cuckoo can fail to place and needs a rebuild with a fresh seed. [`OA_PROBES`] is
//! compiled into the unrolled probe sequence and the builder refuses to publish a snapshot
//! whose measured maximum exceeds it, which turns a probabilistic property into an invariant
//! somebody can check.

use core::mem::{align_of, size_of};

use crate::Action;

// ---------------------------------------------------------------------------
// CLASS24
// ---------------------------------------------------------------------------

/// Prefix length `CLASS24` indexes. Every IPv4 prefix at least this short is resolved by the
/// table alone.
pub const CLASS24_PREFIX_BITS: u32 = 24;

/// Number of `/24` blocks, one entry each.
pub const CLASS24_ENTRIES: usize = 1 << CLASS24_PREFIX_BITS;

/// Entries packed per byte, at two bits each.
pub const CLASS24_PER_BYTE: usize = 4;

/// Size of the table. 4 MiB.
pub const CLASS24_BYTES: usize = CLASS24_ENTRIES / CLASS24_PER_BYTE;

/// Symbol of the `.bss` global carrying [`CLASS24_BYTES`] bytes.
pub const CLASS24_SYMBOL: &str = "CLASS24";

/// What a `/24` carries.
///
/// Two bits, and the fourth code is what makes the table complete rather than a hint:
/// `Table` says the answer is in [`OA_TABLE_SYMBOL`], so no `/24` is ever ambiguous.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class24 {
    /// No configured prefix covers this `/24`.
    None = 0,
    /// A prefix `<= /24` denies it, and nothing longer contradicts that.
    Deny = 1,
    /// A prefix `<= /24` allows it, and nothing longer contradicts that.
    Allow = 2,
    /// At least one `/25` to `/32` inside this `/24` carries a verdict. Consult the table.
    Table = 3,
}

impl Class24 {
    /// Parses a two-bit code. Total, because every two-bit pattern is a valid code.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::None,
            1 => Self::Deny,
            2 => Self::Allow,
            _ => Self::Table,
        }
    }
}

/// Index of the `/24` an address falls in.
pub const fn class24_index(addr: u32) -> usize {
    (addr >> (32 - CLASS24_PREFIX_BITS)) as usize
}

/// Reads the code for an address out of a [`CLASS24_BYTES`]-byte table.
///
/// The packing is little-end within the byte: entry `i` occupies bits `2 * (i % 4)` and
/// `2 * (i % 4) + 1` of byte `i / 4`. Frozen here because the agent writes these bytes
/// through `mmap` and the program reads them with hand-written shifts; a disagreement about
/// which end of the byte holds entry zero is a silent wrong verdict on three quarters of the
/// address space.
pub const fn class24_get(table: &[u8], addr: u32) -> Class24 {
    let index = class24_index(addr);
    Class24::from_bits(table[index / CLASS24_PER_BYTE] >> class24_shift(index))
}

/// Writes the code for an address into a [`CLASS24_BYTES`]-byte table.
pub fn class24_set(table: &mut [u8], addr: u32, class: Class24) {
    let index = class24_index(addr);
    let shift = class24_shift(index);
    let byte = &mut table[index / CLASS24_PER_BYTE];
    *byte = (*byte & !(0b11 << shift)) | ((class as u8) << shift);
}

/// Bit offset of an entry inside its byte.
pub const fn class24_shift(index: usize) -> u32 {
    2 * (index % CLASS24_PER_BYTE) as u32
}

// ---------------------------------------------------------------------------
// OA_TABLE
// ---------------------------------------------------------------------------

/// Log2 of the slot count. Sized so a million keys sit at a load factor of 0.477.
pub const OA_INDEX_BITS: u32 = 21;

/// Slot count. A power of two, so [`OA_INDEX_MASK`] takes any `u32` to a valid index.
///
/// **That does not make the mask structural, and this module used to claim it did.** A
/// compile-time size is exactly what lets LLVM prove the mask redundant and delete it: on the
/// shipped object it folded [`oa_index`] to `(h >> 11) ^ (h >> 27)`, proved the result under
/// 2^21, and removed the `AND`. The 7.0 verifier propagates the bound through that `XOR` and
/// accepts it; **6.8, which is this project's floor, loses it** — `R2_w=scalar()` and then
/// `math between map_value pointer and register with unbounded min value is not allowed`.
/// Every blocklist test was refused on the floor kernel while passing on 7.0.
///
/// The packet path therefore forces the mask to survive with a `read_volatile` barrier between
/// the hash and the `AND`, once, before the unrolled probes. It made the object 109 JITed
/// bytes *smaller*, LLVM having also stopped duplicating the shift chain.
pub const OA_SLOTS: usize = 1 << OA_INDEX_BITS;

/// Mask taking any `u32` to a valid slot index.
pub const OA_INDEX_MASK: u32 = (OA_SLOTS - 1) as u32;

/// Size of the table. 16 MiB.
pub const OA_BYTES: usize = OA_SLOTS * size_of::<OaSlot>();

/// Symbol of the `.bss` global carrying [`OA_SLOTS`] slots.
pub const OA_TABLE_SYMBOL: &str = "OA_TABLE";

/// Largest number of keys a snapshot may carry.
///
/// **A load factor under 0.5 is mandatory, not a preference.** Simulated at 0.477 — one
/// million keys in 2^21 slots — the average miss costs 1.33 probes and the p99.9 is 19. At
/// 0.7 the average miss goes to about 5 and the p99.9 to about 70. The builder refuses past
/// this rather than degrading quietly.
pub const OA_MAX_KEYS: usize = OA_SLOTS / 2;

/// Probes the packet path unrolls, and the maximum probe length the builder will accept.
///
/// **Unrolled to a constant and never a loop.** A loop bounded by a global would blow up the
/// verifier's state space, and the bound is known at build time anyway. The builder measures
/// the real maximum probe length over the keys it just inserted and refuses to publish a
/// snapshot that exceeds this, so the constant is an invariant the program may rely on and
/// not an expectation it hopes holds.
///
/// Sixteen against a **measured** maximum of 11 — `tests/blocklist_layout.rs` at 1 048 450
/// keys and a load factor of 0.500, which is the worst load this format permits. The plan's
/// simulation said 8; the number here is the one that was run. The margin is deliberate and
/// its cost is JITed bytes, which `jited_size` measures.
pub const OA_PROBES: u32 = 16;

/// One slot. Key and tag, eight bytes, no padding.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OaSlot {
    /// The full IPv4 address, host order. Meaningful only when the tag says occupied.
    pub key: u32,
    /// Occupancy, verdict and probe sequence length. See [`oa_tag`].
    pub tag: u32,
}

/// Set when the slot holds a key.
///
/// **Without it a free slot and `0.0.0.0` are the same bit pattern**, and a table zeroed by
/// `.bss` would answer "deny" for the address every uninitialised source uses.
pub const OA_TAG_OCCUPIED: u32 = 1;

/// Shift of the three verdict bits.
pub const OA_TAG_ACTION_SHIFT: u32 = 1;

/// Mask of the verdict field, before shifting.
pub const OA_TAG_ACTION_MASK: u32 = 0b111;

/// Shift of the probe sequence length.
pub const OA_TAG_PSL_SHIFT: u32 = 8;

/// Mask of the probe sequence length field, before shifting.
pub const OA_TAG_PSL_MASK: u32 = 0xff;

/// Shift of the key fingerprint.
pub const OA_TAG_FINGERPRINT_SHIFT: u32 = 16;

/// Mask of the key fingerprint, before shifting.
pub const OA_TAG_FINGERPRINT_MASK: u32 = 0xff;

/// Eight bits of the key's own hash, stored in the tag beside the verdict.
///
/// # What it is for: a torn slot that answers "no verdict" instead of "drop"
///
/// Publishing a snapshot is one `bpf_map_update_elem` over a live 20 MiB `.bss` value, and the
/// packet path can read that value halfway through the copy. An eight-byte slot split across
/// the copy boundary then carries the **new key beside the old tag** — a pair neither snapshot
/// ever held. The old tag's verdict may be `Drop` for a key the new snapshot allows, so the
/// window is a *false positive*: traffic dropped because nobody decided to drop it, which is
/// the one failure mode this whole design refuses to have.
///
/// With the fingerprint, a torn slot is detected instead of believed: the tag holds the
/// fingerprint of the key it was written with, so a key from one snapshot beside a tag from
/// another disagrees with probability 255/256 and [`oa_lookup`] reads the slot as holding
/// somebody else. The probe carries on, the lookup ends in `None`, and `None` under a `Table`
/// code is *no verdict* — the address is treated exactly as it was before any rule existed.
/// **The failure direction is inverted: a wrongly dropped packet becomes a wrongly passed
/// one**, which is the direction the rest of this module already accepts and documents.
///
/// The remaining 1/256 is not a hole this design pretends to close. It is a torn slot whose two
/// keys share a fingerprint, during a copy, for one snapshot — and what closes it completely is
/// re-attaching a second program instance, which is a decision to take with a cycle count
/// rather than with a byte of tag.
///
/// # Why the eight bits are free to compute and not free to check
///
/// It is the **low byte of the hash [`oa_index`] already computed**: the index takes the top
/// [`OA_INDEX_BITS`] of `fmix32(key * OA_MULTIPLIER)` and the low bits were being thrown away.
/// So neither the builder nor the packet path computes anything new — the querier holds the
/// fingerprint of the key it is looking for before the first probe.
///
/// What is not free is the comparison. The tag was already loaded and two of its fields were
/// already tested, but a third test is a third test: one compare and one branch per unrolled
/// step. It is cheaper than it looks on the *executed* path, because a fingerprint that does
/// not match makes the key comparison unnecessary and 255 of 256 occupied slots on a probe run
/// therefore stop before the key is read at all — but the *static* count goes up, and
/// `lorica-dataplane/tests/jited_size.rs` is what says by how much. The design note this came
/// from estimated zero; that was optimistic, and the correction belongs here rather than in a
/// document nobody compiles.
///
/// # It composes with the signature of the cuckoo design
///
/// The candidate cuckoo replacement compares an eight-bit *signature* before it reads a key, and
/// that signature is this same byte with zero forced away, because there a zero marks a free
/// lane. If that variant ever replaces this table, the self-validating slot arrives
/// with it rather than being ported to it: comparing a signature before the key is what that
/// design does for speed, and detecting a torn bucket is the same comparison.
pub const fn oa_fingerprint(key: u32) -> u8 {
    fmix32(key.wrapping_mul(OA_MULTIPLIER)) as u8
}

/// The fingerprint a tag carries.
pub const fn oa_tag_fingerprint(tag: u32) -> u8 {
    ((tag >> OA_TAG_FINGERPRINT_SHIFT) & OA_TAG_FINGERPRINT_MASK) as u8
}

/// Builds a tag for a key.
///
/// **The tag carries a verdict, not membership.** If the configuration denies `10.0.0.0/8`
/// and allows `10.1.2.3/32`, the `/32` has to win *with the opposite verdict*, and the table
/// result short-circuits `CLASS24`. A membership boolean would be wrong here, and the
/// equivalent bug exists in production elsewhere (Cilium issue #41121). The general rule: do
/// not split the decision across two structures, split the storage. "Longest prefix wins" is
/// resolved at construction, in the agent; the packet path only reads.
///
/// It takes the key rather than a fingerprint, so a caller cannot write a tag whose fingerprint
/// belongs to another key — which is the exact corruption [`oa_fingerprint`] exists to detect,
/// and a builder able to create it deliberately is a builder able to create it by accident.
pub const fn oa_tag(key: u32, action: Action, psl: u8) -> u32 {
    OA_TAG_OCCUPIED
        | ((action as u32) & OA_TAG_ACTION_MASK) << OA_TAG_ACTION_SHIFT
        | (psl as u32) << OA_TAG_PSL_SHIFT
        | (oa_fingerprint(key) as u32) << OA_TAG_FINGERPRINT_SHIFT
}

/// Whether a tag marks an occupied slot.
pub const fn oa_occupied(tag: u32) -> bool {
    tag & OA_TAG_OCCUPIED != 0
}

/// The verdict a tag carries. `None` for a discriminant no [`Action`] has, which is a
/// corrupt table rather than a configuration choice.
pub const fn oa_action(tag: u32) -> Option<Action> {
    Action::from_u8(((tag >> OA_TAG_ACTION_SHIFT) & OA_TAG_ACTION_MASK) as u8)
}

/// The probe sequence length a tag carries: how far the slot sits from its home index.
pub const fn oa_psl(tag: u32) -> u8 {
    ((tag >> OA_TAG_PSL_SHIFT) & OA_TAG_PSL_MASK) as u8
}

/// Odd multiplier of the multiply-shift, 2^32 divided by the golden ratio.
pub const OA_MULTIPLIER: u32 = 0x9e37_79b1;

/// Home index of a key.
///
/// **Multiply-shift with a `fmix32` finalizer behind it, and the finalizer buys a guarantee
/// rather than a gain.** Two-independence is *proved insufficient* for open addressing: the
/// expected query cost is square-root of n in the worst case (Pagh, Pagh, Ruzic, STOC 2007),
/// logarithmic under 3- and 4-wise independence, and constant only from 5-wise or with
/// tabulation. The Murmur3 finalizer costs two multiplies and two xorshifts, no rotation —
/// which matters, because the absence of a rotate instruction in the BPF ISA is normative
/// (RFC 9669 section 4.1) and v4 does not add one, so any ARX primitive pays a factor of
/// three. Report it as insurance, never as a speedup.
///
/// **Not keyed, and that is a decision.** A collision here costs probes and never a wrong
/// verdict, because the key is compared exactly; and [`OA_PROBES`] bounds what an attacker
/// who guessed the layout could inflate. A per-snapshot seed would put one more `.rodata`
/// load on the packet path to defend a budget that is already capped.
pub const fn oa_index(key: u32) -> u32 {
    fmix32(key.wrapping_mul(OA_MULTIPLIER)) >> (32 - OA_INDEX_BITS)
}

/// The next slot in a probe sequence.
pub const fn oa_step(index: u32) -> u32 {
    index.wrapping_add(1) & OA_INDEX_MASK
}

/// Murmur3's 32-bit finalizer.
pub const fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// The reference lookup, in the form both sides have to agree on.
///
/// Three exits, and the third is the Robin Hood invariant: a slot whose own probe sequence
/// length is shorter than the distance we have already walked cannot be followed by our key,
/// because insertion would have displaced it. That is what bounds a miss to the maximum PSL
/// rather than to the load factor.
///
/// The packet path unrolls this to [`OA_PROBES`] steps instead of looping, and reaches the
/// slots through a masked index into a `.bss` global rather than through a slice. This
/// function is what the builder round-trips against and what
/// `tests/blocklist_equivalence.rs` compares the unrolled form to; keeping one written
/// definition is the only reason the two can be claimed equivalent.
pub fn oa_lookup(table: &[OaSlot], key: u32) -> Option<Action> {
    let mut index = oa_index(key);
    let mut distance = 0u32;
    // Bits of the same hash the index came from, so obtaining it costs nothing. See
    // [`oa_fingerprint`] for what it buys and what the comparison below costs.
    let fingerprint = oa_fingerprint(key);
    while distance < OA_PROBES {
        let slot = table[(index & OA_INDEX_MASK) as usize];
        if !oa_occupied(slot.tag) {
            return None;
        }
        // The fingerprint first and the key second, which is the order the cost argument
        // depends on: 255 of 256 occupied slots on a probe run are rejected before the key is
        // compared at all. And a slot whose fingerprint disagrees with its own key is a slot
        // torn by a snapshot copy, so reading it as somebody else's is what makes that window
        // fail open instead of dropping traffic nobody decided to drop.
        if fingerprint == oa_tag_fingerprint(slot.tag) && slot.key == key {
            return oa_action(slot.tag);
        }
        if (oa_psl(slot.tag) as u32) < distance {
            return None;
        }
        index = oa_step(index);
        distance += 1;
    }
    None
}

/// The reference insertion, in the form both sides have to agree on.
///
/// Returns the probe sequence length the key ended up at, or `None` if the sequence ran past
/// [`OA_PROBES`] — which is the builder's signal to refuse the snapshot rather than publish a
/// table the unrolled lookup cannot read.
///
/// Robin Hood: a key that has walked further than the slot it lands on takes the slot and
/// carries the evicted one onward. That is what bounds the *maximum* probe length instead of
/// the average, and the maximum is the only thing an unrolled lookup can be compiled against.
///
/// **Here and not in the builder on purpose.** Insertion decides where a key lands, so a
/// builder and a test harness that each wrote their own would agree on the format and
/// disagree on the table. The builder wraps this with the policy — the load factor ceiling,
/// the prefix expansion, the exhaustive round trip — and the dataplane tests fill their
/// fixtures with it, so both read a table the other would have produced.
pub fn oa_insert(table: &mut [OaSlot], key: u32, action: Action) -> Option<u8> {
    let mut index = oa_index(key);
    let mut distance = 0u32;
    let mut carried_key = key;
    let mut carried_action = action;
    let mut placed = None;
    loop {
        if distance >= OA_PROBES {
            return None;
        }
        let slot = table[(index & OA_INDEX_MASK) as usize];
        let displace = oa_psl(slot.tag) as u32;
        if !oa_occupied(slot.tag) || displace < distance {
            table[(index & OA_INDEX_MASK) as usize] = OaSlot {
                key: carried_key,
                tag: oa_tag(carried_key, carried_action, distance as u8),
            };
            if placed.is_none() {
                placed = Some(distance as u8);
            }
            if !oa_occupied(slot.tag) {
                return placed;
            }
            carried_key = slot.key;
            carried_action = oa_action(slot.tag)?;
            distance = displace;
        }
        index = oa_step(index);
        distance += 1;
    }
}

// ---------------------------------------------------------------------------
// The trie that survives
// ---------------------------------------------------------------------------

/// Symbol of the `.rodata` boolean that keeps the `LPM_TRIE` stage in the program.
///
/// Zero erases the stage before the JIT, the way `SIGNATURE_VECTORS` erases an unarmed
/// vector: the verifier treats `.rodata` as constant and removes the branch physically. The
/// loader sets it when the configuration carries IPv6 entries or when the agent is armed and
/// therefore needs somewhere to write exact keys with deadlines. On the common case — an
/// IPv4 blocklist, observation only — the legitimate path pays exactly one access.
pub const BLOCKLIST_TRIE_SYMBOL: &str = "BLOCKLIST_TRIE";

// These tables are a shared in-memory structure, not an ABI: the eBPF program and the agent
// each compile their own view of it and nothing checks them against each other at run time.
// Asserting here fails the build of both the moment one drifts.
const _: () = assert!(size_of::<OaSlot>() == 8);
const _: () = assert!(align_of::<OaSlot>() == 4);
const _: () = assert!(CLASS24_BYTES == 4 * 1024 * 1024);
const _: () = assert!(OA_BYTES == 16 * 1024 * 1024);
const _: () = assert!(OA_MAX_KEYS * 2 == OA_SLOTS);
const _: () = assert!(OA_PROBES <= OA_TAG_PSL_MASK);
// The four tag fields do not overlap. A fingerprint sharing a bit with the probe length would
// hide a displaced key and a torn slot at the same time, and the two failures would look like
// one.
const _: () = assert!(
    OA_TAG_OCCUPIED
        & (OA_TAG_ACTION_MASK << OA_TAG_ACTION_SHIFT
            | OA_TAG_PSL_MASK << OA_TAG_PSL_SHIFT
            | OA_TAG_FINGERPRINT_MASK << OA_TAG_FINGERPRINT_SHIFT)
        == 0
);
const _: () =
    assert!(OA_TAG_ACTION_MASK << OA_TAG_ACTION_SHIFT & OA_TAG_PSL_MASK << OA_TAG_PSL_SHIFT == 0);
const _: () = assert!(
    OA_TAG_PSL_MASK << OA_TAG_PSL_SHIFT & OA_TAG_FINGERPRINT_MASK << OA_TAG_FINGERPRINT_SHIFT == 0
);
