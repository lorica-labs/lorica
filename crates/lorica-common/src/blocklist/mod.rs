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
//! `array_map_gen_lookup` — and `aya` creates `.bss` maps `BPF_F_MMAPABLE`, so the agent
//! rewrites them through `mmap` rather than one syscall per entry. The "three map lookups per
//! packet" budget stops being the binding constraint for this stage.
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

/// Slot count. A power of two, which is what makes the index mask below structural rather
/// than a bounds check the program has to remember to write.
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

/// Builds a tag.
///
/// **The tag carries a verdict, not membership.** If the configuration denies `10.0.0.0/8`
/// and allows `10.1.2.3/32`, the `/32` has to win *with the opposite verdict*, and the table
/// result short-circuits `CLASS24`. A membership boolean would be wrong here, and the
/// equivalent bug exists in production elsewhere (Cilium issue #41121). The general rule: do
/// not split the decision across two structures, split the storage. "Longest prefix wins" is
/// resolved at construction, in the agent; the packet path only reads.
pub const fn oa_tag(action: Action, psl: u8) -> u32 {
    OA_TAG_OCCUPIED
        | ((action as u32) & OA_TAG_ACTION_MASK) << OA_TAG_ACTION_SHIFT
        | (psl as u32) << OA_TAG_PSL_SHIFT
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
    while distance < OA_PROBES {
        let slot = table[(index & OA_INDEX_MASK) as usize];
        if !oa_occupied(slot.tag) {
            return None;
        }
        if slot.key == key {
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
