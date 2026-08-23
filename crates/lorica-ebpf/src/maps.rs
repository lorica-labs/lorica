//! Every map of the program, declared in one place.
//!
//! The sizes here are defaults. Production sizes come from the deployment profile,
//! which derives them from a memlock budget, and the loader applies them before the
//! maps are created.

use aya_ebpf::{
    macros::map,
    maps::{Array, LpmTrie, PerCpuArray, lpm_trie::Key},
};
use lorica_common::{Bucket, CounterId, LpmKey, LpmValue};

/// Entries of the unified list, and the per-entry counter slots that go with them.
const DEFAULT_LIST_ENTRIES: u32 = 1024;

/// Named counters first, then one slot per entry of the unified list.
///
/// Per-CPU so a bump is a lookup and an add with no atomic on the critical path, and
/// so the agent can sum the slots in one batch read instead of one syscall per counter.
#[map]
pub static COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(CounterId::COUNT + DEFAULT_LIST_ENTRIES, 0);

/// One list, one lookup: the allow list and the block list are the same trie and the
/// value carries the verdict.
///
/// `BPF_F_NO_PREALLOC` is not optional for this map type and aya sets it itself. It is
/// also why the kernel memory an entry costs is a measurement rather than a
/// multiplication: the trie allocates per node.
#[map]
pub static UNIFIED_LIST: LpmTrie<[u8; 16], LpmValue> =
    LpmTrie::with_max_entries(DEFAULT_LIST_ENTRIES, 0);

// The key aya builds and the key the policy compiler writes have to be the same bytes,
// and neither crate can see the other type: one is packed, one is not, and only their
// layouts have to agree.
const _: () = assert!(core::mem::size_of::<Key<[u8; 16]>>() == core::mem::size_of::<LpmKey>());

/// Where the clock probe leaves the jiffy it read.
///
/// Not per-CPU: the reader is a userspace process, not the processor that ran the probe,
/// and one slot the kernel keeps global is less arithmetic than a scan of per-CPU slots
/// that are all zero but one. It is in the object that ships because the agent needs
/// `CONFIG_HZ` and the current jiffy before it can turn a TTL in seconds into a deadline,
/// and the kernel exposes neither to userspace.
#[map]
pub static CLOCK_PROBE: Array<u64> = Array::with_max_entries(1, 0);

/// The parsed view of the last packet, for the encapsulation tests.
///
/// Parsing has to be verifiable before any stage exists to act on it, and a verdict
/// plus a counter cannot tell a destination port read at offset 20 from one read at
/// offset 24. That is the bug this map exists to catch, and it is the one the
/// reference selftest leaves open.
#[cfg(feature = "parse-probe")]
#[map]
pub static PARSE_PROBE: PerCpuArray<lorica_common::PacketView> =
    PerCpuArray::with_max_entries(1, 0);

/// Helper calls executed for one packet, indexed by [`HelperKind`].
#[cfg(feature = "count-helpers")]
#[map]
pub static HELPER_COUNTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(crate::helpers::HelperKind::COUNT, 0);

/// Buckets in the bank.
///
/// A compile-time constant and not a load-time global, unlike the sizes above, because the
/// index is the top `log2` of this number bits of the hash: resizing the bank would mean
/// patching a shift width and the map size together, and nothing in this phase resizes it.
/// A power of two, so the reduction is that shift and no division is emitted. The value
/// itself lives in `lorica_common` because the memlock budget is computed in a crate that
/// cannot see this one, and a bank the budget does not know about is kernel memory nobody
/// counted.
pub const BANK_BUCKETS: u32 = lorica_common::DEFAULT_BANK_BUCKETS;

/// One bucket, on a cache line of its own.
///
/// The alignment is a measurement and not hygiene. A [`Bucket`] is 16 bytes, so four of
/// them share a 64-byte line, and four cores updating four *different* buckets inside one
/// line measured 1.99 of scaling where four cores on four lines measured 3.88 — half the
/// benefit of the cores lost to false sharing. `lorica_common::Bucket` stays the two words
/// the arithmetic needs; the padding belongs on this side, in the same envelope that would
/// have carried a `bpf_spin_lock` had the lock been retained. 1024 buckets go from 16 KiB
/// to 64 KiB, which is nothing against the memlock budget of any of the three profiles.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct BankSlot {
    pub bucket: Bucket,
}

// The budget charges a cache line an entry. If the alignment ever stopped producing one,
// the budget would be charging for padding the kernel does not allocate.
const _: () = assert!(
    core::mem::size_of::<BankSlot>() as u64 == lorica_common::BANK_SLOT_BYTES,
    "the bank slot is no longer the size the memlock budget charges for it"
);

/// The leaky-bucket bank: shared, lock-free, one entry per bucket.
///
/// **Why no lock.** Measured on four pinned vCPU against a concentrated distribution, a
/// `bpf_spin_lock` around this update cost 1 988 ns per packet and 0.24 of the aggregate
/// throughput of a single core: the second, third and fourth CPU do not fail to help, they
/// slow the first one down. It collapses under exactly the attack shape it exists to
/// handle, and it would have put the path at three lookups and three helpers, over budget.
/// Lock-free measured 84 ns against 107 uncontended and leaks at most 2.62x in the worst
/// concurrency case.
///
/// **Which direction that leak goes, because it is the only reason tolerating one is
/// defensible.** A lost update is an update that never reached the level, so the level runs
/// *low*, the ceiling is reached *later*, and enforcement comes out more permissive. A
/// factor of N is therefore N times the configured rate getting through — never N times a
/// conformant flow wrongly refused. The error is always non-detection, which is the
/// direction the zero-false-positive criterion of the phase can absorb; a leak that ran the
/// other way would be refusing traffic nobody decided to refuse, and no factor of that
/// would be acceptable. `lorica-dataplane/tests/stage_bucket.rs` measures the factor and
/// reports it as a distribution.
///
/// **Why not per-CPU**, which needs no synchronisation at all: the enforcement diluted to
/// exactly 1/N — four CPUs charged 0.2500 of what was offered — so a flood spread across
/// source ports would collect 4.00x the configured budget for free.
///
/// **Why one entry per bucket and not one entry holding the bank.** The saved lookup saves
/// nothing, 85 ns against 87, because the verifier inlines an `ARRAY` lookup instead of
/// emitting a call. And the index comes from a hash of the source address, so it is
/// attacker-influenced: an index into one large value has to be masked, and a mask is
/// exactly what LLVM moves or drops when it believes it knows the bound — the refusal
/// elsewhere in this program reads `var_off=(0x0; 0xff)`. One entry per bucket makes the
/// lookup itself the bound check, which the verifier proves and no optimiser can remove.
#[map]
pub static BUCKET_BANK: Array<BankSlot> = Array::with_max_entries(BANK_BUCKETS, 0);
