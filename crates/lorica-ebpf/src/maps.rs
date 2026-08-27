//! Every map of the program, declared in one place.
//!
//! The sizes here are defaults. Production sizes come from the deployment profile,
//! which derives them from a memlock budget, and the loader applies them before the
//! maps are created.

use aya_ebpf::{
    bindings::BPF_F_MMAPABLE,
    macros::map,
    maps::{Array, LpmTrie, lpm_trie::Key},
};
// Only the two instrumentation maps below are per-CPU now, and both are behind a feature.
#[cfg(any(feature = "parse-probe", feature = "count-helpers"))]
use aya_ebpf::maps::PerCpuArray;
use lorica_common::{
    Bucket, CLASS24_BYTES, CounterId, CounterLayout, LpmKey, LpmValue, OA_SLOTS, OaSlot,
};

/// Entries of the unified list, and the per-entry counter slots that go with them.
const DEFAULT_LIST_ENTRIES: u32 = 1024;

/// Named counters first, then one slot per entry of the unified list — and one such block
/// per processor, laid end to end in one flat array.
///
/// **Why not `PerCpuArray`, which is what this was.** Reading the counters cost the agent
/// 13 % of a core at the worst configuration, and every nanosecond of it was
/// `BPF_MAP_LOOKUP_BATCH`: ~130 ns fixed plus ~34 ns per possible processor per element, two
/// `copy_to_user` calls and a `cond_resched()` for each one. The way out is not a faster
/// syscall, it is no syscall: `BPF_F_MMAPABLE` lets the agent map the map and read the slots
/// as memory. **The kernel refuses that flag on a per-CPU map** — `map_create` checks it
/// against `BPF_MAP_TYPE_ARRAY` only — so the conversion to a flat array is the precondition
/// and not a detail of the design.
///
/// **What the striping preserves.** `index = cpu * COUNTER_STRIPE + slot`, so each processor
/// owns a contiguous region nothing else writes, and the increment below stays a plain
/// non-atomic add. The stripe is rounded to a cache line
/// ([`COUNTER_STRIPE_SLOTS`](lorica_common::COUNTER_STRIPE_SLOTS)) so a boundary never falls
/// inside one; the reverse layout, one processor's value beside another's for the same slot,
/// would put every processor's counters for one slot in one line and make each bump
/// invalidate it everywhere.
///
/// **What it costs on the packet path**: one `bpf_get_smp_processor_id`, which the verifier
/// does not inline before 6.10, plus a multiply and an add. The static call budget in
/// `lorica-dataplane/tests/helper_budget.rs` had one slot of headroom and this is what
/// spends it.
///
/// The flag goes through `with_max_entries`, whose `flags` argument reaches
/// `bpf_map_def` → `MapData::create` → `bpf_create_map` unchanged — the same path that
/// carries `BPF_F_NO_PREALLOC` for the trie. No fork of aya is involved.
///
/// The size here is a default nothing deploys with. The loader recomputes it from the
/// machine's possible-processor count and the profile's slot count, and patches
/// [`COUNTER_STRIPE`](crate::settings) to match; the two are one decision in
/// `lorica_common::CounterLayout`.
#[map]
pub static COUNTERS: Array<u64> = Array::with_max_entries(
    match CounterLayout::new(CounterId::COUNT + DEFAULT_LIST_ENTRIES, 1) {
        Some(layout) => layout.entries(),
        // Unreachable: one processor and a slot count under 2^29. `unwrap` is not const
        // here, and a panic in a map declaration would be a panic at load time.
        None => CounterId::COUNT + DEFAULT_LIST_ENTRIES,
    },
    BPF_F_MMAPABLE,
);

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

/// The two blocklist tables, and the reason they are globals and not maps.
///
/// A `.bss` global is reached by one `LDX` off a pointer the verifier materialises with
/// `ld_imm64` / `BPF_PSEUDO_MAP_VALUE`, so a lookup costs no `bpf_map_lookup_elem` — not
/// even the eight instructions the verifier inlines an `ARRAY` lookup into. That is the
/// whole reason the blocklist stage fits inside a per-packet budget already spending two
/// lookups: it adds none.
///
/// **What it costs, measured before it was written.** `aya` turns a data section into an
/// `ARRAY` map of one entry whose value is the whole section, so these two are 4 MiB and
/// 16 MiB of `value_size`. `bpftool map create ... type array key 4 value 20971520
/// entries 1` is accepted on 7.0.0-30 and reports `memlock 20971824B`, which is what
/// dismissed the fear that `array_map_alloc_check` would answer `-E2BIG` past
/// `KMALLOC_MAX_SIZE`.
///
/// No `link_section`: both land in `.bss`, which is one map, and the loader writes each
/// one by symbol name through `EbpfLoader::set_global`. `aya` materialises a `.bss`
/// section as a zero vector of its declared size and splices a patched symbol into it at
/// the symbol's own address, so nothing here has to agree with the other table's offset.
#[unsafe(no_mangle)]
pub static mut CLASS24: [u8; CLASS24_BYTES] = [0; CLASS24_BYTES];

/// The open-addressed table. Zeroed, and zero is *free* rather than
/// `0.0.0.0`: [`lorica_common::blocklist::OA_TAG_OCCUPIED`] is what separates the two.
#[unsafe(no_mangle)]
pub static mut OA_TABLE: [OaSlot; OA_SLOTS] = [OaSlot { key: 0, tag: 0 }; OA_SLOTS];

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
/// Lock-free measured 84 ns against 107 uncontended.
///
/// The 2.62x that figure was once paired with was called a worst case and is not one: it
/// came from a fixture where four cores did nothing but the update, and measuring the real
/// stage put the factor between 1.6 and 4.0, bimodal, with single readings up to 3.27. What
/// bounds it is the thread count, which is the dilution the per-CPU layout would have
/// imposed by construction — so the retained layout beats the one it was retained over, and
/// that is the whole claim. `tests/stage_bucket.rs` reports the distribution.
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
