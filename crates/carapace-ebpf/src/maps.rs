//! Every map of the program, declared in one place.
//!
//! The sizes here are defaults. Production sizes come from the deployment profile,
//! which derives them from a memlock budget, and the loader applies them before the
//! maps are created.

use aya_ebpf::{
    macros::map,
    maps::{LpmTrie, PerCpuArray, lpm_trie::Key},
};
use carapace_common::{CounterId, LpmKey, LpmValue};

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

/// The parsed view of the last packet, for the encapsulation tests.
///
/// Parsing has to be verifiable before any stage exists to act on it, and a verdict
/// plus a counter cannot tell a destination port read at offset 20 from one read at
/// offset 24. That is the bug this map exists to catch, and it is the one the
/// reference selftest leaves open.
#[cfg(feature = "parse-probe")]
#[map]
pub static PARSE_PROBE: PerCpuArray<carapace_common::PacketView> =
    PerCpuArray::with_max_entries(1, 0);

/// Helper calls executed for one packet, indexed by [`HelperKind`].
#[cfg(feature = "count-helpers")]
#[map]
pub static HELPER_COUNTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(crate::helpers::HelperKind::COUNT, 0);
