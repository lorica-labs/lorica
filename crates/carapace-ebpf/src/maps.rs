//! Every map of the program, declared in one place.

use aya_ebpf::{macros::map, maps::PerCpuArray};
use carapace_common::CounterId;

/// One slot per [`CounterId`]. Per-CPU so a bump is a lookup and an add with no
/// atomic on the critical path, and so the agent can sum the slots in one batch read
/// instead of one syscall per counter.
#[map]
pub static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(CounterId::COUNT, 0);

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
