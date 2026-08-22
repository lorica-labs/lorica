//! Every helper call of the data path goes through this module.
//!
//! Two reasons, both structural. The static call budget is auditable by reading one
//! file instead of grepping the pipeline. And each wrapper is `#[inline(never)]`, so
//! it is a single call site rather than one per caller: inlining the counter bump
//! would multiply its map lookup by the number of stages that count.
//!
//! Each wrapper also gets its own JIT symbol, which is the only way to obtain a cost
//! breakdown inside the data path.

use aya_ebpf::{helpers::bpf_ktime_get_ns, maps::lpm_trie::Key};
use carapace_common::{CounterId, LpmValue};

use crate::maps::{COUNTERS, UNIFIED_LIST};

/// A packet is one host, so the lookup asks for the full width of the key and the trie
/// answers with the longest entry that covers it. Precedence is the specificity of the
/// address, and nothing in this program compares prefix lengths to obtain it.
const HOST_PREFIX_BITS: u32 = 128;

/// What the instrumented build counts. Kinds, not call sites: the budget of the
/// design is expressed as lookups and helpers, so that is what a test asserts.
#[cfg(feature = "count-helpers")]
#[derive(Clone, Copy)]
pub enum HelperKind {
    MapLookup = 0,
    ClockRead = 1,
}

#[cfg(feature = "count-helpers")]
impl HelperKind {
    pub const COUNT: u32 = 2;
}

/// Counting is itself a map lookup, so it must not count itself, and the probe write
/// of the parse tests must not count either. Otherwise the instrumented figure would
/// measure the instrumentation.
#[cfg(feature = "count-helpers")]
#[inline(always)]
fn observe(kind: HelperKind) {
    if let Some(slot) = crate::maps::HELPER_COUNTS.get_ptr_mut(kind as u32) {
        // SAFETY: the pointer comes from a successful per-CPU lookup.
        unsafe { *slot += 1 }
    }
}

/// Read once per packet in `stage::run` and passed down. Reading it again in a stage
/// would double a helper call the whole budget is built around.
#[inline(never)]
pub fn now_ns() -> u64 {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::ClockRead);
    // SAFETY: no argument, no pointer, available on every kernel at and above the
    // floor.
    unsafe { bpf_ktime_get_ns() }
}

/// The one map lookup that serves every counter in the program.
///
/// Takes an index rather than a [`CounterId`] because the slots above the named ones
/// belong to individual entries of the unified list, and an entry knows its own index
/// and not a name.
#[inline(never)]
pub fn bump_at(index: u32) {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::MapLookup);
    if let Some(slot) = COUNTERS.get_ptr_mut(index) {
        // SAFETY: the pointer comes from a successful per-CPU lookup, so it is valid
        // for the duration of this program run and not shared with another CPU.
        unsafe { *slot += 1 }
    }
}

/// Inlined on purpose: it resolves a name to an index and calls the one wrapper, so
/// every counter in the program still goes through a single call site.
#[inline(always)]
pub fn bump(id: CounterId) {
    bump_at(id.index());
}

/// The one lookup of the unified list.
///
/// It lives here rather than in the stage for the same reason as the counter bump: the
/// static budget has to be readable in one file, and the instrumented count has to see
/// every call. A lookup issued straight from the stage would be invisible to both.
#[inline(never)]
pub fn list_lookup(src: &[u8; 16]) -> Option<LpmValue> {
    #[cfg(feature = "count-helpers")]
    observe(HelperKind::MapLookup);
    UNIFIED_LIST.get(Key::new(HOST_PREFIX_BITS, *src)).copied()
}

/// Publishes the parsed view for the encapsulation tests. Deliberately outside the
/// helper accounting: it does not exist in a build without the feature.
#[cfg(feature = "parse-probe")]
#[inline(never)]
pub fn probe(view: &carapace_common::PacketView) {
    if let Some(slot) = crate::maps::PARSE_PROBE.get_ptr_mut(0) {
        // The two packet pointers are cleared first: the verifier refuses a store of a
        // pointer into a map value, and their values would mean nothing to a reader in
        // userspace anyway.
        let mut copy = *view;
        copy.data = 0;
        copy.data_end = 0;
        // SAFETY: the pointer comes from a successful per-CPU lookup.
        unsafe { *slot = copy }
    }
}
