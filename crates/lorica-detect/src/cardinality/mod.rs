//! The second stage: how wide the traffic is spread, and across how many sources.
//!
//! **What this catches that the ladder cannot.** [`tier`](crate::tier) confirms a refusal on
//! one key taking hits fast enough to be named — `hottest_entry` against
//! `Config::entry_per_sec`. Carpet bombing is built to defeat exactly that: the attack aims
//! at a prefix rather than an address, so the load divides across every entry under it and
//! **no single counter reaches its threshold** while their sum is an order of magnitude past
//! it. The signal is not a level anywhere, it is the *width* of the spread, which is a
//! property of the whole map and of no slot in it.
//!
//! **Why this is not in the kernel program, with its number.** A per-prefix sketch updated
//! per packet is one more map lookup and one more hash on the steady-state path — the path
//! the per-packet budget is stated about. The one hash that path already gave up cost 61 to
//! 73 ns of a 210 ns pipeline (see
//! [`MultiplyShift`](lorica_common::MultiplyShift)), so a second one is not affordable, and
//! eBPF has no vector unit to amortise it with either. Up here the same arithmetic runs once
//! a tick over the whole map, in registers eight lanes wide. That division — the kernel
//! counts, the agent reduces — is the asymmetry this stage exists to demonstrate.
//!
//! **The two signals, and why they are two.** [`scan`] answers the width exactly, because
//! the entry slots are an enumeration and counting an enumeration needs no estimator.
//! [`estimator`] answers the source count approximately, because sources are not
//! enumerated anywhere: what exists is the occupancy of a bank indexed by a hash of the
//! source address. Width without sources cannot tell a carpet from a broad flash crowd;
//! sources without width cannot tell a carpet from a botnet on one target. Neither is
//! derivable from the other, which is why both are in [`Verdict`] and why the ladder, not
//! this file, decides what to do with them.

pub mod estimator;
pub mod scan;
pub mod view;

use lorica_common::DEFAULT_BANK_BUCKETS;

use crate::snapshot::BucketView;
use scan::{Isa, reduce_with};
use view::CounterSlots;

/// Everything this stage needs that is not in a snapshot.
///
/// Every field is a **parameter** and none is a measurement. This tree holds no traffic
/// capture of a carpet bombing, so the defaults are stated to be re-baselined rather than
/// presented as findings, and the doc on each says against what.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Hits on one entry, in one tick, below which the entry does not count as active.
    /// One: any movement at all. Would be re-baselined against the background rate a
    /// quiet unified list actually shows.
    pub active_floor: u64,
    /// Entries active at once that make the spread a carpet rather than ordinary breadth.
    /// Parameter, and the one that decides the false-positive rate: a list of a thousand
    /// entries under normal traffic has some number of them moving, and this has to be
    /// above it.
    pub min_prefixes: u32,
    /// Hits on one entry, in one tick, at or above which the ladder's own keyed path
    /// already names that entry. A carpet is defined by nothing reaching this, so the two
    /// stages cannot both claim the same traffic.
    pub per_prefix_ceiling: u64,
    /// Distinct sources at or above which the spread is treated as spoofed rather than as a
    /// botnet. Parameter: 4096, four times the bank, which is where linear counting has
    /// already lost most of its resolution.
    pub min_sources: u64,
    /// Buckets in the bank. [`DEFAULT_BANK_BUCKETS`] by default and a field because
    /// [`BucketView`] publishes shares rather than its own length — see
    /// [`estimator::occupied`].
    pub buckets: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            active_floor: 1,
            min_prefixes: 64,
            per_prefix_ceiling: 1_000,
            min_sources: 4_096,
            buckets: DEFAULT_BANK_BUCKETS,
        }
    }
}

/// What one tick's scan found. Not a decision: the numbers a decision can be written about.
#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    /// Which path actually ran, which is not always the one asked for.
    pub isa: Isa,
    /// Entries that moved at all this tick.
    pub prefixes: u32,
    /// The largest single entry delta.
    pub hottest: u64,
    /// Every entry delta added up. The number that is orders of magnitude past the
    /// per-entry threshold while [`Self::hottest`] is under it.
    pub total: u64,
    /// Distinct sources behind the bank's occupancy, or `None` when the bank is full and
    /// the estimator has no information left to give.
    pub sources: Option<u64>,
    /// The spread is wide and nothing in it is hot.
    pub carpet: bool,
    /// More distinct sources than [`Params::min_sources`], a full bank included.
    pub spoofed: bool,
}

/// The stage. Holds the previous entry slots and nothing else.
///
/// Positional against the previous read, exactly as
/// [`Engine::hottest_entry`](crate::Engine) is: the slot order is the counter index order
/// the policy compiler allocated, so it is stable for as long as the policy is, and a
/// change of length is a recompiled policy whose deltas across the change would be
/// meaningless. The history is dropped there rather than reinterpreted.
pub struct PrefixCardinality {
    isa: Isa,
    prev: Vec<u64>,
    primed: bool,
}

impl Default for PrefixCardinality {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixCardinality {
    /// Detects the widest path once, here, and not on every tick.
    pub fn new() -> Self {
        Self {
            isa: Isa::detect(),
            prev: Vec::new(),
            primed: false,
        }
    }

    /// The path this stage will use unless one is forced.
    pub const fn isa(&self) -> Isa {
        self.isa
    }

    /// One tick. Allocates only when the map's entry count changes, which is a recompiled
    /// policy and not a tick.
    pub fn observe(&mut self, slots: &CounterSlots<'_>, bank: &BucketView, p: &Params) -> Verdict {
        self.observe_with(self.isa, slots, bank, p)
    }

    /// One tick on a named path. `isa` is a value so a test can enter the fallback on the
    /// machine it is running on; a path this processor cannot run falls back to the scalar
    /// one and says so in [`Verdict::isa`].
    pub fn observe_with(
        &mut self,
        isa: Isa,
        slots: &CounterSlots<'_>,
        bank: &BucketView,
        p: &Params,
    ) -> Verdict {
        let cur = slots.entries();
        let occupied = estimator::occupied(bank.loaded_share(0), p.buckets);
        let sources = estimator::distinct_sources(occupied, p.buckets);
        let spoofed = sources.is_none_or(|n| n >= p.min_sources);

        // The first reading is the baseline every later delta is taken against. A live
        // agent attaches to maps that already hold counts, so answering a width here would
        // report the whole history of the machine as one tick's spread.
        if !self.primed || self.prev.len() != cur.len() {
            self.prev.clear();
            self.prev.extend_from_slice(cur);
            self.primed = true;
            return Verdict {
                isa,
                prefixes: 0,
                hottest: 0,
                total: 0,
                sources,
                carpet: false,
                spoofed,
            };
        }

        let (isa, r) = match reduce_with(isa, cur, &self.prev, p.active_floor) {
            Some(r) => (isa, r),
            None => (
                Isa::Scalar,
                reduce_with(Isa::Scalar, cur, &self.prev, p.active_floor).unwrap_or_default(),
            ),
        };
        self.prev.copy_from_slice(cur);

        Verdict {
            isa,
            prefixes: r.active,
            hottest: r.hottest,
            total: r.total,
            sources,
            // Both halves, and the second one is what keeps the two stages apart: a spread
            // with something hot in it is the case the ladder's keyed path already names,
            // and claiming it here would let two stages confirm on the same traffic.
            carpet: r.active >= p.min_prefixes && r.hottest < p.per_prefix_ceiling,
            spoofed,
        }
    }
}
