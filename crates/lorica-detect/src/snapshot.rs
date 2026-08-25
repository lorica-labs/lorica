//! Immutable views over the maps the tick read in one batch.
//!
//! **Why the snapshot has two sides and not one.** The bank holds
//! [`Bucket`](lorica_common::Bucket), which is a level and a timestamp and no source key.
//! That is not a gap to work around. With [`DEFAULT_BANK_BUCKETS`](lorica_common::
//! DEFAULT_BANK_BUCKETS) = 1024 buckets and any realistic number of active sources, two
//! sources share a bucket by the pigeonhole principle, and no quality of hashing changes
//! it — `multiply_shift` spreads 10 000 constructed collisions to a chi-square of 76.8, and
//! spreading is not separating. So [`BucketView`] is the *candidate* side of the snapshot:
//! it can name a number and never a source. [`CounterView::entries`] is the *confirmed*
//! side: the slots above the named counters belong one to an entry of the unified list,
//! which is an exact key, and an exact key is the one thing no other source can move.
//!
//! **The alternative that was rejected, with its cost.** Carrying the last key charged to
//! each bucket alongside its level would have given every candidate a name for
//! `size_of::<LpmKey>()` = 20 bytes a bucket, 20 KiB across the bank, and one more batch
//! read per tick. It is absent because that field is precisely a state another source
//! displaces: the attacker's next packet overwrites it, so a rule resting on it refuses
//! whoever was written there last. The 20 KiB was never the objection.

use lorica_common::{CounterId, LpmKey, SHARE_SCALE};

/// Slots the named counters occupy, read from `lorica-common` rather than restated: a
/// number copied from one crate into another expires without saying so.
pub const NAMED_SLOTS: usize = CounterId::ALL.len();

/// One slot above the named counters, together with the unified-list entry it belongs to.
///
/// The key travels with the count because the agent is the only side that knows the
/// pairing: the policy compiler assigned the `counter_idx`, the kernel side only increments
/// it. Reconstructing the pairing from the index alone would mean the detector holding a
/// second copy of the compiler's allocation, which is the drift the counter map's own tests
/// exist to refuse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EntryCounter {
    pub key: LpmKey,
    pub hits: u64,
}

/// The counter map as one tick saw it: the named slots by index, and the per-entry slots
/// with their keys.
pub struct CounterView {
    named: [u64; NAMED_SLOTS],
    entries: Vec<EntryCounter>,
}

impl CounterView {
    pub fn new(named: [u64; NAMED_SLOTS], entries: Vec<EntryCounter>) -> Self {
        Self { named, entries }
    }

    /// The running total, not a delta. Every rate in this crate is derived from two of
    /// these and the time between them, because that is what the map actually offers and a
    /// delta computed anywhere else would need its own memory of the previous read.
    pub fn get(&self, id: CounterId) -> u64 {
        self.named[id.index() as usize]
    }

    pub fn named(&self) -> &[u64; NAMED_SLOTS] {
        &self.named
    }

    pub fn entries(&self) -> &[EntryCounter] {
        &self.entries
    }
}

/// The bucket levels as one tick saw them, in the order of the bank.
///
/// The [`BankLayout`](lorica_common::BankLayout) is not stored: the only two things read
/// off the bank here are how loaded it is and how much it holds, and both come from the
/// levels themselves. `shards` would be a field nothing reads.
pub struct BucketView {
    levels: Vec<u64>,
}

impl BucketView {
    pub fn new(levels: Vec<u64>) -> Self {
        Self { levels }
    }

    /// Share of the bank carrying more than `units`, in [`SHARE_SCALE`] units.
    ///
    /// A share and not a count, so the signal means the same thing to a bank sized
    /// differently by configuration, and in `SHARE_SCALE` units because that denominator
    /// already exists for exactly this: a power of two, 16 bits, chosen because a share
    /// derived from sampled packet counters cannot resolve finer than its own noise.
    pub fn loaded_share(&self, units: u64) -> u32 {
        if self.levels.is_empty() {
            return 0;
        }
        let loaded = self.levels.iter().filter(|l| **l > units).count() as u64;
        (loaded * u64::from(SHARE_SCALE) / self.levels.len() as u64) as u32
    }

    /// Everything the bank is holding, in bucket units.
    ///
    /// Saturating, because the sum of 1024 levels each bounded by
    /// `BURST_MAX * UNITS_PER_BYTE` is within `u64` but a corrupt read is not, and a
    /// wrapped total would read as the bank suddenly emptying.
    pub fn total_units(&self) -> u64 {
        self.levels
            .iter()
            .fold(0u64, |acc, l| acc.saturating_add(*l))
    }
}

/// One tick's reading of everything the engine gets to see.
///
/// `at_ns` and not a clock call: this crate does not read the time, it is told the time.
/// The tick owns the clock, so a replay of a recorded sequence exercises the same
/// arithmetic as a live agent instead of a fixture-flavoured variant of it.
pub struct Snapshot {
    pub seq: u64,
    pub at_ns: u64,
    pub counters: CounterView,
    pub buckets: BucketView,
}

impl Snapshot {
    /// This reading on the kernel's coarse clock, which is the only clock
    /// [`Deadline`](lorica_common::Deadline) is comparable against.
    ///
    /// `hz` is a parameter and not a constant because `CONFIG_HZ` has no userspace
    /// interface: the agent measures it through `CLOCK_PROBE` and hands it down.
    pub const fn jiffies(&self, hz: u32) -> u64 {
        let hz = if hz == 0 { 1 } else { hz as u64 };
        let ns_per_jiffy = 1_000_000_000 / hz;
        self.at_ns / if ns_per_jiffy == 0 { 1 } else { ns_per_jiffy }
    }
}
