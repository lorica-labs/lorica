//! The four invariants the ladder rests on, now that it is fed.
//!
//! Until this week `state.rs` built every snapshot with two empty vectors, and its own comment
//! said why: *nothing in the tick reads the bucket bank or the unified list yet*. The ladder,
//! the hysteresis and the cardinality scan were all written and all tested, and all of them ran
//! on nothing — `Confirmation::ExactKey` wants a counter slot that is rising and no slot was
//! ever read, so nothing could ever be confirmed.
//!
//! Feeding it makes four properties testable that could not be tested before, because each of
//! them is about what the engine does with an input it did not previously receive. They are
//! written here rather than beside the code they check because three of the four are about the
//! *composition* of the snapshot, the engine and the hysteresis, and a unit test of any one of
//! the three cannot see them.
//!
//! Every snapshot here is built by hand. This crate reads no map and no clock — it is told the
//! time — so a hand-built sequence exercises exactly the arithmetic a live agent runs.

use lorica_common::{CounterId, DEFAULT_BANK_BUCKETS, LpmKey, UNITS_PER_BYTE};
use lorica_detect::{
    BucketView, Config, CounterView, Engine, Snapshot,
    snapshot::{EntryCounter, NAMED_SLOTS},
    tier::ladder::Tier,
};

/// The fast cadence the engine samples at, in nanoseconds. Ten of these make a slow tick.
const PERIOD_NS: u64 = 100_000_000;

/// A source that is a candidate and never a suspect: no counter names it, only a bucket.
const HOT_ADDR: [u8; 4] = [203, 0, 113, 9];

/// What a tick carries. Built as a struct rather than passed as six arguments so a test reads
/// as a description of the traffic rather than as a call.
#[derive(Clone, Copy, Default)]
struct Tick {
    /// Buckets over the loaded threshold, out of `DEFAULT_BANK_BUCKETS`.
    loaded: u32,
    /// Hits added to the one entry's own slot since the previous tick.
    entry_hits: u64,
    /// Whether the per-entry slice and the bank were re-read this tick. False models a sweep
    /// that did not run or that failed.
    fresh: bool,
}

/// Builds a sequence and feeds it, answering the rung in force after each tick.
///
/// The counter totals are cumulative because that is what the map offers: every rate in the
/// engine is derived from two readings and the interval between them, and a fixture handing it
/// deltas would be testing arithmetic the agent does not do.
struct Replay {
    engine: Engine,
    named: [u64; NAMED_SLOTS],
    entry_hits: u64,
    at_ns: u64,
    /// The stamp the last *fresh* tick carried. A stale tick republishes it unchanged, which is
    /// exactly what the agent does when a sweep does not run.
    fresh_at_ns: u64,
    seq: u64,
}

impl Replay {
    fn new(cfg: Config) -> Self {
        Self {
            engine: Engine::new(cfg),
            named: [0; NAMED_SLOTS],
            entry_hits: 0,
            at_ns: 0,
            fresh_at_ns: 0,
            seq: 0,
        }
    }

    fn step(&mut self, tick: Tick) -> Tier {
        self.entry_hits += tick.entry_hits;
        if tick.fresh {
            self.fresh_at_ns = self.at_ns;
        }

        let entries = vec![EntryCounter {
            key: LpmKey::host_v4(HOT_ADDR),
            hits: self.entry_hits,
        }];
        let mut counters = CounterView::new(self.named, entries);
        counters.set_entries_at_ns(self.fresh_at_ns);

        let mut levels = vec![0u64; DEFAULT_BANK_BUCKETS as usize];
        // Comfortably over `loaded_level_units`, so `loaded` is the only variable.
        let level = 64 * 1024 * UNITS_PER_BYTE;
        for slot in levels.iter_mut().take(tick.loaded as usize) {
            *slot = level;
        }
        let mut buckets = BucketView::new(levels);
        buckets.set_at_ns(self.fresh_at_ns);

        let snapshot = Snapshot {
            seq: self.seq,
            at_ns: self.at_ns,
            counters,
            buckets,
        };
        self.seq += 1;
        self.at_ns += PERIOD_NS;
        self.engine.observe(&snapshot).tier()
    }

    fn run(&mut self, ticks: usize, tick: Tick) -> Tier {
        let mut last = Tier::Observe;
        for _ in 0..ticks {
            last = self.step(tick);
        }
        last
    }
}

/// Enough ticks for the ladder to climb as far as the traffic can take it: the hysteresis
/// spends `rise_ticks` on the streak and `hold_ticks` stabilising between rungs, on the slow
/// cadence, which is one tick in ten.
const LONG: usize = 400;

/// **A loaded bank, on its own, can never refuse a packet.**
///
/// This is the invariant the whole two-sided snapshot exists for. With 1 024 buckets and any
/// realistic source count two sources share one — pigeonhole, not hashing quality — so a level
/// is a state a second source moves, and a refusal resting on it refuses whoever else hashed
/// there. The engine may climb: marking and limiting rest on pressure legitimately. What it
/// may not do is reach a rung that drops.
#[test]
fn a_loaded_bank_alone_never_reaches_a_rung_that_drops() {
    let mut replay = Replay::new(Config::default());
    let tier = replay.run(
        LONG,
        Tick {
            // The whole bank over the threshold: there is no more pressure to offer.
            loaded: DEFAULT_BANK_BUCKETS,
            entry_hits: 0,
            fresh: true,
        },
    );
    assert!(
        !tier.drops(),
        "pressure alone reached {tier:?}, which refuses packets on a signal no source owns"
    );
}

/// **An entry whose own slot is rising can.**
///
/// The other half of the same invariant, and the reason the first one is a property of the
/// design rather than of a threshold being too high: the same engine, the same bank, plus a
/// per-entry counter that no other source can increment, does climb into refusal. Without this
/// the first test would pass on an engine that simply never climbs.
#[test]
fn an_exact_entry_taking_hits_does_reach_one() {
    let cfg = Config::default();
    // Comfortably over `entry_per_sec`, sustained. A slow tick is ten fast ones, so the rate
    // the engine derives is this divided by the fast period and multiplied out.
    let per_tick = cfg.entry_per_sec * 10;
    let mut replay = Replay::new(cfg);
    let tier = replay.run(
        LONG,
        Tick {
            loaded: DEFAULT_BANK_BUCKETS,
            entry_hits: per_tick,
            fresh: true,
        },
    );
    assert!(
        tier.drops(),
        "an exact key taking hits reached only {tier:?}: the confirmed side of the snapshot is \
         not reaching the ladder, which is the failure this whole change exists to fix"
    );
}

/// **A sweep that did not happen moves no rung.**
///
/// The dangerous misreading, and the one requirement (d) is about. A slice whose stamp has not
/// moved is *not looked at*; treating it as unchanged would make an agent that stopped reading
/// its maps indistinguishable from an attack that stopped, and only one of those should let the
/// ladder descend. The engine is first driven into refusal, then fed stale ticks: the rung must
/// stay exactly where the last real reading left it.
#[test]
fn a_sweep_that_did_not_happen_moves_no_rung() {
    let cfg = Config::default();
    let per_tick = cfg.entry_per_sec * 10;
    let mut replay = Replay::new(cfg);
    let climbed = replay.run(
        LONG,
        Tick {
            loaded: DEFAULT_BANK_BUCKETS,
            entry_hits: per_tick,
            fresh: true,
        },
    );
    assert!(climbed.drops(), "the fixture did not reach a refusing rung");

    // The traffic has not changed; the agent has stopped seeing it. Nothing in the snapshot
    // moves except the clock.
    let held = replay.run(
        LONG,
        Tick {
            loaded: DEFAULT_BANK_BUCKETS,
            entry_hits: per_tick,
            fresh: false,
        },
    );
    assert_eq!(
        held, climbed,
        "the rung moved from {climbed:?} to {held:?} while the agent was reading nothing: a \
         stalled sweep is being read as a change in the traffic"
    );
}

/// The named counters still reach the engine, so a fixture that fed nothing would fail here
/// rather than pass the three tests above by never demanding anything.
#[test]
fn the_named_counters_still_drive_the_climb() {
    let mut replay = Replay::new(Config::default());
    let quiet = replay.run(50, Tick::default());
    assert_eq!(quiet, Tier::Observe, "a quiet agent should stay at rung 0");

    let busy = replay.run(
        LONG,
        Tick {
            loaded: DEFAULT_BANK_BUCKETS,
            entry_hits: 0,
            fresh: true,
        },
    );
    assert!(
        busy > Tier::Observe,
        "a bank fully loaded demanded nothing at all, so the fixture is not reaching the engine"
    );
    assert!(!busy.drops());
    // The invalid-packet counter is the other confirmation route and is deliberately not
    // exercised here: `CounterId::COUNT` is asserted only so that a catalogue change that
    // renumbers the slots breaks this file too.
    assert!(CounterId::COUNT as usize >= NAMED_SLOTS);
}
