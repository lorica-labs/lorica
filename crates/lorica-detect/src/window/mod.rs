//! Two cadences, because one of them is provably blind to the traffic it was built for.
//!
//! **What a single one-second window costs, arithmetically.** A window reports a rate, and
//! a rate over a window is an average over that window. A burst-flood 300 ms long averaged
//! over 1 s reads at 30 % of its actual rate: the fixture in `tests/replay.rs` puts
//! 1 200 000 over-budget packets per second into 300 ms, and a one-second window reports
//! 360 000 — below a threshold the same traffic clears three times over at 100 ms. The same
//! aliasing is what lets a pulse-wave rotate its vector between two reads and be measured
//! only in the mixture. Nothing about the threshold fixes this; it is the window.
//!
//! **Why not one 100 ms window for everything.** Because the tick already measured what
//! that costs. Reading a per-CPU counter slot is about 264 ns, linear in slots read per
//! second, and fifty thousand slots at ten hertz is 13 % of a core. So the fast cadence
//! carries only what a burst needs — the named counters and the bank — and profiles,
//! fingerprints, escalation and hysteresis stay on the slow one, where a full sweep costs a
//! tenth as much per second.
//!
//! **Why the period is a field and not a constant.** Both cadences are the same arithmetic
//! over a different interval, and the interval has to be a value for the aliasing above to
//! be demonstrable: `sub_second_burst` replays one recorded sequence at both cadences and
//! asserts the fast one sees what the slow one cannot.

/// The burst cadence. Chosen so a burst-flood shorter than a second occupies whole periods
/// rather than fractions of one.
pub const FAST_PERIOD_NS: u64 = 100_000_000;

/// The profile cadence: escalation, hysteresis and the descent all count in these.
pub const SLOW_PERIOD_NS: u64 = 1_000_000_000;

/// A rate derived from a running total sampled at least `period_ns` apart.
///
/// The window closes on the first observation at or past its period rather than at a fixed
/// grid, so a tick that arrives late reports the rate over the interval that actually
/// elapsed instead of attributing its extra traffic to a nominal 100 ms.
pub struct Window {
    period_ns: u64,
    opened_at_ns: u64,
    opened_total: u64,
    dt_ns: u64,
    per_sec: u64,
    primed: bool,
}

impl Window {
    pub fn new(period_ns: u64) -> Self {
        Self {
            period_ns: period_ns.max(1),
            opened_at_ns: 0,
            opened_total: 0,
            dt_ns: 0,
            per_sec: 0,
            primed: false,
        }
    }

    /// Feeds one reading of the running total. Answers the rate when this reading closed a
    /// period, and nothing when the period is still open.
    ///
    /// A total that went backwards answers zero rather than an enormous positive rate. The
    /// tick leaves the previous total standing when a batch read fails, so a total below the
    /// one before it is a read that did not happen, not traffic that un-arrived, and the
    /// direction that is safe to be wrong in is the low one.
    pub fn observe(&mut self, at_ns: u64, total: u64) -> Option<u64> {
        if !self.primed {
            self.primed = true;
            self.opened_at_ns = at_ns;
            self.opened_total = total;
            return None;
        }

        let dt_ns = at_ns.saturating_sub(self.opened_at_ns);
        if dt_ns < self.period_ns {
            return None;
        }

        let delta = total.saturating_sub(self.opened_total);
        let per_sec = delta.saturating_mul(1_000_000_000) / dt_ns.max(1);

        self.dt_ns = dt_ns;
        self.per_sec = per_sec;
        self.opened_at_ns = at_ns;
        self.opened_total = total;
        Some(per_sec)
    }

    /// The interval the last closed period actually spanned, which is what every other rate
    /// taken on the same tick has to be divided by.
    pub fn dt_ns(&self) -> u64 {
        self.dt_ns
    }

    pub fn per_sec(&self) -> u64 {
        self.per_sec
    }
}
