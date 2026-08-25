//! Rise, stabilisation, descent — the three counters that keep a pulse-wave from driving
//! the ladder.
//!
//! **Why the descent is not the rise with the comparison flipped.** A symmetric rule
//! oscillates by construction against traffic that alternates: whatever streak arms the
//! rise, the same streak of quiet disarms it, and an attacker who knows the streak length
//! sets their period to twice it. Three separate counters break that: a lower demand must
//! hold for longer than a higher one did (`fall_ticks` above `rise_ticks`), and no
//! transition of either kind is allowed within `hold_ticks` of the last one. The pulse-wave
//! fixture is 5 cycles of 2 s against `fall_ticks` = 5 slow ticks, and the transition count
//! it produces is the measurement — printed as `LORICA_TRANSITIONS`, not judged by eye.
//!
//! **Why one rung at a time, in both directions.** It is what makes the rungs 0 to 2 chain
//! themselves on timing alone. Nothing in this type can see whether `bpf_qdisc` is
//! available, so the climb from `Observe` to `Limit` takes the same number of slow ticks on
//! a kernel that has it and on a kernel that does not; without it, rung 1 is a no-op that is
//! counted and not acted on. The alternative — jumping straight to `Limit` when marking
//! cannot be enforced — was rejected because it makes the verdict a function of the kernel:
//! the same traffic would be rate-limited on one host and merely marked on another, at the
//! same instant, and no operator could reconcile the two logs.
//!
//! The `Deadline` on each [`Decision`](super::ladder::Decision) sits under all of this. It
//! is not a fourth counter, it is the case where the counters never run: see
//! [`Hysteresis::expire`].

use super::ladder::Tier;

pub struct Hysteresis {
    rise_ticks: u32,
    hold_ticks: u32,
    fall_ticks: u32,
    current: Tier,
    demanded: Tier,
    streak: u32,
    since_change: u32,
}

impl Hysteresis {
    /// `since_change` starts saturated: the first transition is gated by the demand streak
    /// alone, since there is no previous transition to stabilise after.
    pub fn new(rise_ticks: u32, hold_ticks: u32, fall_ticks: u32) -> Self {
        Self {
            rise_ticks: rise_ticks.max(1),
            hold_ticks,
            fall_ticks: fall_ticks.max(1),
            current: Tier::Observe,
            demanded: Tier::Observe,
            streak: 0,
            since_change: u32::MAX,
        }
    }

    /// Feeds one slow tick's demand and answers the rung now in force.
    pub fn step(&mut self, demand: Tier) -> Tier {
        if demand == self.demanded {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.demanded = demand;
            self.streak = 1;
        }
        self.since_change = self.since_change.saturating_add(1);

        if self.since_change < self.hold_ticks {
            return self.current;
        }
        if demand > self.current && self.streak >= self.rise_ticks {
            self.current = self.current.up();
            self.since_change = 0;
        } else if demand < self.current && self.streak >= self.fall_ticks {
            self.current = self.current.down();
            self.since_change = 0;
        }
        self.current
    }

    pub fn current(&self) -> Tier {
        self.current
    }

    /// Abandons the ladder in one step, for the case the counters above cannot cover:
    /// nothing renewed the standing decision before its deadline.
    ///
    /// One step and not a rung, because an expired deadline means slow ticks stopped
    /// arriving — the agent stalled, was killed, lost the map. Descending politely would
    /// require the ticks that are precisely what is missing.
    pub fn expire(&mut self) -> Tier {
        self.current = Tier::Observe;
        self.demanded = Tier::Observe;
        self.streak = 0;
        self.since_change = 0;
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rise takes its streak, the stabilisation delay blocks the next rung, and one rung is
    /// taken per pass — the three behaviours the pulse-wave case rests on.
    #[test]
    fn one_rung_per_streak_plus_hold() {
        let mut h = Hysteresis::new(2, 2, 5);

        assert_eq!(
            h.step(Tier::Limit),
            Tier::Observe,
            "one tick is not a streak"
        );
        assert_eq!(h.step(Tier::Limit), Tier::Mark, "streak met, one rung only");
        assert_eq!(h.step(Tier::Limit), Tier::Mark, "stabilising");
        assert_eq!(h.step(Tier::Limit), Tier::Limit);
    }

    /// The descent is longer than the climb was, which is the asymmetry that makes an
    /// attacker's period useless to them.
    #[test]
    fn descent_needs_the_longer_streak() {
        let mut h = Hysteresis::new(2, 2, 5);
        for _ in 0..4 {
            h.step(Tier::Limit);
        }
        assert_eq!(h.current(), Tier::Limit);

        for tick in 0..4 {
            assert_eq!(h.step(Tier::Observe), Tier::Limit, "fell at tick {tick}");
        }
        assert_eq!(h.step(Tier::Observe), Tier::Mark);
    }

    #[test]
    fn expiry_abandons_every_rung_at_once() {
        let mut h = Hysteresis::new(2, 2, 5);
        for _ in 0..8 {
            h.step(Tier::DropBroad);
        }
        assert!(h.current() > Tier::Limit);
        assert_eq!(h.expire(), Tier::Observe);
    }
}
