//! The engine: two cadences in, one rung out.
//!
//! **Why the demand and the rung in force are two different things.** The obvious shape is
//! one function from a snapshot to a tier, and it is wrong for a reason the pulse-wave case
//! makes measurable: such a function has no memory, so it answers the traffic and an
//! attacker with a period shorter than the response time drives it. Here the snapshot
//! produces a *demand* — a rung the current tick would justify — and [`Hysteresis`] decides
//! what is actually in force. Everything that resists oscillation lives in that gap.
//!
//! **Where the signals come from, and what is not available.** There is no total-packet
//! counter: counting every accepted packet would put a map lookup on the steady-state path,
//! which is the path the per-packet budget is stated about. So volume is read off the bank —
//! how much of it is loaded, and whether its total is rising — and the named counters supply
//! only exceptions. That shapes the ladder rather than limiting it: what distinguishes a
//! flash crowd from a flood is precisely that the exception counters stay flat while the
//! bank fills.

pub mod hysteresis;
pub mod ladder;

use lorica_common::{
    CounterId, Deadline, LpmKey, SHARE_SCALE, UNITS_PER_BYTE, V4_MAPPED_PREFIX_BITS,
};

use crate::snapshot::{NAMED_SLOTS, Snapshot};
use crate::window::{FAST_PERIOD_NS, SLOW_PERIOD_NS, Window};
use hysteresis::Hysteresis;
use ladder::{Confirmation, Decision, Reason, Tier};

/// Counters only an objectively invalid or spoofed packet increments.
///
/// The exclusions are the interesting part. `UrpfNoRoute` is out: the counter map's own
/// documentation separates it from `UrpfWrongInterface` because no route at all is what a
/// routing convergence window looks like, and confirming a refusal on it would refuse
/// legitimate traffic every time an upstream reconverges. `FragmentLaterDropped` and
/// `LpmDropHit` are out because they count refusals the policy already made, so treating
/// them as evidence would let the ladder confirm itself. `IcmpEchoDropped` and
/// `IcmpOtherDropped` likewise.
const INVALID: [CounterId; 19] = [
    CounterId::ParseTruncated,
    CounterId::ParseDepthExceeded,
    CounterId::ParseUnknownEncap,
    CounterId::SanityIpLength,
    CounterId::SanityL4Length,
    CounterId::SanityTcpFlags,
    CounterId::SanityIpOptionsRefused,
    CounterId::UrpfWrongInterface,
    CounterId::BogonRefused,
    CounterId::SignatureAmpDns,
    CounterId::SignatureAmpNtp,
    CounterId::SignatureAmpSsdp,
    CounterId::SignatureAmpMemcached,
    CounterId::SignatureAmpA2s,
    CounterId::SignatureAmpRaknet,
    CounterId::SignatureLoopyPortPair,
    CounterId::SignatureFragAbuse,
    CounterId::SignatureImpossibleTcpFlags,
    CounterId::SignatureLengthMismatch,
];

/// Everything the ladder needs that is not in a snapshot.
///
/// Every threshold here is a **parameter**, not a measurement. This tree holds per-packet
/// timings and no traffic capture, so the defaults below are stated so they can be
/// re-baselined rather than presented as findings — the doc on each says what it would be
/// re-baselined against.
pub struct Config {
    /// Ticks of the kernel's coarse clock per second, measured by the agent through
    /// `CLOCK_PROBE` because `CONFIG_HZ` has no userspace interface.
    pub hz: u32,
    /// How long a decision stands without renewal. The net, not the mechanism.
    pub ttl_secs: u64,
    /// Level above which a bucket counts as loaded, in bucket units. Parameter: 16 KiB of
    /// backlog. Would be re-baselined against the burst the bank is actually provisioned
    /// with.
    pub loaded_level_units: u64,
    /// Loaded share, in [`SHARE_SCALE`] units, at which rung 1 becomes justified.
    pub mark_share: u32,
    /// Loaded share at which rung 2 becomes justified.
    pub limit_share: u32,
    /// Over-budget packets per second, at the fast cadence, that constitute a burst.
    /// Parameter.
    pub burst_per_sec: u64,
    /// Invalid packets per second above which [`Confirmation::InvalidPacket`] is the ground
    /// rather than the weaker [`Confirmation::ExactKey`]. Parameter.
    pub invalid_per_sec: u64,
    /// Hits per second on one unified-list entry that make that key worth refusing.
    /// Parameter.
    pub entry_per_sec: u64,
    /// Consecutive slow ticks the rung below must be seen not to have reduced the offending
    /// rate before the rung above is justified. This is what makes "measured insufficient"
    /// a measurement: the rung above needs it again for as long, so rung 4 costs twice this.
    pub insufficient_ticks: u32,
    /// Consecutive slow ticks the bank total must rise before saturation is inferred.
    pub saturation_ticks: u32,
    /// Link capacity, in bits per second. Parameter, and load-bearing: the saturation signal
    /// is the bank's total *rising*, which means arrivals exceed the drain the bank was
    /// provisioned with — so this number is the offered rate exceeding the link only insofar
    /// as the bank's global rate was provisioned at the link. Provisioning it elsewhere makes
    /// rungs 5 and 6 mean something else.
    pub link_bps: u64,
    /// Prefix length rung 4 widens a confirmed key to. Parameter: a v4 /24, which is the
    /// smallest block routing policy commonly treats as one allocation.
    pub broad_prefix_len: u32,
    /// The prefix a blackhole would be asked for. `None` makes rung 6 unreachable, since the
    /// rung refuses traffic and has nothing to name.
    pub rtbh_prefix: Option<LpmKey>,
    /// Rung 6 is disableable, and off by default: a blackhole completes the attack on the
    /// announced prefix, so it is an operator's decision and not a default.
    pub rtbh_enabled: bool,
    /// Whether rung 1 can actually mark. `false` does not change which rung is reached or
    /// when — see [`Hysteresis`] — it only makes rung 1 a no-op that is counted.
    pub qdisc_available: bool,
    pub rise_ticks: u32,
    pub hold_ticks: u32,
    pub fall_ticks: u32,
    /// The profile cadence, in nanoseconds. Every counter above — `rise_ticks`,
    /// `hold_ticks`, `fall_ticks`, `insufficient_ticks`, `saturation_ticks` — counts in
    /// these, so this is the one parameter that scales the whole ladder in time rather than
    /// changing its shape.
    ///
    /// **A field rather than [`SLOW_PERIOD_NS`] directly, because it governs two different
    /// things and they have to be measurable apart.** Shortening it speeds the climb, by
    /// making every gate above shorter in wall-clock while leaving all of them the same
    /// number of ticks; and it reduces aliasing, by sampling the bank and the entry rates
    /// more often so a pulse shorter than the window is no longer averaged into it. Those
    /// are two distinct effects with two distinct costs, and a constant cannot be swept.
    pub slow_period_ns: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hz: 1000,
            ttl_secs: 600,
            loaded_level_units: 16 * 1024 * UNITS_PER_BYTE,
            mark_share: SHARE_SCALE / 20,
            limit_share: SHARE_SCALE / 4,
            burst_per_sec: 500_000,
            invalid_per_sec: 10_000,
            entry_per_sec: 1_000,
            insufficient_ticks: 3,
            saturation_ticks: 3,
            link_bps: 1_000_000_000,
            broad_prefix_len: V4_MAPPED_PREFIX_BITS + 24,
            rtbh_prefix: None,
            rtbh_enabled: false,
            qdisc_available: false,
            rise_ticks: 2,
            hold_ticks: 2,
            fall_ticks: 5,
            slow_period_ns: SLOW_PERIOD_NS,
        }
    }
}

/// What the engine did, for the operator and for the tests. Not a log: these are the numbers
/// an assertion can be written about.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub ticks: u64,
    pub slow_ticks: u64,
    /// Fast-cadence periods whose rate crossed [`Config::burst_per_sec`]. The one number
    /// that distinguishes the two cadences: a sub-second burst raises this at 100 ms and
    /// cannot raise it at 1 s.
    pub bursts: u64,
    pub transitions: u64,
    pub peak_rung: u8,
    /// Slow ticks whose demand was raised by a burst the fast cadence caught and the bank
    /// no longer showed. This is the fast cadence reaching the ladder rather than only a
    /// counter: it is zero by construction for an agent running at 1 s, whatever its
    /// thresholds.
    pub burst_driven_ticks: u64,
    /// Slow ticks spent at rung 1 with no `bpf_qdisc` to mark with. Marked in metric,
    /// not acted on — which is the point: the rung was still entered.
    pub mark_noop_ticks: u64,
    /// Times a standing decision was abandoned because its deadline passed unrenewed.
    pub expiries: u64,
    /// Slow ticks abandoned because the per-entry slice had not been re-read since the last
    /// one, so the ladder was not moved.
    ///
    /// **Zero in a healthy agent, and a number that climbs is an operator's problem and not a
    /// traffic one.** It means the counter sweep is failing or falling behind the slow cadence,
    /// and while it climbs the ladder is frozen: the standing rung stays and its deadline is
    /// the only thing that will release it. Published rather than logged because the difference
    /// between "the attack stopped" and "we stopped looking" is invisible in every other number
    /// this struct carries.
    pub unrefreshed_slow_ticks: u64,
}

pub struct Engine {
    cfg: Config,
    burst: Window,
    slow: Window,
    hyst: Hysteresis,
    prev_named: [u64; NAMED_SLOTS],
    prev_entries: Vec<u64>,
    /// The stamp the entry baseline was taken at. A snapshot carrying the same stamp has not
    /// been re-read since, so there is no delta to take and none is invented.
    prev_entries_at_ns: u64,
    prev_total_units: u64,
    /// The same, for the bank.
    prev_bank_at_ns: u64,
    primed: bool,
    rising: u32,
    /// Whether any fast period since the last slow tick was a burst. This is the only way
    /// the 100 ms cadence reaches the ladder, and it has to be a latch rather than a
    /// reading: the slow tick samples the bank at one instant, and a 300 ms burst is over by
    /// the time that instant arrives.
    burst_seen: bool,
    insufficient: u32,
    /// The over-budget rate at the moment rung 2 came into force. "Insufficient" means this
    /// rate did not come down under it, which is a measurement and not the assumption that
    /// a limiter never works.
    limit_entry_per_sec: u64,
    /// The reason of the last demand that named an exact key. A refusal that outlives its
    /// key while the ladder descends stays pinned to the key it was confirmed on; it is
    /// never re-aimed at whatever the bank happens to show now.
    keyed: Option<Reason>,
    standing: Decision,
    metrics: Metrics,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        let hyst = Hysteresis::new(cfg.rise_ticks, cfg.hold_ticks, cfg.fall_ticks);
        let slow_period_ns = cfg.slow_period_ns;
        Self {
            cfg,
            burst: Window::new(FAST_PERIOD_NS),
            slow: Window::new(slow_period_ns),
            hyst,
            prev_named: [0; NAMED_SLOTS],
            prev_entries: Vec::new(),
            prev_entries_at_ns: 0,
            prev_total_units: 0,
            prev_bank_at_ns: 0,
            primed: false,
            rising: 0,
            burst_seen: false,
            insufficient: 0,
            limit_entry_per_sec: 0,
            keyed: None,
            standing: Decision::quiet(),
            metrics: Metrics::default(),
        }
    }

    /// Feeds one snapshot and answers the decision now standing.
    ///
    /// Called at the fast cadence. The burst window closes on every call; the slow window
    /// closes on one call in ten, and that is where the ladder moves.
    pub fn observe(&mut self, s: &Snapshot) -> Decision {
        self.metrics.ticks += 1;
        let over_total = s.counters.get(CounterId::BucketOverBudget);

        // The first snapshot is the baseline every later delta is taken against. A live
        // agent attaches to maps that already hold counts, so starting the previous read at
        // zero would report the whole history of the machine as one tick's worth of traffic.
        if !self.primed {
            self.primed = true;
            self.prev_named = *s.counters.named();
            self.prev_entries.clear();
            self.prev_entries
                .extend(s.counters.entries().iter().map(|e| e.hits));
            self.prev_entries_at_ns = s.counters.entries_at_ns();
            self.prev_total_units = s.buckets.total_units();
            self.prev_bank_at_ns = s.buckets.at_ns();
        }

        if let Some(per_sec) = self.burst.observe(s.at_ns, over_total)
            && per_sec >= self.cfg.burst_per_sec
        {
            self.metrics.bursts += 1;
            self.burst_seen = true;
        }

        // The net, applied before any arithmetic: an unrenewed decision is abandoned rather
        // than reconsidered, because the reason it went unrenewed is that the ticks that
        // would reconsider it stopped arriving.
        if self.standing.tier() != Tier::Observe
            && self.standing.deadline().expired(s.jiffies(self.cfg.hz))
        {
            self.hyst.expire();
            self.keyed = None;
            self.standing = Decision::quiet();
            self.metrics.expiries += 1;
            self.metrics.transitions += 1;
        }

        if self.slow.observe(s.at_ns, over_total).is_some() {
            self.slow_tick(s);
        }
        self.standing
    }

    pub fn current(&self) -> Tier {
        self.hyst.current()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    fn slow_tick(&mut self, s: &Snapshot) {
        self.metrics.slow_ticks += 1;

        // **A slow tick whose evidence was not refreshed does not move the ladder.**
        //
        // The per-entry slice is swept on a slower cadence than this tick and the sweep can
        // fail. When it has not been re-read, `hottest_entry` correctly declines to invent a
        // delta — but the demand computed without it is *lower*, and a lower demand held for
        // `fall_ticks` walks the ladder back down. An agent that stopped reading its maps would
        // therefore talk itself out of a mitigation while the attack it was mitigating carried
        // on, which is the single worst misreading this system can make.
        //
        // So the tick is counted and abandoned. The rung stays exactly where the last real
        // reading left it, and the net under all of it is unchanged: the standing decision
        // still carries a `Deadline`, and `observe` expires it whether or not slow ticks are
        // still doing anything. A sweep that never comes back releases the mitigation on that
        // timer, which is the mechanism that exists for precisely this case.
        //
        // The stamp gates on the *confirmed* side and not the bank, because that is the side
        // whose absence lowers a demand into and out of refusal. It also moves whenever the
        // sweep succeeded, whatever the policy holds, so an agent with no entries at all still
        // ticks normally.
        if s.counters.entries_at_ns() <= self.prev_entries_at_ns {
            self.metrics.unrefreshed_slow_ticks += 1;
            return;
        }

        let dt_ns = self.slow.dt_ns().max(1);
        let over = self.slow.per_sec();
        let share = s.buckets.loaded_share(self.cfg.loaded_level_units);
        let invalid = self.invalid(s, dt_ns);
        let hottest = self.hottest_entry(s);
        let excess_bps = self.excess_bps(s);

        if self.burst_seen && share < self.cfg.mark_share {
            self.metrics.burst_driven_ticks += 1;
        }

        let before = self.hyst.current();
        self.track_insufficiency(before, over);
        self.rising = if excess_bps > 0 { self.rising + 1 } else { 0 };

        let (demand, demand_reason) =
            self.demand(before, share, over, invalid, hottest, excess_bps);
        if demand_reason.exact_key().is_some() {
            self.keyed = Some(demand_reason);
        }

        let in_force = self.hyst.step(demand);
        if in_force != before {
            self.metrics.transitions += 1;
        }
        self.metrics.peak_rung = self.metrics.peak_rung.max(in_force.rung());
        if in_force == Tier::Mark && !self.cfg.qdisc_available {
            self.metrics.mark_noop_ticks += 1;
        }
        if !in_force.drops() {
            self.keyed = None;
        }

        let reason = self.reason_for(in_force, demand, demand_reason, share, over, excess_bps);
        let deadline = if in_force == Tier::Observe {
            Deadline::never()
        } else {
            Deadline::after(
                s.jiffies(self.cfg.hz),
                self.cfg.ttl_secs.saturating_mul(u64::from(self.cfg.hz)),
            )
        };

        // A refusal this engine cannot justify is not applied. `Decision::new` answering
        // `None` means the rung in force lost the key it was confirmed on, and falling to
        // rung 0 is the safe direction of being wrong.
        self.standing = Decision::new(in_force, reason, deadline).unwrap_or_else(Decision::quiet);
        self.burst_seen = false;
    }

    /// The rung this tick alone would justify, and why.
    #[allow(clippy::too_many_arguments)]
    fn demand(
        &self,
        before: Tier,
        share: u32,
        over: u64,
        invalid: Option<(CounterId, u64)>,
        hottest: Option<(LpmKey, u64)>,
        excess_bps: u64,
    ) -> (Tier, Reason) {
        let mut out = (Tier::Observe, Reason::Quiet);

        // Not `over > 0`. A steady state has buckets going over budget — that is what a
        // shaper looks like working — so a demand armed by a single over-budget packet never
        // disarms, and the descent below can then never reach rung 0. The signals are a
        // loaded share of the bank, or a burst the fast cadence caught between two slow
        // ticks.
        if share >= self.cfg.mark_share || self.burst_seen {
            out = (
                Tier::Mark,
                Reason::Pressure {
                    counter: CounterId::BucketMarked,
                    per_sec: over,
                    loaded_share: share,
                },
            );
        }
        if share >= self.cfg.limit_share {
            out = (
                Tier::Limit,
                Reason::Pressure {
                    counter: CounterId::BucketOverBudget,
                    per_sec: over,
                    loaded_share: share,
                },
            );
        }

        // Rungs 3 and 4 need three things at once: a key, a rate on that key, and the rung
        // below measured insufficient. Any two of them are not enough, which is the whole
        // difference between this and a threshold.
        let confirmable = hottest.filter(|(_, per_sec)| {
            *per_sec >= self.cfg.entry_per_sec && self.insufficient >= self.cfg.insufficient_ticks
        });
        if let Some((key, per_sec)) = confirmable {
            let by = match invalid {
                Some((id, rate)) if rate >= self.cfg.invalid_per_sec => {
                    Confirmation::InvalidPacket(id)
                }
                _ => Confirmation::ExactKey,
            };
            out = (Tier::DropSurgical, Reason::Confirmed { key, by, per_sec });

            if before >= Tier::DropSurgical
                && self.insufficient >= self.cfg.insufficient_ticks.saturating_mul(2)
            {
                out = (
                    Tier::DropBroad,
                    Reason::Confirmed {
                        key: widen(key, self.cfg.broad_prefix_len),
                        by,
                        per_sec,
                    },
                );
            }
        }

        // Rungs 5 and 6 are about the link and not about a source, so they override: no
        // amount of surgical refusal helps once arrivals exceed what the link can pass.
        if self.rising >= self.cfg.saturation_ticks {
            out = (
                Tier::Escalate,
                Reason::Saturation {
                    excess_bps,
                    link_bps: self.cfg.link_bps,
                    announce: None,
                },
            );
            let blackholeable = self.cfg.rtbh_prefix.filter(|_| {
                self.cfg.rtbh_enabled
                    && before >= Tier::Escalate
                    && self.rising >= self.cfg.saturation_ticks.saturating_mul(2)
            });
            if let Some(announce) = blackholeable {
                out = (
                    Tier::Rtbh,
                    Reason::Saturation {
                        excess_bps,
                        link_bps: self.cfg.link_bps,
                        announce: Some(announce),
                    },
                );
            }
        }

        out
    }

    /// The reason to publish for the rung actually in force, which is not always the rung
    /// demanded: the ladder is walked one rung at a time, so a tick can be in force at a
    /// rung this tick's signals did not ask for.
    #[allow(clippy::too_many_arguments)]
    fn reason_for(
        &self,
        in_force: Tier,
        demand: Tier,
        demand_reason: Reason,
        share: u32,
        over: u64,
        excess_bps: u64,
    ) -> Reason {
        if in_force == demand {
            return demand_reason;
        }
        match in_force {
            Tier::Observe => Reason::Quiet,
            Tier::Escalate | Tier::Rtbh => Reason::Saturation {
                excess_bps,
                link_bps: self.cfg.link_bps,
                announce: if in_force == Tier::Rtbh {
                    self.cfg.rtbh_prefix
                } else {
                    None
                },
            },
            Tier::DropSurgical | Tier::DropBroad => self.keyed.unwrap_or(Reason::Quiet),
            Tier::Mark | Tier::Limit => Reason::Pressure {
                counter: CounterId::BucketOverBudget,
                per_sec: over,
                loaded_share: share,
            },
        }
    }

    /// Whether the rung below reduced the offending rate, counted in consecutive slow ticks.
    fn track_insufficiency(&mut self, in_force: Tier, over: u64) {
        if in_force < Tier::Limit {
            self.insufficient = 0;
            self.limit_entry_per_sec = 0;
            return;
        }
        if self.limit_entry_per_sec == 0 {
            self.limit_entry_per_sec = over;
        }
        if over >= self.limit_entry_per_sec {
            self.insufficient += 1;
        } else {
            self.insufficient = 0;
        }
    }

    /// The fastest-rising invalid-packet counter and the group's total rate.
    ///
    /// The single counter is what [`Confirmation::InvalidPacket`] names, so an operator
    /// reading the decision sees which signature or which sanity check grounded it rather
    /// than that some check did.
    fn invalid(&mut self, s: &Snapshot, dt_ns: u64) -> Option<(CounterId, u64)> {
        let named = s.counters.named();
        let mut worst = None;
        let mut total = 0u64;
        for id in INVALID {
            let i = id.index() as usize;
            let delta = named[i].saturating_sub(self.prev_named[i]);
            total = total.saturating_add(delta);
            if delta > worst.map_or(0, |(_, d)| d) {
                worst = Some((id, delta));
            }
        }
        self.prev_named = *named;
        let per_sec = total.saturating_mul(1_000_000_000) / dt_ns;
        worst.map(|(id, _)| (id, per_sec))
    }

    /// The unified-list entry taking hits fastest.
    ///
    /// Matched positionally against the previous read. The slot order is the counter index
    /// order the policy compiler allocated, so it is stable for as long as the policy is;
    /// a change of length is a recompiled policy, and the deltas across it would be
    /// meaningless, so the history is dropped rather than reinterpreted.
    ///
    /// **Two refusals rather than one, and the second is the one that matters.** A change of
    /// length drops the history, as it always did. A slice whose stamp has not moved since the
    /// last delta is *not looked at* — the sweep is slower than this tick and it can fail — and
    /// the difference between "unchanged" and "not looked at" is the difference between an
    /// attack that stopped and an agent that stopped watching. Answering zero for the second
    /// would let a saturated agent talk itself down the ladder, so it answers nothing and
    /// leaves the baseline alone.
    ///
    /// `dt_ns` is the caller's tick interval and is deliberately not used: the rate is divided
    /// by the interval the two readings actually span, which is longer whenever a sweep was
    /// skipped or failed. Dividing a two-interval delta by one interval would double the rate
    /// an attacker appears to have, in the direction that confirms.
    fn hottest_entry(&mut self, s: &Snapshot) -> Option<(LpmKey, u64)> {
        let entries = s.counters.entries();
        let at_ns = s.counters.entries_at_ns();
        if entries.len() != self.prev_entries.len() {
            self.prev_entries.clear();
            self.prev_entries.extend(entries.iter().map(|e| e.hits));
            self.prev_entries_at_ns = at_ns;
            return None;
        }
        let span_ns = at_ns.saturating_sub(self.prev_entries_at_ns);
        if span_ns == 0 {
            return None;
        }
        let mut best: Option<(LpmKey, u64)> = None;
        for (e, prev) in entries.iter().zip(self.prev_entries.iter_mut()) {
            let delta = e.hits.saturating_sub(*prev);
            *prev = e.hits;
            if delta > best.map_or(0, |(_, d)| d) {
                best = Some((e.key, delta));
            }
        }
        self.prev_entries_at_ns = at_ns;
        best.map(|(key, delta)| (key, delta.saturating_mul(1_000_000_000) / span_ns))
    }

    /// Bits per second by which arrivals exceeded the bank's provisioned drain.
    ///
    /// The bank never resets and a bucket that stops receiving drains to zero, so the total
    /// rises only while arrivals outrun the drain — which is why the *rise* is a rate and
    /// the total is not. The level is in units of `1 / UNITS_PER_BYTE` byte, never in bytes,
    /// so the conversion is here and not at the call site.
    /// Zero when the bank has not been re-read since the last call, for the reason
    /// [`Self::hottest_entry`] gives: the bank is swept slower than this tick and a reading
    /// that did not happen is not a reading of zero. Zero here is the safe direction — it
    /// drives `rising` back to nothing and demands no rung — but it is returned because the
    /// bank was not looked at, and the baseline is left where it was so the next real reading
    /// spans the whole interval.
    fn excess_bps(&mut self, s: &Snapshot) -> u64 {
        let at_ns = s.buckets.at_ns();
        let span_ns = at_ns.saturating_sub(self.prev_bank_at_ns);
        if span_ns == 0 {
            return 0;
        }
        let total = s.buckets.total_units();
        let rise = total.saturating_sub(self.prev_total_units);
        self.prev_total_units = total;
        self.prev_bank_at_ns = at_ns;
        (rise / UNITS_PER_BYTE)
            .saturating_mul(8)
            .saturating_mul(1_000_000_000)
            / span_ns
    }
}

/// A confirmed key widened to `prefix_len`, host bits zeroed.
///
/// Never widened past the key's own prefix length: widening is how rung 4 covers a source
/// that moves within an allocation, and a `prefix_len` longer than the key would narrow it
/// instead, which would silently refuse nothing.
fn widen(key: LpmKey, prefix_len: u32) -> LpmKey {
    let prefix_len = prefix_len.min(key.prefix_len);
    let whole = (prefix_len / 8) as usize;
    let mut addr = [0u8; 16];
    addr[..whole].copy_from_slice(&key.addr[..whole]);
    let rest = prefix_len % 8;
    if whole < addr.len() && rest != 0 {
        addr[whole] = key.addr[whole] & (0xffu8 << (8 - rest));
    }
    LpmKey { prefix_len, addr }
}
