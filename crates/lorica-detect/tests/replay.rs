//! Replay of recorded snapshot sequences through the decision engine.
//!
//! The fixtures are read here and never by the crate: `lorica-detect` performs no I/O and
//! takes no serialization dependency, so the JSON shapes below are the test's own mirror of
//! the snapshot types rather than derives on them.
//!
//! Every case prints one machine-readable line per replay:
//!
//! ```text
//! LORICA_TRANSITIONS fixture=<name> cadence_ms=<100|1000> ticks=<n> transitions=<n> peak_tier=<n> final_tier=<n>
//! ```
//!
//! That line is the point of the non-oscillation case. The ceiling asserted against it is
//! per fixture — see [`transition_ceiling`].

use std::collections::BTreeMap;

use lorica_common::{CounterId, DEFAULT_BANK_BUCKETS, LpmKey, UNITS_PER_BYTE};
use lorica_detect::snapshot::NAMED_SLOTS;
use lorica_detect::{BucketView, Config, CounterView, Engine, EntryCounter, Snapshot, Tier};
use serde::Deserialize;

/// Ceiling on the number of rung changes each replay may produce, one per fixture.
///
/// **Re-baselined from the `LORICA_TRANSITIONS` lines, per fixture rather than globally.** A
/// single loose bound across four fixtures is only as tight as the fixture that legitimately
/// moves most: `attack_end` climbs four rungs and comes back down, so one shared ceiling that
/// admits its eight admits four times what `pulse_wave` should ever produce, and `pulse_wave`
/// is the fixture the non-oscillation criterion is about.
///
/// The margin is not absorbing variance — a replay is deterministic and these counts are a
/// pure function of the fixture and the [`Config`]. It absorbs re-tuning the ladder's timing
/// constants, which are parameters and will move. Measured, then rounded up:
///
/// | fixture | measured | ceiling |
/// |---|---:|---:|
/// | `flash_crowd` | 2 | 4 |
/// | `pulse_wave` | 3 | 6 |
/// | `attack_end` | 8 | 10 |
/// | `sub_second_burst` | 1 | 2 |
///
/// **Re-measured after the ladder was retuned**, which is the case the margin was reserved for:
/// `rise_ticks` went to one and the profile cadence to 500 ms, so the ladder now takes a rung on
/// a single slow tick of demand and takes it twice as often in wall-clock. `pulse_wave` moved
/// from 2 changes to 3 and, more to the point, from peak rung 2 to peak rung 3 — it now reaches
/// `DropSurgical` on a fixture that carries real invalid packets and a hot entry, which is the
/// gain the retune was for and not a regression. `sub_second_burst` moved from 0 to 1 at the
/// fast cadence for the same reason. Neither exceeded its old ceiling; `pulse_wave`'s is doubled
/// from its new measurement rather than left at 4, so the next parameter change is not a build
/// break at one transition of drift.
///
/// `tests` proves it discriminates: with `hold_ticks` and `fall_ticks` cut to let the ladder
/// chase every slow tick, `pulse_wave` produces 20 transitions against this 4. The previous
/// shared ceiling of 12 had never seen an oscillation — the one break that had been run
/// against it tripped the peak-rung assertion first, so the transition bound itself was
/// unproven.
fn transition_ceiling(fixture: &str) -> u64 {
    match fixture {
        "flash_crowd" => 4,
        "pulse_wave" => 6,
        "attack_end" => 10,
        "sub_second_burst" => 2,
        other => panic!("no re-baselined transition ceiling for fixture {other}"),
    }
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    #[allow(dead_code)]
    about: String,
    #[allow(dead_code)]
    magnitudes: String,
    period_ms: u64,
    #[serde(default)]
    entry_v4: Option<[u8; 4]>,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    repeat: u64,
    #[allow(dead_code)]
    note: String,
    #[serde(default)]
    loaded_buckets: u32,
    #[serde(default)]
    level_kib: u64,
    #[serde(default)]
    entry_per_sec: u64,
    /// Counter increments, in units per second, keyed by [`CounterId::name`]. Per second
    /// and not per period so a fixture reads the way an operator states a rate, and looked
    /// up by name so a renamed variant fails the test instead of silently counting nothing.
    #[serde(default)]
    counters: BTreeMap<String, u64>,
}

fn fixture(name: &str) -> Fixture {
    let path = format!(
        "{}/tests/fixtures/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The fixture expanded into the cumulative totals a batch map read would have returned.
///
/// Counters accumulate, because the maps do: the engine is handed totals and derives every
/// rate itself, which is the only way a replay exercises the same arithmetic the tick does.
fn snapshots(f: &Fixture) -> Vec<Snapshot> {
    let period_ns = f.period_ms * 1_000_000;
    let mut named = [0u64; NAMED_SLOTS];
    let mut entry_hits = 0u64;
    let mut out = Vec::new();

    for step in &f.steps {
        for _ in 0..step.repeat {
            for (name, per_sec) in &step.counters {
                let id = CounterId::from_name(name)
                    .unwrap_or_else(|| panic!("{}: no counter named {name}", f.name));
                named[id.index() as usize] += per_sec * f.period_ms / 1000;
            }
            entry_hits += step.entry_per_sec * f.period_ms / 1000;

            let entries = match f.entry_v4 {
                Some(addr) => vec![EntryCounter {
                    key: LpmKey::host_v4(addr),
                    hits: entry_hits,
                }],
                None => Vec::new(),
            };

            let mut levels = vec![0u64; DEFAULT_BANK_BUCKETS as usize];
            let level = step.level_kib * 1024 * UNITS_PER_BYTE;
            for slot in levels.iter_mut().take(step.loaded_buckets as usize) {
                *slot = level;
            }

            // **Both slices are stamped, and a fixture that forgot to would be a fixture that
            // tests nothing.** The engine refuses to take a delta across a slice whose stamp
            // has not moved, because in a live agent that means the sweep did not happen. A
            // replay that left the stamps at zero would therefore exercise the refusal on
            // every tick and pass every assertion by never demanding a rung. This fixture
            // models an agent whose sweeps all succeeded; `a_sweep_that_did_not_happen`
            // models the other case on purpose.
            let at_ns = out.len() as u64 * period_ns;
            let mut counters = CounterView::new(named, entries);
            counters.set_entries_at_ns(at_ns);
            let mut buckets = BucketView::new(levels);
            buckets.set_at_ns(at_ns);

            out.push(Snapshot {
                seq: out.len() as u64,
                at_ns,
                counters,
                buckets,
            });
        }
    }
    out
}

struct Run {
    ticks: u64,
    transitions: u64,
    peak_tier: u8,
    final_tier: u8,
    bursts: u64,
    burst_driven: u64,
    mark_noop: u64,
    drops: u64,
}

/// Replays a fixture, keeping every `stride`-th snapshot.
///
/// `stride` is how the two cadences are compared without a second fixture: at 1 the engine
/// is fed every 100 ms period, at 10 it is fed one snapshot per second, which is literally
/// what an agent reading the maps once a second would have seen.
fn replay(f: &Fixture, cfg: Config, stride: usize) -> Run {
    let snaps = snapshots(f);
    let mut engine = Engine::new(cfg);
    let mut ticks = 0;
    let mut drops = 0;

    for snap in snaps.iter().step_by(stride) {
        let decision = engine.observe(snap);
        ticks += 1;
        if decision.tier().drops() {
            drops += 1;
            assert!(
                decision.reason().exact_key().is_some(),
                "{}: rung {:?} refuses packets without naming an exact key",
                f.name,
                decision.tier()
            );
        }
    }

    let m = engine.metrics();
    let run = Run {
        ticks,
        transitions: m.transitions,
        peak_tier: m.peak_rung,
        final_tier: engine.current().rung(),
        bursts: m.bursts,
        burst_driven: m.burst_driven_ticks,
        mark_noop: m.mark_noop_ticks,
        drops,
    };
    println!(
        "LORICA_TRANSITIONS fixture={} cadence_ms={} ticks={} transitions={} peak_tier={} final_tier={}",
        f.name,
        f.period_ms * stride as u64,
        run.ticks,
        run.transitions,
        run.peak_tier,
        run.final_tier,
    );
    run
}

#[test]
fn flash_crowd() {
    let f = fixture("flash_crowd");
    let run = replay(&f, Config::default(), 1);

    assert_eq!(run.drops, 0, "a legitimate rush was met with a drop");
    assert!(
        run.peak_tier <= Tier::Limit.rung(),
        "peak rung {} is above Limit on traffic that carries no invalid packet and no \
         confirmed key",
        run.peak_tier
    );
    assert!(run.transitions <= transition_ceiling(&f.name));
}

/// Rungs 0 to 2 chain on the same timing whether or not `bpf_qdisc` exists. Without it rung
/// 1 marks nothing and says so in a metric; it is not skipped, because skipping it would
/// make the same traffic reach a different rung on two hosts at the same instant.
#[test]
fn the_kernel_does_not_change_the_verdict() {
    let f = fixture("flash_crowd");

    let without = replay(&f, Config::default(), 1);
    let with = replay(
        &f,
        Config {
            qdisc_available: true,
            ..Config::default()
        },
        1,
    );

    assert_eq!(without.transitions, with.transitions);
    assert_eq!(without.peak_tier, with.peak_tier);
    assert_eq!(without.final_tier, with.final_tier);
    assert!(
        without.mark_noop > 0 && with.mark_noop == 0,
        "rung 1 was {} no-op ticks without a qdisc and {} with one",
        without.mark_noop,
        with.mark_noop
    );
}

#[test]
fn sub_second_burst() {
    let f = fixture("sub_second_burst");

    let fast = replay(&f, Config::default(), 1);
    let slow = replay(&f, Config::default(), 10);

    assert!(
        fast.bursts > 0,
        "the 100 ms cadence missed a 300 ms burst, which is the one thing it exists for"
    );
    assert_eq!(
        slow.bursts, 0,
        "the 1 s cadence reported a burst it cannot resolve; the fixture no longer \
         demonstrates the aliasing it was built for"
    );

    // Not only the metric: the burst has to reach the demand the ladder is driven by, or
    // the fast cadence is measuring something nothing acts on. The rung itself is not
    // asserted, and deliberately: one 300 ms burst is a single slow tick's demand, which is
    // under `rise_ticks`, so the ladder correctly refuses to move for it. Seen is not the
    // same as acted on, and this fixture is about seen.
    assert!(fast.burst_driven > 0);
    assert_eq!(slow.burst_driven, 0);
    assert_eq!(fast.drops, 0, "one burst is not a confirmed key");
}

#[test]
fn pulse_wave() {
    let f = fixture("pulse_wave");
    let run = replay(&f, Config::default(), 1);

    assert!(
        run.transitions <= transition_ceiling(&f.name),
        "{} rung changes over {} ticks: the ladder is following the pulse instead of \
         resisting it",
        run.transitions,
        run.ticks
    );
}

/// The transition ceiling, shown catching what it exists to catch.
///
/// A bound nothing has ever exceeded is not a bound. The break is the smallest one that
/// produces an oscillation rather than a wrong verdict: hysteresis reduced to nothing, so the
/// ladder re-decides from scratch on every slow tick and follows the pulse instead of
/// resisting it. Every other assertion in `pulse_wave` still passes under this break — no
/// drop, no rung above Limit — which is exactly why the transition count has to be asserted
/// separately.
#[test]
fn a_ladder_without_hysteresis_blows_the_ceiling() {
    let f = fixture("pulse_wave");
    let cfg = Config {
        rise_ticks: 1,
        hold_ticks: 0,
        fall_ticks: 1,
        ..Config::default()
    };
    let run = replay(&f, cfg, 1);

    assert!(
        run.transitions > transition_ceiling(&f.name),
        "the ladder was stripped of its hysteresis and still made only {} rung changes over          {} ticks: either the fixture no longer pulses or the ceiling is measuring nothing",
        run.transitions,
        run.ticks
    );
}

#[test]
fn attack_end() {
    let f = fixture("attack_end");
    let run = replay(&f, Config::default(), 1);

    assert!(
        run.peak_tier > Tier::Observe.rung(),
        "the fixture never climbed, so its descent proves nothing"
    );
    assert_eq!(
        run.final_tier,
        Tier::Observe.rung(),
        "the flood stopped and the ladder stayed at rung {}",
        run.final_tier
    );
    assert!(run.transitions <= transition_ceiling(&f.name));
}

/// The invariant, asserted directly rather than only through the fixtures: there is no way
/// to spell a decision that refuses packets on the strength of a bucket.
#[test]
fn a_drop_without_a_key_is_not_representable() {
    use lorica_common::Deadline;
    use lorica_detect::Reason;

    for tier in [
        Tier::Observe,
        Tier::Mark,
        Tier::Limit,
        Tier::DropSurgical,
        Tier::DropBroad,
        Tier::Escalate,
        Tier::Rtbh,
    ] {
        let unkeyed = lorica_detect::Decision::new(
            tier,
            Reason::Pressure {
                counter: CounterId::BucketOverBudget,
                per_sec: u64::MAX,
                loaded_share: u32::MAX,
            },
            Deadline::never(),
        );
        assert_eq!(
            unkeyed.is_none(),
            tier.drops(),
            "{tier:?}: keyless decision accepted for a dropping rung, or refused for a \
             rung that does not drop"
        );
    }
}
