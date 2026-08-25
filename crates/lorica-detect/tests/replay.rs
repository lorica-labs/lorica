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
//! deliberately loose — see [`TRANSITION_CEILING`].

use std::collections::BTreeMap;

use lorica_common::{CounterId, DEFAULT_BANK_BUCKETS, LpmKey, UNITS_PER_BYTE};
use lorica_detect::snapshot::NAMED_SLOTS;
use lorica_detect::{BucketView, Config, CounterView, Engine, EntryCounter, Snapshot, Tier};
use serde::Deserialize;

/// Ceiling on the number of rung changes a replay may produce.
///
/// **Provisional.** A number picked to make the test that was just written go green proves
/// nothing, so this one is set far above every value observed so far and the definitive
/// figure will be re-baselined from the `LORICA_TRANSITIONS` lines once the fixtures are
/// backed by captures. What the assertion buys today is a bound that a genuinely
/// oscillating ladder — one transition every slow tick, hundreds of them — fails.
const TRANSITION_CEILING: u64 = 12;

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

            out.push(Snapshot {
                seq: out.len() as u64,
                at_ns: out.len() as u64 * period_ns,
                counters: CounterView::new(named, entries),
                buckets: BucketView::new(levels),
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
        if decision.tier.drops() {
            drops += 1;
            assert!(
                decision.reason.exact_key().is_some(),
                "{}: rung {:?} refuses packets without naming an exact key",
                f.name,
                decision.tier
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
    assert!(run.transitions <= TRANSITION_CEILING);
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
        run.transitions <= TRANSITION_CEILING,
        "{} rung changes over {} ticks: the ladder is following the pulse instead of \
         resisting it",
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
    assert!(run.transitions <= TRANSITION_CEILING);
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
