//! A deterministic replayer for pulsed attacks, and the seven numbers it scores the ladder on.
//!
//! `lorica-detect` reads no map and no clock — it is told the time — so a timestamped sequence
//! of snapshots built in memory exercises exactly the arithmetic a live agent runs. That is the
//! whole reason this is possible without a bench: same input, same output, to the byte, on any
//! machine, with no network, no kernel and no wall clock anywhere in the loop.
//!
//! **What this is not.** It does not simulate the data path. It replays a scenario's declared
//! ground truth past the engine and scores the *timeline of rungs* the engine produced against
//! what the scenario says was happening. "Legitimate packets refused" is therefore a number
//! about the ladder's timing, computed from a rate the scenario declares, and not a packet
//! anything dropped. Saying so is the difference between a metric and a claim.
//!
//! **Why it is separate from `replay.rs`.** That file asserts; this one measures. It writes
//! `LORICA_PULSE` lines and a CSV, and its assertions are deliberately few — the flash crowd,
//! which is the false-positive test, and the ones each scenario states about itself. The rest
//! is for reading, because the point of a campaign is to find out what the current tuning does
//! and not to enshrine it.
//!
//! ## The scenario format, version 1
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "pulse_50ms",
//!   "about": "prose, for the reader",
//!   "period_ms": 100,
//!   "entry_v4": [203, 0, 113, 7],
//!   "timeline": [
//!     { "repeat": 20, "note": "quiet", "legit_pps": 20000 },
//!     { "cycles": 5, "phases": [ { "repeat": 1, "note": "pulse", "attack_pps": 800000 } ] }
//!   ]
//! }
//! ```
//!
//! A timeline entry is either a phase or a group of phases repeated `cycles` times. The group
//! exists because six scenarios of five pulses each would otherwise be a thousand lines of
//! copied JSON, and a fixture nobody can read is a fixture nobody checks.
//!
//! `version` is refused if it is not 1. A scenario written against a later shape and replayed
//! by this harness would be scored under rules it was not written for, and the failure would
//! be a plausible number rather than an error.
//!
//! ## Ground truth
//!
//! `legit_pps` and `attack_pps` are what the scenario declares was on the wire. They are what
//! the over- and under-mitigation columns are computed from, and they are deliberately separate
//! from `entry_per_sec` and the counter rates, which are what the *engine* sees. A scenario can
//! therefore describe an attacker the engine has no evidence for, which is the interesting case.

use std::collections::BTreeMap;

use lorica_common::{CounterId, DEFAULT_BANK_BUCKETS, LpmKey, UNITS_PER_BYTE};
use lorica_detect::{
    BucketView, Config, CounterView, Engine, EntryCounter, Snapshot, Tier, snapshot::NAMED_SLOTS,
};
use serde::Deserialize;

/// The one version this harness scores. See the module header.
const FORMAT_VERSION: u32 = 1;

const SCENARIOS: [&str; 6] = [
    "pulse_widths",
    "pulse_gaps",
    "rotating_vector",
    "flash_crowd_legit",
    "mixed_vectors",
    "renewed_sources",
];

#[derive(Deserialize)]
struct Scenario {
    version: u32,
    name: String,
    #[allow(dead_code)]
    about: String,
    period_ms: u64,
    #[serde(default)]
    entry_v4: Option<[u8; 4]>,
    timeline: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Entry {
    Group { cycles: u32, phases: Vec<Phase> },
    One(Phase),
}

#[derive(Deserialize, Clone)]
struct Phase {
    repeat: u64,
    #[allow(dead_code)]
    note: String,
    /// Ground truth: what the scenario says was legitimate traffic, in packets per second.
    #[serde(default)]
    legit_pps: u64,
    /// Ground truth: what the scenario says was attack traffic.
    #[serde(default)]
    attack_pps: u64,
    /// Whether the entry the engine can confirm is the attacker or a legitimate source.
    ///
    /// The flash crowd sets this false while the counters still move: that is the shape of a
    /// false positive, and without the field the harness could not tell a correct refusal from
    /// an incorrect one.
    #[serde(default = "yes")]
    entry_is_attacker: bool,
    #[serde(default)]
    loaded_buckets: u32,
    #[serde(default)]
    level_kib: u64,
    #[serde(default)]
    entry_per_sec: u64,
    /// Counter increments in units per second, by [`CounterId::name`]. Looked up by name so a
    /// renamed variant fails the run instead of silently counting nothing.
    #[serde(default)]
    counters: BTreeMap<String, u64>,
}

const fn yes() -> bool {
    true
}

/// One tick: the snapshot the engine sees, and what the scenario says was really happening.
struct Step {
    snapshot: Snapshot,
    legit_pps: u64,
    attack_pps: u64,
    entry_is_attacker: bool,
}

fn scenario(name: &str) -> Scenario {
    let path = format!(
        "{}/tests/scenarios/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let s: Scenario = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert_eq!(
        s.version, FORMAT_VERSION,
        "{path} is written for scenario format {} and this harness scores format \
         {FORMAT_VERSION}: it would be measured under rules it was not written for",
        s.version
    );
    assert_eq!(s.name, name, "{path} names itself {} ", s.name);
    s
}

/// Flattens the timeline and expands it into the cumulative totals a map read would return.
///
/// Counters accumulate because the maps do: the engine is handed totals and derives every rate
/// itself, which is the only way a replay exercises the arithmetic the tick runs.
fn steps(s: &Scenario) -> Vec<Step> {
    let period_ns = s.period_ms * 1_000_000;
    let mut named = [0u64; NAMED_SLOTS];
    let mut entry_hits = 0u64;
    let mut out: Vec<Step> = Vec::new();

    let mut flat: Vec<Phase> = Vec::new();
    for entry in &s.timeline {
        match entry {
            Entry::One(phase) => flat.push(phase.clone()),
            Entry::Group { cycles, phases } => {
                for _ in 0..*cycles {
                    flat.extend(phases.iter().cloned());
                }
            }
        }
    }

    for phase in &flat {
        for _ in 0..phase.repeat {
            for (name, per_sec) in &phase.counters {
                let id = CounterId::from_name(name)
                    .unwrap_or_else(|| panic!("{}: no counter named {name}", s.name));
                named[id.index() as usize] += per_sec * s.period_ms / 1000;
            }
            entry_hits += phase.entry_per_sec * s.period_ms / 1000;

            let at_ns = out.len() as u64 * period_ns;
            let entries = match s.entry_v4 {
                Some(addr) => vec![EntryCounter {
                    key: LpmKey::host_v4(addr),
                    hits: entry_hits,
                }],
                None => Vec::new(),
            };
            let mut counters = CounterView::new(named, entries);
            // Every sweep succeeds in these scenarios. The case where one does not is
            // `starved_no_more.rs`, which is about the engine refusing to move rather than
            // about what a pulse does to it.
            counters.set_entries_at_ns(at_ns);

            let mut levels = vec![0u64; DEFAULT_BANK_BUCKETS as usize];
            let level = phase.level_kib * 1024 * UNITS_PER_BYTE;
            for slot in levels.iter_mut().take(phase.loaded_buckets as usize) {
                *slot = level;
            }
            let mut buckets = BucketView::new(levels);
            buckets.set_at_ns(at_ns);

            out.push(Step {
                snapshot: Snapshot {
                    seq: out.len() as u64,
                    at_ns,
                    counters,
                    buckets,
                },
                legit_pps: phase.legit_pps,
                attack_pps: phase.attack_pps,
                entry_is_attacker: phase.entry_is_attacker,
            });
        }
    }
    out
}

/// The seven numbers, plus what they were computed over.
#[derive(Default)]
struct Score {
    ticks: u64,
    /// Ticks from the first attack tick to the first tick a refusing rung was in force.
    /// `None` when the ladder never refused while the attack ran.
    detect_ticks: Option<u64>,
    peak_rung: u8,
    /// Rung changes that reversed direction. A climb followed by a climb is the ladder
    /// working; a climb followed by a descent followed by a climb is it hunting, and only the
    /// second is what a mis-tuned hysteresis produces.
    reversals: u64,
    transitions: u64,
    /// Pulses during which no refusing rung was ever in force.
    missed_pulses: u64,
    pulses: u64,
    /// Ticks a refusing rung stayed in force after the last attack tick.
    hold_ticks: u64,
    /// Legitimate packets refused: the scenario's legitimate rate, over the ticks a refusing
    /// rung was in force while the confirmable entry was **not** the attacker.
    legit_refused: u64,
    /// Attack packets that passed because no refusing rung was in force.
    under_mitigated: u64,
    /// Legitimate packets refused, which is the same quantity as `legit_refused` and is
    /// reported under both names because an operator asks the two questions differently.
    over_mitigated: u64,
}

fn score(name: &str, cfg: Config) -> Score {
    let sc = scenario(name);
    let steps = steps(&sc);
    let mut engine = Engine::new(cfg);
    let period_ms = sc.period_ms;

    let mut out = Score::default();
    let mut previous = Tier::Observe;
    let mut direction: i8 = 0;
    let mut first_attack: Option<usize> = None;
    let mut last_attack: Option<usize> = None;
    // Whether the pulse in progress has been refused at any point.
    let mut in_pulse = false;
    let mut pulse_answered = false;

    for (i, step) in steps.iter().enumerate() {
        let tier = engine.observe(&step.snapshot).tier();
        out.ticks += 1;
        out.peak_rung = out.peak_rung.max(tier.rung());

        if tier != previous {
            out.transitions += 1;
            let now: i8 = if tier > previous { 1 } else { -1 };
            if direction != 0 && now != direction {
                out.reversals += 1;
            }
            direction = now;
            previous = tier;
        }

        let attacking = step.attack_pps > 0;
        if attacking {
            first_attack.get_or_insert(i);
            last_attack = Some(i);
            if !in_pulse {
                in_pulse = true;
                pulse_answered = false;
                out.pulses += 1;
            }
            if tier.drops() {
                pulse_answered = true;
                if out.detect_ticks.is_none()
                    && let Some(start) = first_attack
                {
                    out.detect_ticks = Some((i - start) as u64);
                }
            } else {
                out.under_mitigated += step.attack_pps * period_ms / 1000;
            }
        } else if in_pulse {
            in_pulse = false;
            if !pulse_answered {
                out.missed_pulses += 1;
            }
        }

        // A refusal while the confirmable entry is not the attacker is the false positive this
        // whole design exists to avoid, and the flash crowd is the scenario that produces it.
        if tier.drops() && !step.entry_is_attacker {
            out.legit_refused += step.legit_pps * period_ms / 1000;
        }
        if let Some(last) = last_attack
            && i > last
            && tier.drops()
        {
            out.hold_ticks += 1;
        }
    }
    out.over_mitigated = out.legit_refused;
    out
}

/// Runs the six and writes the CSV beside them.
///
/// One test and not six, because the deliverable is the table: a reader comparing scenarios
/// wants them produced by one pass of one engine configuration, and six tests would let one of
/// them be skipped without the table saying so.
#[test]
fn the_six_scenarios_score_the_current_tuning() {
    let mut csv = String::from(
        "scenario,ticks,pulses,detect_ticks,peak_rung,transitions,reversals,missed_pulses,\
         hold_ticks,legit_refused,under_mitigated,over_mitigated\n",
    );

    for name in SCENARIOS {
        let s = score(name, Config::default());
        let detect = s
            .detect_ticks
            .map_or_else(|| "never".to_owned(), |t| t.to_string());
        println!(
            "LORICA_PULSE scenario={name} ticks={} pulses={} detect_ticks={detect} \
             peak_rung={} transitions={} reversals={} missed={} hold_ticks={} \
             legit_refused={} under_mitigated={}",
            s.ticks,
            s.pulses,
            s.peak_rung,
            s.transitions,
            s.reversals,
            s.missed_pulses,
            s.hold_ticks,
            s.legit_refused,
            s.under_mitigated
        );
        csv.push_str(&format!(
            "{name},{},{},{detect},{},{},{},{},{},{},{},{}\n",
            s.ticks,
            s.pulses,
            s.peak_rung,
            s.transitions,
            s.reversals,
            s.missed_pulses,
            s.hold_ticks,
            s.legit_refused,
            s.under_mitigated,
            s.over_mitigated
        ));
    }

    // `CARGO_TARGET_TMPDIR` and not the source tree: the CSV is a product of the run and
    // belongs where a build product goes, so a replay never leaves the working tree dirty.
    let path = format!("{}/pulse-scores.csv", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, &csv).unwrap_or_else(|e| panic!("{path}: {e}"));
    println!("LORICA_PULSE csv={path}");
}

/// **The one assertion that must never be relaxed.**
///
/// A flash crowd is legitimate traffic arriving suddenly: the bank fills, the bucket counter
/// climbs, and no exception counter moves, because nothing is wrong with the packets. The
/// ladder may mark and it may limit — those rungs rest on pressure and pressure is real here —
/// but it must not refuse a packet, because the only thing that could justify refusing one is
/// evidence no source can move, and there is none.
///
/// A failure here invalidates the whole ladder, not this scenario: it would mean the type-level
/// guard in `Decision::new` had been routed around, or that a scenario the engine cannot tell
/// from an attack exists in the shape operators meet most often.
#[test]
fn a_flash_crowd_refuses_nothing() {
    let s = score("flash_crowd_legit", Config::default());
    assert_eq!(
        s.legit_refused, 0,
        "the ladder refused {} legitimate packets on a flash crowd",
        s.legit_refused
    );
    assert!(
        s.peak_rung < Tier::DropSurgical.rung(),
        "the ladder reached rung {} on legitimate traffic",
        s.peak_rung
    );
}

/// Determinism, checked rather than asserted in prose.
///
/// Two runs of the same scenario through two fresh engines must agree on every column. It is
/// the property the whole harness rests on and the cheapest one to lose: a `HashMap` iteration
/// or a clock read anywhere in the engine would break it and nothing else here would notice.
#[test]
fn two_runs_of_a_scenario_agree_on_every_column() {
    for name in SCENARIOS {
        let a = score(name, Config::default());
        let b = score(name, Config::default());
        assert_eq!(a.ticks, b.ticks, "{name}: ticks");
        assert_eq!(a.detect_ticks, b.detect_ticks, "{name}: detect");
        assert_eq!(a.peak_rung, b.peak_rung, "{name}: peak");
        assert_eq!(a.transitions, b.transitions, "{name}: transitions");
        assert_eq!(a.reversals, b.reversals, "{name}: reversals");
        assert_eq!(a.missed_pulses, b.missed_pulses, "{name}: missed");
        assert_eq!(a.hold_ticks, b.hold_ticks, "{name}: hold");
        assert_eq!(a.legit_refused, b.legit_refused, "{name}: legit refused");
        assert_eq!(a.under_mitigated, b.under_mitigated, "{name}: under");
    }
}

/// The control scenario must actually be answered, or the table means nothing.
///
/// Every other column in this harness reads acceptably when the engine has stopped confirming
/// anything at all: `detect_ticks` says `never`, `legit_refused` says zero, and a reader
/// skimming for red numbers finds none. `mixed_vectors` is six exception counters and a hot
/// entry rising together for eight seconds — the least ambiguous input the engine can be given
/// — so a run where even that is never refused is a broken engine and not a cautious one.
///
/// The bound is deliberately loose. It is not a latency target: the ladder is slow, this file
/// exists partly to say how slow, and pinning the current number here would turn a measurement
/// into a rule. It fails on "never", which is the failure that would otherwise be invisible.
#[test]
fn the_control_scenario_is_answered_at_all() {
    let s = score("mixed_vectors", Config::default());
    let detect = s.detect_ticks.expect(
        "the least ambiguous attack in the set was never refused: confirmation is not reaching \
         the ladder, and every other scenario's `never` is meaningless until this passes",
    );
    assert!(
        detect < s.ticks,
        "detection landed after the run ended, which cannot happen"
    );
    assert_eq!(
        s.legit_refused, 0,
        "the control scenario declares no legitimate source as the confirmable entry, so this \
         column must be zero whatever the ladder did"
    );
}
