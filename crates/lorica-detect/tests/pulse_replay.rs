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

/// **Phase 2: the three held out of the tuning.**
///
/// Written after the sweep, against the direction the sweep pointed, and deliberately not used
/// to choose anything. A tuning found by optimising against `SCENARIOS` cannot be validated by
/// `SCENARIOS` — that is fitting a parameter to a test set and calling the fit a result — so
/// these three exist only to refuse a tuning, never to select one.
///
/// All three carry a legitimate source whose own counter slot crosses `entry_per_sec`, because
/// that is the only shape that can produce a false positive at all: every dropping rung is
/// gated on `Confirmation::ExactKey`, so a scenario built purely of bucket pressure is green at
/// every tuning by construction and would prove nothing. A carrier-grade NAT gateway, a reverse
/// proxy in front of an origin and a busy hour are all ordinary, and all three of them exceed a
/// per-source rate an attacker would.
const HELD_OUT: [&str; 3] = ["legit_staircase", "legit_spike", "legit_noisy"];

#[derive(Deserialize)]
struct Scenario {
    version: u32,
    name: String,
    #[allow(dead_code)]
    about: String,
    period_ms: u64,
    #[serde(default)]
    entry_v4: Option<[u8; 4]>,
    /// Whether `entry_v4` names a source the operator has allow-listed.
    ///
    /// **This is a property of the traffic, not a switch for the test.** A compiled `Allow`
    /// rule still gets its own counter slot — deliberately, so an operator can see which
    /// allow-listed source traversed the pipeline — but `Roster::from_entries` does not seat
    /// it, so the detector is never handed it as a confirmation candidate. A scenario that
    /// declares its busy source allow-listed is therefore replayed the way the agent would
    /// actually present it: the counters move in the map and no key reaches the ladder.
    ///
    /// Before that filter existed the key *was* handed over, and the three legitimate
    /// scenarios were refused at rung 4. `the_defect_this_filter_exists_for_is_real` replays
    /// them the old way and fails if the filter is ever removed.
    #[serde(default)]
    allow_listed: bool,
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
fn steps(s: &Scenario, force_seat: bool) -> Vec<Step> {
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
            let entries = match s.entry_v4.filter(|_| force_seat || !s.allow_listed) {
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

/// The columns, per scenario and per sweep point.
///
/// Every delay is in milliseconds from the first tick the scenario declares as attack, and
/// also reported in **slow ticks** by the sweep. Both are needed and they answer different
/// questions: the tick count is the gate arithmetic — how many slow ticks `rise_ticks`,
/// `hold_ticks` and `insufficient_ticks` cost between them — and the millisecond figure is
/// that count multiplied by the period. Reporting only milliseconds would make a shorter
/// window look like a cheaper gate, which it is not.
#[derive(Default, Clone, Copy)]
struct Score {
    period_ms: u64,
    slow_ms: u64,
    ticks: u64,
    /// From the first attack tick to the tick each rung was first in force.
    mark_ms: Option<u64>,
    limit_ms: Option<u64>,
    /// To the first tick a refusing rung was in force. `None` when the ladder never refused
    /// while the attack ran.
    detect_ms: Option<u64>,
    peak_rung: u8,
    /// Rung changes that reversed direction. A climb followed by a climb is the ladder
    /// working; a climb, a descent and a climb is it hunting, and only the second is what a
    /// mis-tuned hysteresis produces.
    reversals: u64,
    /// Reversals that happened while the scenario declares an attack in progress. **This is
    /// the oscillation number.** The plain `reversals` count includes the descent at the end
    /// of a run, which is the ladder doing its job, so a tuning that only descends more
    /// finely reads as noisier than it is. Hunting is a reversal with an attack still on.
    reversals_under_attack: u64,
    transitions: u64,
    /// Pulses during which no refusing rung was ever in force.
    missed_pulses: u64,
    pulses: u64,
    /// How long a refusing rung stayed in force after the last attack tick.
    hold_ms: u64,
    /// Legitimate packets refused: the scenario's legitimate rate, over the ticks a refusing
    /// rung was in force while the confirmable entry was **not** the attacker.
    legit_refused: u64,
    /// Attack packets that passed because no refusing rung was in force.
    under_mitigated: u64,
}

impl Score {
    /// The delay to the first refusal expressed in slow ticks, which is the number the gates
    /// actually produce and the only one comparable across periods.
    fn detect_slow_ticks(&self) -> Option<u64> {
        self.detect_ms.map(|ms| ms / self.slow_ms.max(1))
    }
}

fn score(name: &str, cfg: Config) -> Score {
    score_with(name, cfg, false)
}

/// Replays a scenario the way the agent presented it **before** `Roster` learned to skip an
/// allow-listed entry: the key is seated whatever the operator decided about it.
///
/// Used by exactly one test, which asserts the false positive comes back. Keeping the old
/// behaviour reachable is what makes the filter's absence a failing build rather than a silent
/// regression to eleven million refused packets.
fn score_forcing_seat(name: &str, cfg: Config) -> Score {
    score_with(name, cfg, true)
}

/// Scores a scenario with the confirmable entry either present in the roster or absent.
///
/// `force_seat` overrides a scenario's `allow_listed`, which is the only reason this takes an
/// argument at all.
/// It is not a tuning: it is the shape the agent would present if `Roster` filtered the entry
/// out, which is the fix under test in the note. The scenario is otherwise identical, so the
/// difference between the two runs is attributable to the roster and to nothing else.
fn score_with(name: &str, cfg: Config, force_seat: bool) -> Score {
    let sc = scenario(name);
    let steps = steps(&sc, force_seat);
    let period_ms = sc.period_ms;
    let mut out = Score {
        period_ms,
        slow_ms: cfg.slow_period_ns / 1_000_000,
        ..Score::default()
    };
    let mut engine = Engine::new(cfg);

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
        let attacking = step.attack_pps > 0;

        if tier != previous {
            out.transitions += 1;
            let now: i8 = if tier > previous { 1 } else { -1 };
            if direction != 0 && now != direction {
                out.reversals += 1;
                // Still under attack, so this is the ladder changing its mind about traffic
                // that has not changed — which is what a mis-tuned hysteresis does.
                if attacking {
                    out.reversals_under_attack += 1;
                }
            }
            direction = now;
            previous = tier;
        }

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
            } else {
                out.under_mitigated += step.attack_pps * period_ms / 1000;
            }
        } else if in_pulse {
            in_pulse = false;
            if !pulse_answered {
                out.missed_pulses += 1;
            }
        }

        // Timed from the first attack tick and not from the run, so a scenario that opens
        // with quiet is not credited with the quiet.
        if let Some(start) = first_attack {
            let since = (i - start) as u64 * period_ms;
            if tier >= Tier::Mark {
                out.mark_ms.get_or_insert(since);
            }
            if tier >= Tier::Limit {
                out.limit_ms.get_or_insert(since);
            }
            if tier.drops() && attacking {
                out.detect_ms.get_or_insert(since);
            }
        }

        // A refusal while the confirmable entry is not the attacker is the false positive
        // this whole design exists to avoid.
        if tier.drops() && !step.entry_is_attacker {
            out.legit_refused += step.legit_pps * period_ms / 1000;
        }
        if let Some(last) = last_attack
            && i > last
            && tier.drops()
        {
            out.hold_ms += period_ms;
        }
    }
    out
}

/// One sweep point: what was changed from [`Config::default`], and how it is written down.
///
/// A struct of four numbers rather than a closure over `Config`, because a point has to be
/// printable, reproducible from its printed form, and comparable to its neighbours. The
/// `label` is what appears in the CSV and in `LORICA_POINT`, and it is also what
/// `LORICA_SWEEP` accepts: any row of the table can be re-run on its own from what the table
/// prints, which is the whole of requirement (c).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Point {
    rise: u32,
    hold: u32,
    insufficient: u32,
    slow_ms: u64,
}

impl Point {
    fn config(self) -> Config {
        Config {
            rise_ticks: self.rise,
            hold_ticks: self.hold,
            insufficient_ticks: self.insufficient,
            slow_period_ns: self.slow_ms * 1_000_000,
            ..Config::default()
        }
    }

    fn label(self) -> String {
        format!(
            "rise={},hold={},insuf={},slow_ms={}",
            self.rise, self.hold, self.insufficient, self.slow_ms
        )
    }

    /// Parses a label back into a point, for `LORICA_SWEEP`.
    fn parse(text: &str) -> Self {
        let mut p = BASELINE;
        for field in text.split(',') {
            let (key, value) = field
                .split_once('=')
                .unwrap_or_else(|| panic!("LORICA_SWEEP field {field:?} is not key=value"));
            let n: u64 = value
                .trim()
                .parse()
                .unwrap_or_else(|e| panic!("LORICA_SWEEP {key}: {e}"));
            match key.trim() {
                "rise" => p.rise = n as u32,
                "hold" => p.hold = n as u32,
                "insuf" | "insufficient" => p.insufficient = n as u32,
                "slow_ms" => p.slow_ms = n,
                other => panic!("LORICA_SWEEP: no axis named {other}"),
            }
        }
        p
    }
}

/// The shipped default, as a point, so the table always contains the thing every row is
/// compared to — and so an unset `LORICA_SWEEP` replays what is actually running.
///
/// `the_point_named_here_is_the_one_that_ships` holds it to `Config::default()`. Without that
/// the two drift apart silently and every row of the sweep is measured against a baseline
/// nothing runs.
const BASELINE: Point = Point {
    rise: 1,
    hold: 2,
    insufficient: 3,
    slow_ms: 500,
};

/// What shipped before this campaign, kept because two tests are about the difference.
const PREVIOUS: Point = Point {
    rise: 2,
    hold: 2,
    insufficient: 3,
    slow_ms: 1000,
};

fn csv_header() -> String {
    "point,rise,hold,insuf,slow_ms,scenario,ticks,pulses,mark_ms,limit_ms,detect_ms,\
     detect_slow_ticks,peak_rung,transitions,reversals,reversals_under_attack,missed_pulses,\n     hold_ms,legit_refused,\
     under_mitigated\n"
        .to_owned()
}

fn csv_row(point: Point, name: &str, s: &Score) -> String {
    let opt = |v: Option<u64>| v.map_or_else(|| "never".to_owned(), |x| x.to_string());
    format!(
        "\"{}\",{},{},{},{},{name},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        point.label(),
        point.rise,
        point.hold,
        point.insufficient,
        point.slow_ms,
        s.ticks,
        s.pulses,
        opt(s.mark_ms),
        opt(s.limit_ms),
        opt(s.detect_ms),
        opt(s.detect_slow_ticks()),
        s.peak_rung,
        s.transitions,
        s.reversals,
        s.reversals_under_attack,
        s.missed_pulses,
        s.hold_ms,
        s.legit_refused,
        s.under_mitigated
    )
}

/// Scores every scenario at one point and prints one line each.
fn run_point(point: Point, names: &[&str], csv: &mut String) -> Vec<(String, Score)> {
    let opt = |v: Option<u64>| v.map_or_else(|| "never".to_owned(), |x| x.to_string());
    let mut out = Vec::new();
    for name in names {
        let s = score(name, point.config());
        println!(
            "LORICA_POINT {} scenario={name} mark_ms={} limit_ms={} detect_ms={} \
             detect_slow_ticks={} peak={} reversals={} hunting={} missed={} legit_refused={}",
            point.label(),
            opt(s.mark_ms),
            opt(s.limit_ms),
            opt(s.detect_ms),
            opt(s.detect_slow_ticks()),
            s.peak_rung,
            s.reversals,
            s.reversals_under_attack,
            s.missed_pulses,
            s.legit_refused
        );
        csv.push_str(&csv_row(point, name, &s));
        out.push(((*name).to_owned(), s));
    }
    out
}

fn write_csv(file: &str, csv: &str) -> String {
    let path = format!("{}/{file}", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, csv).unwrap_or_else(|e| panic!("{path}: {e}"));
    path
}

/// The six at the current default, which is the row every sweep point is read against.
#[test]
fn the_six_scenarios_score_the_current_tuning() {
    let mut csv = csv_header();
    run_point(BASELINE, &SCENARIOS, &mut csv);
    println!("LORICA_PULSE csv={}", write_csv("pulse-scores.csv", &csv));
}

/// **Phase 1: the curve.**
///
/// Two axes governing the climb — `rise_ticks` and the `insufficient_ticks` gate, with
/// `hold_ticks` alongside because it is the third term in the same sum — and one governing
/// dilution, the slow period. They are swept as one grid and read as two questions, because
/// **the period is not a third climb parameter, it is a multiplier on all of them**: every
/// gate counts in slow ticks, so halving the period halves the climb in wall-clock without
/// changing a single gate. That is why `detect_slow_ticks` sits in the table next to
/// `detect_ms`. A row that improves the tick count changed the arithmetic; a row that
/// improves only the millisecond figure bought it with sampling rate, and pays for it in the
/// per-tick cost measured elsewhere.
///
/// Dilution is read off `missed_pulses` on `pulse_gaps`, and only the period can move it: a
/// 300 ms pulse averaged into a one-second window is below `burst_per_sec` whatever the gates
/// are set to.
///
/// This writes the table. It asserts nothing about which point is best, on purpose.
#[test]
fn phase_1_sweeps_the_climb_and_the_window() {
    let mut csv = csv_header();
    let mut summary = String::from(
        "point,worst_detect_ms,worst_detect_slow_ticks,gaps_missed,hunting,\
         legit_refused\n",
    );

    for slow_ms in [1000u64, 500, 250] {
        for rise in [2u32, 1] {
            for hold in [2u32, 1, 0] {
                for insufficient in [3u32, 2, 1] {
                    let point = Point {
                        rise,
                        hold,
                        insufficient,
                        slow_ms,
                    };
                    let scored = run_point(point, &SCENARIOS, &mut csv);

                    // The worst case over the scenarios that can be detected at all: a point
                    // is only as fast as its slowest answer, and averaging would let one
                    // scenario's speed hide another's `never`.
                    let answered: Vec<&Score> = scored
                        .iter()
                        .filter(|(n, _)| n != "flash_crowd_legit")
                        .map(|(_, s)| s)
                        .collect();
                    let worst_ms = answered.iter().filter_map(|s| s.detect_ms).max();
                    let worst_ticks = answered.iter().filter_map(|s| s.detect_slow_ticks()).max();
                    let never = answered.iter().filter(|s| s.detect_ms.is_none()).count();
                    let gaps = scored
                        .iter()
                        .find(|(n, _)| n == "pulse_gaps")
                        .map_or(0, |(_, s)| s.missed_pulses);
                    let hunting: u64 = scored.iter().map(|(_, s)| s.reversals_under_attack).sum();
                    let refused: u64 = scored.iter().map(|(_, s)| s.legit_refused).sum();
                    summary.push_str(&format!(
                        "\"{}\",{},{},{gaps},{hunting},{refused}\n",
                        point.label(),
                        // `never` carried into the worst case rather than dropped, because a
                        // point that answers four scenarios quickly and misses two is not a
                        // fast point.
                        if never > 0 {
                            format!("never x{never}")
                        } else {
                            worst_ms.unwrap_or(0).to_string()
                        },
                        worst_ticks.map_or_else(|| "never".to_owned(), |v| v.to_string()),
                    ));
                }
            }
        }
    }

    println!("LORICA_SWEEP csv={}", write_csv("sweep.csv", &csv));
    println!(
        "LORICA_SWEEP summary={}",
        write_csv("sweep-summary.csv", &summary)
    );
    print!("{summary}");
}

/// Re-runs one point from its label, which is requirement (c).
///
/// ```text
/// LORICA_SWEEP=rise=1,hold=1,insuf=2,slow_ms=500 \
///   cargo test -p lorica-detect --test pulse_replay -- --nocapture one_point
/// ```
///
/// Unset, it replays the default, so the test is never a no-op and never silently skipped.
#[test]
fn one_point_replays_from_its_label() {
    let point = std::env::var("LORICA_SWEEP").map_or(BASELINE, |text| Point::parse(&text));
    let mut csv = csv_header();
    run_point(point, &SCENARIOS, &mut csv);
    println!("LORICA_POINT csv={}", write_csv("point.csv", &csv));
}

/// **The one assertion that must never be relaxed.**
///
/// A flash crowd is legitimate traffic arriving suddenly: the bank fills, the bucket counter
/// climbs, and no exception counter moves, because nothing is wrong with the packets. The
/// ladder may mark and it may limit — those rungs rest on pressure and pressure is real here
/// — but it must not refuse a packet, because the only thing that could justify refusing one
/// is evidence no source can move, and there is none.
///
/// A failure here invalidates the whole ladder, not this scenario: it would mean the
/// type-level guard in `Decision::new` had been routed around, or that a scenario the engine
/// cannot tell from an attack exists in the shape operators meet most often.
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
/// the property the whole harness rests on and the cheapest one to lose: a `HashMap`
/// iteration or a clock read anywhere in the engine would break it and nothing else here
/// would notice.
#[test]
fn two_runs_of_a_scenario_agree_on_every_column() {
    for name in SCENARIOS {
        let a = score(name, Config::default());
        let b = score(name, Config::default());
        assert_eq!(a.mark_ms, b.mark_ms, "{name}: mark");
        assert_eq!(a.limit_ms, b.limit_ms, "{name}: limit");
        assert_eq!(a.detect_ms, b.detect_ms, "{name}: detect");
        assert_eq!(a.peak_rung, b.peak_rung, "{name}: peak");
        assert_eq!(a.transitions, b.transitions, "{name}: transitions");
        assert_eq!(a.reversals, b.reversals, "{name}: reversals");
        assert_eq!(
            a.reversals_under_attack, b.reversals_under_attack,
            "{name}: hunting"
        );
        assert_eq!(a.missed_pulses, b.missed_pulses, "{name}: missed");
        assert_eq!(a.hold_ms, b.hold_ms, "{name}: hold");
        assert_eq!(a.legit_refused, b.legit_refused, "{name}: legit refused");
        assert_eq!(a.under_mitigated, b.under_mitigated, "{name}: under");
    }
}

/// The control scenario must actually be answered, or the table means nothing.
///
/// Every other column in this harness reads acceptably when the engine has stopped confirming
/// anything at all: `detect_ms` says `never`, `legit_refused` says zero, and a reader skimming
/// for red numbers finds none. `mixed_vectors` is six exception counters and a hot entry
/// rising together for eight seconds — the least ambiguous input the engine can be given — so
/// a run where even that is never refused is a broken engine and not a cautious one.
///
/// The bound is deliberately loose. It is not a latency target: the ladder is slow, this file
/// exists partly to say how slow, and pinning the current number here would turn a measurement
/// into a rule. It fails on "never", which is the failure that would otherwise be invisible.
#[test]
fn the_control_scenario_is_answered_at_all() {
    let s = score("mixed_vectors", Config::default());
    let detect = s.detect_ms.expect(
        "the least ambiguous attack in the set was never refused: confirmation is not reaching \
         the ladder, and every other scenario's `never` is meaningless until this passes",
    );
    assert!(
        detect < s.ticks * s.period_ms,
        "detection landed after the run ended, which cannot happen"
    );
    assert_eq!(
        s.legit_refused, 0,
        "the control scenario declares no legitimate source as the confirmable entry, so this \
         column must be zero whatever the ladder did"
    );
}

/// **Phase 2: the swept grid, against the three held out of it.**
///
/// The same grid as [`phase_1_sweeps_the_climb_and_the_window`], scored against three scenarios
/// written after the sweep and used only to refuse a tuning. Every point, not only the
/// recommended one: a tuning is a region of this grid rather than a coordinate, and a neighbour
/// that refuses legitimate traffic means the recommendation sits next to a cliff.
///
/// **This assertion could not be made until the roster was fixed.** It failed at 104 of the 162
/// point-scenario pairs, *including the current default*, which refused 11.09 M packets on
/// `legit_staircase` and reached rung 4 on it. None of that was a property of any tuning:
/// `Roster::from_entries` seated allow-listed entries, so the detector was handed a legitimate
/// source as a confirmation candidate and `hottest_entry` took the maximum over it. The three
/// scenarios now declare `allow_listed`, the roster no longer seats such an entry, and the grid
/// is clean — see `the_defect_this_filter_exists_for_is_real`, which replays them the old way.
///
/// Failures are collected rather than panicked on at the first, because the useful output is
/// *which* points fail and on which scenario.
#[test]
fn phase_2_no_swept_point_refuses_a_legitimate_packet() {
    let mut csv = csv_header();
    let mut failures: Vec<String> = Vec::new();

    for slow_ms in [1000u64, 500, 250] {
        for rise in [2u32, 1] {
            for hold in [2u32, 1, 0] {
                for insufficient in [3u32, 2, 1] {
                    let point = Point {
                        rise,
                        hold,
                        insufficient,
                        slow_ms,
                    };
                    for (name, s) in run_point(point, &HELD_OUT, &mut csv) {
                        if s.legit_refused > 0 || s.peak_rung >= Tier::DropSurgical.rung() {
                            failures.push(format!(
                                "{} on {name}: {} legitimate packets refused, peak rung {}",
                                point.label(),
                                s.legit_refused,
                                s.peak_rung
                            ));
                        }
                    }
                }
            }
        }
    }

    println!("LORICA_HELDOUT csv={}", write_csv("held-out.csv", &csv));
    assert!(
        failures.is_empty(),
        "{} of the swept points refuse legitimate traffic:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// **The false positive the roster filter exists for, kept reachable so it cannot come back.**
///
/// Replays the three legitimate scenarios the way the agent presented them before
/// `Roster::from_entries` learned to skip an allow-listed entry: the key is seated whatever the
/// operator decided about it. The refusals return, in the millions, at rung 4 — a widened `/24`
/// around a carrier-grade NAT gateway.
///
/// This is the regression test for a defect rather than for a feature, so it asserts the *old*
/// behaviour. Deleting the filter would make `phase_2` and `phase_4` fail, which is the primary
/// guard; this one exists so the failure is legible — it says what was lost and how much, rather
/// than leaving somebody to rediscover the mechanism from a red assertion on a tuning grid.
///
/// Run at the default and at the recommendation, because a diagnosis that only holds at one
/// tuning is a coincidence.
#[test]
fn the_defect_this_filter_exists_for_is_real() {
    for point in [PREVIOUS, BASELINE] {
        let mut worst = 0u64;
        for name in HELD_OUT {
            let seated = score_forcing_seat(name, point.config());
            let filtered = score(name, point.config());
            println!(
                "LORICA_ROSTER {} scenario={name} seated_refused={} seated_peak={} \
                 filtered_refused={} filtered_peak={}",
                point.label(),
                seated.legit_refused,
                seated.peak_rung,
                filtered.legit_refused,
                filtered.peak_rung
            );
            worst = worst.max(seated.legit_refused);
            assert_eq!(
                filtered.legit_refused,
                0,
                "{}: {name} refuses {} legitimate packets with the filter in place",
                point.label(),
                filtered.legit_refused
            );
        }
        assert!(
            worst > 10_000_000,
            "{}: seating allow-listed keys refused only {worst} packets, against the 11.09 M \
             measured when the filter was written — either the scenarios have drifted or the \
             filter is no longer the thing being tested",
            point.label()
        );
    }
}

/// The sweep's baseline and the shipped default must be the same point.
///
/// Cheap, and it is the assumption every other row in the table rests on. A default that moved
/// without this constant moving would leave the whole sweep comparing against something nobody
/// runs, and nothing else here would notice.
#[test]
fn the_point_named_here_is_the_one_that_ships() {
    let shipped = Config::default();
    let named = BASELINE.config();
    assert_eq!(named.rise_ticks, shipped.rise_ticks, "rise_ticks");
    assert_eq!(named.hold_ticks, shipped.hold_ticks, "hold_ticks");
    assert_eq!(
        named.insufficient_ticks, shipped.insufficient_ticks,
        "insufficient_ticks"
    );
    assert_eq!(
        named.slow_period_ns, shipped.slow_period_ns,
        "slow_period_ns"
    );
}

/// **Phase 4: the shipped default, held to all nine.**
///
/// Not a recommendation any more — this is what runs. It was written while the tuning was still
/// a proposal and while the roster still handed the detector allow-listed keys, so the three
/// held-out scenarios had to be scored with the key withheld to model the fix. Both have landed:
/// the scenarios declare `allow_listed`, the roster does not seat such an entry, and this scores
/// the nine exactly as the agent would present them.
///
/// The bounds are the numbers the campaign quoted, so a future change that gives back the gain
/// fails here rather than in a note nobody re-runs.
#[test]
fn phase_4_the_recommendation_is_green_on_all_nine() {
    let cfg = Config::default;

    for name in HELD_OUT {
        let s = score(name, cfg());
        assert_eq!(
            s.legit_refused, 0,
            "{name} refuses {} legitimate packets at the recommended point even with the              roster fix modelled: the recommendation is wrong, not the sequencing",
            s.legit_refused
        );
        assert!(
            s.peak_rung < Tier::DropSurgical.rung(),
            "{name} reached rung {} on legitimate traffic",
            s.peak_rung
        );
    }

    let control = score("mixed_vectors", cfg());
    let detect = control
        .detect_ms
        .expect("the control is never answered at the recommended point");
    assert!(
        detect <= 3000,
        "the control took {detect} ms at the recommended point, which is no longer the gain          this point was recommended for"
    );

    // The scenario the whole campaign started from: a stable, perfectly attributable source
    // attacking for six seconds, which the default never refuses at all.
    let stable = score("renewed_sources", cfg());
    assert!(
        stable.detect_ms.is_some(),
        "the six-second stable attacker is still never refused, which was the point"
    );

    // Hunting is what the speed is bought with, and it is bought in units the note quotes.
    let hunting: u64 = SCENARIOS
        .iter()
        .map(|n| score(n, cfg()).reversals_under_attack)
        .sum();
    assert!(
        hunting <= 2,
        "the recommended point hunts {hunting} times across the six, against the 1 measured          when it was recommended"
    );
}
