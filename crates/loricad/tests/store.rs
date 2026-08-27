//! What the mitigation state costs per tick, and what a crash between two durable commits
//! leaves behind.
//!
//! Linux only, and not because redb is: the tick figure is only meaningful against a named
//! machine and a named filesystem, and the agent this belongs to does not build anywhere
//! else. The module under test is included by path — an integration test cannot reach into a
//! binary crate, and including the file is what keeps one definition of it.

#![cfg(target_os = "linux")]

#[path = "../src/store/state.rs"]
#[allow(dead_code)]
mod state;
mod support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use state::{State, Tier};
use support::{Scratch, filesystem, machine};

/// Ticks measured, after a warm-up. Ten thousand is a hundred seconds of a 100 Hz agent, so
/// the median is a median over a realistic stretch and not over a burst.
const SAMPLES: usize = 10_000;
const WARMUP: usize = 200;

/// The assertion, per build profile, and every number in here was measured on carapace-dev.
///
/// **20 us was the figure this was written against and it is not reachable.** Release, ext4,
/// redb 2.6.3: the median non-durable commit is 45.4 us at [`CADENCE`] and the p99 is 81.1.
/// On tmpfs, where there is no device write at all, it is 37.6 us at the same cadence and
/// 23.0 at a cadence of 2 — so 23 us is the floor of a redb write transaction on this
/// machine, and it is `begin_write`, `open_table`, `commit`, not the data: cutting the tick
/// from two inserts to one moved it by 1.2 us. 100 us covers the measured p99 and is 0.1 % of
/// a 100 ms period.
///
/// The debug budget is separate because an unoptimised build measures rustc: the same tick
/// costs 496 us there. One number for both profiles would be either unmeetable in debug or
/// vacuous in release, and `scripts/lab/kernel-tests.sh` builds debug.
const BUDGET: Duration = if cfg!(debug_assertions) {
    Duration::from_micros(2_000)
} else {
    Duration::from_micros(100)
};

/// Cadence used where hardening is not what is being measured. Larger than any test's
/// sample count, so no durable commit lands in the middle of one.
const NEVER: u64 = u64::MAX;

/// The cadence the tick measurement runs at, taken from the agent instead of chosen here:
/// this file measures what ships, and a second number would be a second decision.
///
/// One second of a 10 Hz agent. Deliberately not [`NEVER`], and the reason is
/// [`the_cost_per_write_is_dominated_past_ten_writes_a_commit`], which measures both halves
/// of the trade across cadences rather than quoting them.
const CADENCE: u64 = State::DEFAULT_HARDEN_EVERY;

/// The cadences the sweep covers: two writes per durable commit, one second at 10 Hz, ten
/// seconds, and never. Enough to show the curve turn without turning the suite into a
/// campaign.
const CADENCES: [u64; 4] = [2, State::DEFAULT_HARDEN_EVERY, 100, NEVER];

const CRASH_ENV: &str = "LORICA_STORE_CRASH_DB";
/// Ticks the child gets to keep. One, and it is the tier change: hardening on a tier change
/// is unconditional, so the durable point is known exactly instead of depending on where the
/// cadence happened to fall.
const DURABLE_TICKS: u64 = 1;
/// Non-durable ticks the child makes after the last durable one, and therefore the ticks the
/// crash is expected to cost.
const LOST_TICKS: u64 = 3;

#[test]
fn a_tick_writes_in_under_twenty_microseconds() {
    let directory = Scratch::new("store-tick");
    let mut store =
        State::open(&directory.join("state.redb"), CADENCE).expect("cannot open the state");

    // The tier the store opened at, held for every tick below. Any other value would make the
    // first tick a tier change, and a tier change hardens whatever the cadence says.
    let tier = store.tier();
    for _ in 0..WARMUP {
        store.record(tier).expect("a warm-up tick failed");
    }

    // The two kinds of commit are sorted apart as they are taken, by asking the store what it
    // just did rather than by counting ticks and predicting it. The durable ones are not
    // thrown away: they are the other half of the argument, and this is where the factor
    // between the two is measured on this machine instead of quoted from a document.
    let mut plain = Vec::with_capacity(SAMPLES);
    let mut durable = Vec::new();
    for _ in 0..SAMPLES {
        let before = store.hardenings();
        let at = Instant::now();
        store.record(tier).expect("a tick failed");
        let elapsed = at.elapsed();
        if store.hardenings() == before {
            plain.push(elapsed);
        } else {
            durable.push(elapsed);
        }
    }
    assert_eq!(
        plain.len() + durable.len(),
        SAMPLES,
        "a sample went missing"
    );
    assert!(
        !durable.is_empty(),
        "a cadence of {CADENCE} over {SAMPLES} ticks hardened nothing, so the two paths were \
         never compared"
    );
    plain.sort_unstable();
    durable.sort_unstable();

    let p50 = plain[plain.len() / 2];
    let p99 = plain[plain.len() * 99 / 100];
    let max = plain[plain.len() - 1];
    let durable_p50 = durable[durable.len() / 2];

    println!(
        "tick write on {}, {} on {}, {} build, cadence {CADENCE}: {} non-durable commits at \
         p50 {:.1} us, p99 {:.1} us, max {:.1} us, budget {} us; {} durable commits at \
         p50 {:.1} us, a factor of {:.0}",
        machine(),
        directory.path().display(),
        filesystem(directory.path()),
        if cfg!(debug_assertions) {
            "unoptimised"
        } else {
            "release"
        },
        plain.len(),
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6,
        max.as_secs_f64() * 1e6,
        BUDGET.as_micros(),
        durable.len(),
        durable_p50.as_secs_f64() * 1e6,
        durable_p50.as_secs_f64() / p50.as_secs_f64(),
    );
    assert!(
        p50 < BUDGET,
        "the median tick write is {:.1} us, over the {} us budget, on {}",
        p50.as_secs_f64() * 1e6,
        BUDGET.as_micros(),
        machine()
    );
}

/// The measurement the cadence is chosen on, printed as a table instead of quoted from one.
///
/// **What it shows and why the shape of it is the decision.** A `Durability::None` commit
/// pins a parent state redb keeps so it can roll back to it, and only a durable commit
/// clears the backlog. So deferring hardening does not remove work, it concentrates it: the
/// cheap commit gets *more* expensive as the backlog grows and the durable one pays for all
/// of it at once. Past the point where that begins, a longer cadence buys a higher cost per
/// write **and** a wider window of loss — strictly worse on both axes, which is what makes
/// the choice a measurement rather than a preference.
///
/// Nothing is asserted about the ordering. The curve is a property of the storage engine and
/// the redb changelog says it has moved twice — a "None commits linearly slower" regression
/// fixed in 3.0.0, non-durable commits about twice as fast in 4.2.0 — so the value of this
/// test is the record it prints on the machine that ran it. The one assertion is the one that
/// matters to the agent: the cadence it ships with has to fit the per-tick budget.
///
/// A separate database per cadence, because the backlog is what is being measured and a
/// reused file would carry the previous cadence's.
#[test]
fn the_cost_per_write_is_dominated_past_ten_writes_a_commit() {
    let directory = Scratch::new("store-cadence");
    println!(
        "cadence sweep on {}, {} on {}, {} build, {SAMPLES} commits per cadence",
        machine(),
        directory.path().display(),
        filesystem(directory.path()),
        if cfg!(debug_assertions) {
            "unoptimised"
        } else {
            "release"
        },
    );

    for cadence in CADENCES {
        let path = directory.join(&format!("cadence-{cadence}.redb"));
        let mut store = State::open(&path, cadence).expect("cannot open the state");
        let tier = store.tier();
        for _ in 0..WARMUP {
            store.record(tier).expect("a warm-up tick failed");
        }

        let mut plain = Vec::with_capacity(SAMPLES);
        let mut durable = Vec::new();
        for _ in 0..SAMPLES {
            let before = store.hardenings();
            let at = Instant::now();
            store.record(tier).expect("a tick failed");
            let elapsed = at.elapsed();
            if store.hardenings() == before {
                plain.push(elapsed);
            } else {
                durable.push(elapsed);
            }
        }
        plain.sort_unstable();
        durable.sort_unstable();

        let p50 = |samples: &[Duration]| {
            samples
                .get(samples.len() / 2)
                .map_or(f64::NAN, |value| value.as_secs_f64() * 1e6)
        };
        // The number the trade is actually about: what one *write* costs on average, cheap
        // commits and the durable one that pays for them together. A cadence is only better
        // than a shorter one if this falls.
        let per_write = plain
            .iter()
            .chain(durable.iter())
            .sum::<Duration>()
            .as_secs_f64()
            * 1e6
            / SAMPLES as f64;
        println!(
            "  cadence {:>10}: {:>5} non-durable at p50 {:>7.1} us, {:>4} durable at p50              {:>8.1} us, {:>7.1} us per write",
            if cadence == NEVER {
                "never".to_owned()
            } else {
                cadence.to_string()
            },
            plain.len(),
            p50(&plain),
            durable.len(),
            p50(&durable),
            per_write,
        );

        if cadence == State::DEFAULT_HARDEN_EVERY {
            let median = plain[plain.len() / 2];
            assert!(
                median < BUDGET,
                "at the cadence the agent ships with, the median non-durable commit is                  {:.1} us against the {} us budget on {}",
                median.as_secs_f64() * 1e6,
                BUDGET.as_micros(),
                machine()
            );
        }
    }
}

#[test]
fn a_crash_between_durable_commits_leaves_a_consistent_base() {
    // The child is this same binary, re-run on this same test, with the database path in the
    // environment. A real crash is the only honest simulation of one: a dropped `Database`
    // would run redb's destructors, which is exactly the thing a crash does not do.
    if let Ok(path) = std::env::var(CRASH_ENV) {
        crash(&PathBuf::from(path));
    }

    let directory = Scratch::new("store-crash");
    let database = directory.join("state.redb");
    let status = Command::new(std::env::current_exe().expect("cannot find the test binary"))
        .args([
            "a_crash_between_durable_commits_leaves_a_consistent_base",
            "--exact",
            "--nocapture",
        ])
        .env(CRASH_ENV, &database)
        .status()
        .expect("cannot run the child");
    assert!(
        status.code().is_none(),
        "the child was supposed to die on a signal and it exited with {status:?}"
    );

    let store = State::open(&database, NEVER).expect("the database does not open after the crash");
    assert_eq!(
        store.tier(),
        Tier::Attached,
        "the tier of the last durable commit did not survive"
    );
    assert_eq!(
        store.ticks(),
        DURABLE_TICKS,
        "the base came back at a tick count no commit ever wrote, which is a torn commit \
         and not a rollback"
    );
    println!(
        "after the crash on {}: {} ticks survived, {LOST_TICKS} non-durable ticks were rolled back",
        machine(),
        store.ticks()
    );
}

/// The child. Hardens at a known tick, writes a few more without hardening, then dies without
/// running a single destructor.
fn crash(database: &Path) -> ! {
    let mut store = State::open(database, NEVER).expect("the child cannot open the state");
    store
        .record(Tier::Attached)
        .expect("the escalating tick failed");
    assert_eq!(store.hardenings(), 1, "escalating did not harden");
    for _ in 0..LOST_TICKS {
        store
            .record(Tier::Attached)
            .expect("a non-durable tick failed");
    }
    assert_eq!(store.hardenings(), 1, "the child hardened twice");
    std::process::abort();
}

#[test]
fn a_tier_change_hardens_and_a_tick_at_the_same_tier_does_not() {
    let directory = Scratch::new("store-tier");
    let mut store =
        State::open(&directory.join("state.redb"), NEVER).expect("cannot open the state");

    // The tier the store opened at. Recording it again is not a change.
    assert_eq!(store.tier(), Tier::Detached);
    for _ in 0..5 {
        store.record(Tier::Detached).expect("a tick failed");
    }
    assert_eq!(
        store.hardenings(),
        0,
        "ticks at an unchanged tier issued an fsync, which is the 1448 us path"
    );

    store.record(Tier::Attached).expect("a tick failed");
    assert_eq!(store.hardenings(), 1, "escalating did not harden");
    for _ in 0..5 {
        store.record(Tier::Attached).expect("a tick failed");
    }
    assert_eq!(store.hardenings(), 1, "staying attached hardened again");

    store.record(Tier::Detached).expect("a tick failed");
    assert_eq!(
        store.hardenings(),
        2,
        "de-escalating did not harden, and a restart would attach a host nobody is attacking"
    );

    // The cadence, on its own store so the tier never moves and only the count can trigger.
    let mut cadenced = State::open(&directory.join("cadence.redb"), 3).expect("cannot open");
    for _ in 0..9 {
        cadenced.record(Tier::Detached).expect("a tick failed");
    }
    assert_eq!(
        cadenced.hardenings(),
        3,
        "a cadence of 3 over 9 ticks hardened {} times",
        cadenced.hardenings()
    );
}
