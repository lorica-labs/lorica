//! Which stage owns the nanoseconds.
//!
//! The previous phase measured 236 ns above the floor for a legitimate UDP packet against
//! a budget of 10 ns in the spec, and did not say where they go. This file says it, before
//! three more stages are added to the path.
//!
//! **Why by subtraction and not by profile.** Every stage, and every parser in a build
//! with the `profiling` feature, has its own JIT symbol, and `perf` does resolve them:
//! `bpf_prog_<tag>_<name>` appears in a report. It is not usable as a ventilation. Four of
//! the stage symbols are named `run` and three of the parser symbols `parse`, because the
//! name the kernel keeps is the last component of the Rust path; and on this hardware
//! `bpf_dispatcher_xdp` collects a third of the samples, so the denominator of any
//! percentage is a guess. Cutting the pipeline after stage k and measuring the whole path
//! twice gives a difference in nanoseconds, which needs no denominator.
//!
//! **What it costs to be measurable.** The cutoff is a compare against a load-time global,
//! present only in a build with the `stage-cutoff` feature. The object that ships has none
//! of them. So the pipeline measured here is up to nine compares away from the pipeline
//! that runs, and the last line of the report is that difference, measured rather than
//! declared negligible.

#![cfg(all(feature = "kernel-tests", feature = "stage-cutoff"))]

mod support;

use carapace_common::{NO_CUTOFF, STAGE_CUTOFF_SHIFT};
use support::{
    PktBuilder, TestProg, XdpAction,
    run::{object_path, plain_object_path},
};

/// `bench/results/floor-20260822T093726Z.json`: an `XDP_PASS` that does nothing, same
/// harness, same machine.
const FLOOR_NS: u128 = 15;

/// One million, as the plan specifies: enough that the per-run average is stable.
const REPEAT: u32 = 1_000_000;

const GAME_PORT: u16 = 30_120;

/// The pipeline, in order, and what each cutoff adds to the one before it.
///
/// The first two are not stages. Parsing and the one clock reading are what every packet
/// pays before any stage has an opinion, and a ventilation that hides them inside stage 1
/// would blame the wrong code.
const LEVELS: [(u32, &str); 9] = [
    (1, "parse"),
    (2, "clock read"),
    (3, "stage 1 sanity"),
    (4, "stage 2 ICMP"),
    (5, "stage 3 LPM list"),
    (6, "stage 4 fragments"),
    (7, "stage 5 uRPF"),
    (8, "stage 6 signatures"),
    (9, "stage 7 buckets"),
];

fn steady_state_packet() -> Vec<u8> {
    // The path the budget is stated about: a legitimate UDP packet that matches no entry
    // and walks the pipeline to the end.
    PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 1])
        .udp(1111, GAME_PORT)
        .build()
}

fn at_cutoff(stages: u32) -> TestProg {
    TestProg::load_object(
        &object_path(),
        support::PROGRAM,
        stages << STAGE_CUTOFF_SHIFT,
    )
}

/// One level per process, so a `perf stat` around the process attributes its counters to
/// one cutoff. The load and the harness are the same work at every level, so the
/// difference between two levels is the stage between them and nothing else.
fn only_level() -> Option<u32> {
    let raw = std::env::var("CARAPACE_STAGE_CUTOFF").ok()?;
    let stages = raw
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("CARAPACE_STAGE_CUTOFF is {raw:?}, which is not a level"));
    assert!(
        LEVELS.iter().any(|(s, _)| *s == stages),
        "CARAPACE_STAGE_CUTOFF is {stages}, and the pipeline has {} levels",
        LEVELS.len()
    );
    Some(stages)
}

#[test]
fn one_level_of_the_pipeline_under_a_profiler() {
    let Some(stages) = only_level() else {
        println!("CARAPACE_STAGE_CUTOFF unset, nothing to profile");
        return;
    };
    let label = LEVELS
        .iter()
        .find(|(s, _)| *s == stages)
        .map(|(_, l)| *l)
        .expect("checked above");
    let packet = steady_state_packet();
    let prog = at_cutoff(stages);
    assert_eq!(prog.run(&packet), XdpAction::Pass);
    // One record per line, for the script that wraps this process in a perf stat.
    println!(
        "LEVEL,{stages},{label},{}",
        prog.ns_per_run(&packet, REPEAT)
    );
}

/// How many times the whole sweep is walked. A single pass on this hardware puts ±10 ns of
/// drift on a 250 ns figure, which is more than four of the seven stages cost, and a
/// single pass reported three of them as costing a negative number of nanoseconds. The
/// passes interleave the levels rather than repeating each one in place, so a slow drift
/// moves every level together instead of loading itself onto whichever level it caught.
const DEFAULT_PASSES: usize = 7;

fn passes() -> usize {
    match std::env::var("CARAPACE_STAGE_PASSES") {
        Ok(raw) => raw
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("CARAPACE_STAGE_PASSES is {raw:?}, which is not a count")),
        Err(_) => DEFAULT_PASSES,
    }
}

fn median(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
fn each_stage_of_the_pipeline_costs_what_it_costs() {
    if only_level().is_some() {
        println!("a single level was requested, the sweep is left to a plain run");
        return;
    }
    let packet = steady_state_packet();
    let passes = passes();
    println!("floor subtracted: {FLOOR_NS} ns, repeat = {REPEAT}, {passes} interleaved passes");

    // The plain object rides in the same interleaving as the cutoff levels: it is the
    // reference the sweep is checked against, so it has to meet the same drift.
    let mut samples = vec![Vec::with_capacity(passes); LEVELS.len() + 1];
    for _ in 0..passes {
        for (index, (stages, label)) in LEVELS.iter().enumerate() {
            let prog = at_cutoff(*stages);
            assert_eq!(
                prog.run(&packet),
                XdpAction::Pass,
                "a cutoff after {label} must still pass a legitimate packet"
            );
            samples[index].push(prog.ns_per_run(&packet, REPEAT));
        }
        let plain = TestProg::load_object(&plain_object_path(), support::PROGRAM, NO_CUTOFF);
        assert_eq!(plain.run(&packet), XdpAction::Pass);
        samples[LEVELS.len()].push(plain.ns_per_run(&packet, REPEAT));
    }

    println!(
        "{:<20} {:>10} {:>12} {:>12} {:>10}",
        "cumulative through", "median ns", "above floor", "this level", "spread"
    );
    let mut previous = 0u128;
    let mut above_per_level = Vec::with_capacity(LEVELS.len());
    for (index, (_, label)) in LEVELS.iter().enumerate() {
        let low = *samples[index].iter().min().expect("one pass at least");
        let high = *samples[index].iter().max().expect("one pass at least");
        let raw = median(&mut samples[index]);
        let above = raw.saturating_sub(FLOOR_NS);
        println!(
            "{label:<20} {raw:>7} ns {above:>9} ns {:>9} ns {:>7} ns",
            above as i128 - previous as i128,
            high - low
        );
        above_per_level.push(above);
        previous = above;
    }

    // A cutoff object built without the feature ignores the cutoff and reports the same
    // figure at every level. That reads exactly like a pipeline whose stages are free, and
    // a flat curve that looks like a result is how the previous phase lost an afternoon.
    let first = above_per_level[0];
    let last = above_per_level[above_per_level.len() - 1];
    assert!(
        last > first,
        "the whole pipeline ({last} ns) does not cost more than parsing alone ({first} ns). \
         The object was built without the stage-cutoff feature, so every cutoff ran the \
         whole pipeline: build it with --ebpf-features stage-cutoff"
    );

    // What being measurable costs. The plain object is the one that ships, walked to the
    // end; the deepest cutoff is the same walk with the compares in it. The spread of the
    // plain object is also the resolution of this whole file, and of assertion 3.
    let plain = &mut samples[LEVELS.len()];
    let low = *plain.iter().min().expect("one pass at least");
    let high = *plain.iter().max().expect("one pass at least");
    let plain_ns = median(plain).saturating_sub(FLOOR_NS);
    println!(
        "\n{:<20} {:>7} ns above the floor, spread {} ns over {passes} passes",
        "plain object",
        plain_ns,
        high - low
    );
    println!(
        "{:<20} {:>7} ns",
        "cutoff compares cost",
        last as i128 - plain_ns as i128
    );
}
