//! What one whole tick costs, and what it publishes.
//!
//! `no_alloc_in_tick.rs` asserts the batch read allocates nothing. That is the expensive
//! half of the tick and not the tick: the sweep also has to publish what it read, and
//! republishing an `Arc<Snapshot>` per tick allocates one control block per tick by
//! construction. So the assertion worth having is over the whole thing — read, then
//! publish — and it is the publication side that this file exists to pin down.
//!
//! **What is not in the measured region, and why it is not a hole in it.** There is no
//! ring buffer to drain: no crate in this tree declares one, so a tick that drained it
//! would be measuring a fixture. There is no decision either — `lorica-detect` takes a
//! snapshot and the tick does not hand it one yet. Both are additions to this loop, and
//! this file is where their cost has to appear when they arrive rather than a second timer.
//!
//! The counting allocator lives in the binary and an integration test cannot reach into
//! one, so it is declared again here, thread-local because cargo runs tests in parallel
//! threads and a global count would be whatever the other test happened to be doing. This
//! is the pattern `no_alloc_in_tick.rs` set; `panic = "abort"` is what makes a surprise
//! allocation an abort rather than a report.

#![cfg(all(target_os = "linux", feature = "kernel-tests"))]

#[path = "../src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../src/tick/mod.rs"]
#[allow(dead_code)]
mod tick;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    path::PathBuf,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData},
};
use lorica_common::{CounterId, CounterLayout, DEFAULT_SETTINGS, SETTINGS_SYMBOL};
use lorica_dataplane::maps;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every method forwards to System unchanged, so the contract is System's.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Slots the counter map is sized for. Well above the named counters, so the full sweep
/// walks something rather than reading the same thirty-four slots twice.
const SLOTS: u32 = 4_096;

const TICKS: u64 = 1_000;

/// The period of the timer at the default ten hertz.
///
/// The mean is asserted against a tenth of it and the worst tick against a half, and the
/// split is not slack for its own sake: the mean is what the duty cycle is, and it measures
/// at 1.7 ms on the lab VM, while the worst tick over a thousand is a tail belonging to a
/// shared host — 5.5 ms observed there, and a guard tuned to that number would be a guard
/// that fails on a busy afternoon rather than on a regression. A single 50 ms tick still
/// fits inside the period; a mean of 10 ms would not leave the loop any.
const BUDGET: Duration = Duration::from_millis(100);

fn object_path() -> PathBuf {
    if let Ok(path) = std::env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

/// Loads the program and leaks it, because the readers the sweep owns are `'static`: the
/// maps have to outlive every reader of them, which is the same reason the agent leaks it.
fn load() -> &'static Ebpf {
    let bytes = std::fs::read(object_path()).expect("cannot read the eBPF object");
    let layout = layout();
    let mut loader = EbpfLoader::new();
    // The counter map's entry count and the stripe width the program indexes it with are one
    // decision, and `size_counters` is what makes it. Setting only the size would load a
    // program counting into slot zero of every stripe.
    let ebpf = maps::size_counters(&mut loader, &layout)
        .override_global(SETTINGS_SYMBOL, &DEFAULT_SETTINGS, true)
        .load(&bytes)
        .expect("loading the object failed");
    Box::leak(Box::new(ebpf))
}

/// The counter layout the sweep under test reads, on this machine.
fn layout() -> CounterLayout {
    maps::counter_layout(SLOTS).expect("no counter layout for this machine")
}

fn sweep_over(ebpf: &'static Ebpf) -> tick::Sweep {
    let named = maps::counters(ebpf, CounterId::COUNT, CounterId::COUNT)
        .expect("building the named-counter reader failed");
    let full = maps::counters(ebpf, SLOTS, 1_000).expect("building the full-sweep reader failed");
    tick::Sweep::new(
        named,
        full,
        CounterId::COUNT as usize,
        SLOTS as usize,
        // Every tick, which is the cadence the budget is stated about: a slower full sweep
        // only makes the measurement cheaper than the thing it is standing in for.
        1,
    )
}

#[test]
fn a_thousand_whole_ticks_allocate_nothing_and_fit_the_budget() {
    let ebpf = load();
    let mut sweep = sweep_over(ebpf);
    let mut published = state::Published::default();
    let started = Instant::now();

    // One tick and one read before the count starts. The reader sizes its buffers on the
    // first read, and arc-swap initialises its per-thread slot on the first `load_full`;
    // neither happens again, and the agent spends its life after both.
    sweep.run();
    published.publish(&sweep, started.elapsed().as_nanos() as u64);
    let _ = published.read();

    let before = ALLOCATIONS.with(Cell::get);
    let mut worst = Duration::ZERO;
    let loop_started = Instant::now();
    for _ in 0..TICKS {
        let at = Instant::now();
        sweep.run();
        published.publish(&sweep, started.elapsed().as_nanos() as u64);
        worst = worst.max(at.elapsed());
    }
    let elapsed = loop_started.elapsed();
    let after = ALLOCATIONS.with(Cell::get);

    let mean = elapsed / u32::try_from(TICKS).expect("TICKS fits a u32");
    println!(
        "tick over {SLOTS} slots: mean {mean:?}, worst {worst:?}, {TICKS} ticks in {elapsed:?}, \
         {} allocations, {} reallocated buffers",
        after - before,
        published.reallocations(),
    );

    assert_eq!(
        after,
        before,
        "the tick allocated {} times over {TICKS} ticks",
        after - before
    );
    assert_eq!(
        published.reallocations(),
        0,
        "a reader held the spare buffer with nothing reading in this test"
    );
    assert!(
        mean < BUDGET / 10,
        "the mean tick took {mean:?} of the {BUDGET:?} budget"
    );
    assert!(
        worst < BUDGET / 2,
        "the worst tick took {worst:?} of the {BUDGET:?} budget"
    );

    let snapshot = published.read();
    assert_eq!(snapshot.seq, TICKS + 1, "the sequence skipped a tick");
    assert_eq!(snapshot.counters.failures(), 0, "a read failed");
}

/// The defect this file was written for: the sweep used to reduce the named counters to
/// their sum, so every one of the thirty-four series rendered zero.
///
/// The slots are written from userspace rather than by running traffic through the program,
/// because what is under test is that a total reaches the snapshot at its own
/// `CounterId::index()` — not what increments it. The values are distinct and derived from
/// the index, so a snapshot that carried a sum, a shifted array or the same number
/// everywhere fails.
#[test]
fn the_snapshot_carries_one_total_per_named_counter() {
    let bytes = std::fs::read(object_path()).expect("cannot read the eBPF object");
    let layout = layout();
    let mut loader = EbpfLoader::new();
    let mut ebpf = maps::size_counters(&mut loader, &layout)
        .override_global(SETTINGS_SYMBOL, &DEFAULT_SETTINGS, true)
        .load(&bytes)
        .expect("loading the object failed");

    {
        let mut counters: Array<&mut MapData, u64> = ebpf
            .map_mut("COUNTERS")
            .expect("no COUNTERS map")
            .try_into()
            .expect("COUNTERS is not a flat array");
        for index in 0..CounterId::ALL.len() {
            // Everything in processor zero's stripe: the reader sums the stripes, so one is
            // enough to tell the slots apart and the sum is the value written.
            let slot = u32::try_from(index).expect("the counter count fits a u32");
            counters
                .set(layout.index(0, slot), expected(index), 0)
                .expect("writing the counter slot failed");
        }
    }

    let ebpf: &'static Ebpf = Box::leak(Box::new(ebpf));
    let mut sweep = sweep_over(ebpf);
    let mut published = state::Published::default();
    sweep.run();
    published.publish(&sweep, 0);

    let snapshot = published.read();
    let named = snapshot.counters.named();
    assert_eq!(
        named.len(),
        CounterId::ALL.len(),
        "the snapshot carries a different number of totals than there are counters"
    );
    for (index, id) in CounterId::ALL.iter().enumerate() {
        assert_eq!(
            named[index],
            expected(index),
            "{} carries the wrong total",
            id.name()
        );
    }
    // The sum is still published, and is still not a substitute for the array above.
    assert_eq!(
        sweep.named_counted(),
        (0..CounterId::ALL.len()).map(expected).sum::<u64>(),
        "the sum does not match the totals it is a sum of"
    );
}

/// The other half of the two-buffer claim: the pool never writes over a buffer somebody is
/// reading, and the tick that cannot reuse its spare says so.
///
/// This is the branch the budget assertion above never takes, and it is the one that would
/// be a data race if it were wrong. A reader keeping its snapshot past the next tick is not
/// how the agent behaves today — both handlers finish inside the branch that took them —
/// but it is one `tokio::spawn` away, and the count is what would make it visible.
#[test]
fn a_snapshot_a_reader_still_holds_is_not_written_over() {
    let ebpf = load();
    let mut sweep = sweep_over(ebpf);
    let mut published = state::Published::default();

    sweep.run();
    published.publish(&sweep, 1);
    let held = published.read();
    assert_eq!(held.at_ns, 1);

    // Two ticks: the first one publishes the spare, the second one wants the buffer `held`
    // is still pointing at.
    sweep.run();
    published.publish(&sweep, 2);
    sweep.run();
    published.publish(&sweep, 3);

    assert_eq!(
        published.reallocations(),
        1,
        "the pool reused a buffer a reader was holding"
    );
    assert_eq!(held.at_ns, 1, "the held snapshot was written over");
    assert_eq!(published.read().at_ns, 3, "the last tick was not published");
}

/// Distinct per slot, and not a plain index: a zero in slot zero would be indistinguishable
/// from a slot nobody wrote.
fn expected(index: usize) -> u64 {
    1_000 + index as u64
}
