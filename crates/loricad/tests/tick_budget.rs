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

#[path = "../src/roster.rs"]
#[allow(dead_code)]
mod roster;
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

/// A stamp for a tick that only needs one to be distinct. The sweep uses it to mark the slices
/// it completed, and the publication carries it; nothing here reads a rate off it.
fn at_ns_of(sweep: &tick::Sweep) -> u64 {
    sweep.ticks().saturating_mul(100_000_000)
}

/// One entry per slot above the named counters.
///
/// The keys are arbitrary and distinct; what matters is the count, because the publication does
/// a lookup and a push per seat and this test is about what that costs after the first tick.
fn entries_for_every_slot() -> Vec<(lorica_common::LpmKey, lorica_common::LpmValue)> {
    (CounterId::COUNT..SLOTS)
        .map(|slot| {
            let n = slot - CounterId::COUNT;
            let mut value = lorica_common::LpmValue::zeroed();
            value.counter_idx = slot;
            let key =
                lorica_common::LpmKey::host_v4([10, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
            (key, value)
        })
        .collect()
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
        // No bank. The budget is about the counter sweep and the publication, and a bank read
        // is a syscall on a cadence of its own -- measuring it here would fold two very
        // different costs into one number. Its buffers are allocated in its constructor and
        // never again, which is the property this test is about, so its absence does not
        // weaken the claim.
        None,
        1,
    )
}

#[test]
fn a_thousand_whole_ticks_allocate_nothing_and_fit_the_budget() {
    let ebpf = load();
    let mut sweep = sweep_over(ebpf);
    let mut published = state::Published::default();
    let roster = roster::Roster::from_entries(&entries_for_every_slot());
    // A roster with an entry per slot above the named counters, which is the shape a real
    // policy produces and the one that makes the publication do the most work: every seat is
    // looked up in the sweep and pushed into the snapshot's entry slice, every tick. An empty
    // roster would let this test pass on a publication that never touches that buffer.
    let roster = roster::Roster::from_entries(&entries_for_every_slot());
    let started = Instant::now();

    // **Two ticks and two reads before the count starts, and the second is not padding.**
    // The reader sizes its buffers on the first read and arc-swap initialises its per-thread
    // slot on the first `load_full`, neither of which happens again. But the publication
    // alternates between *two* snapshot buffers, so the entry slice and the level slice are
    // each sized twice -- once per buffer -- and a single priming tick leaves the spare empty
    // to grow on the tick after the count started. That is what this test caught when the
    // slices were first filled: eleven allocations over a thousand ticks, all of them the
    // second buffer catching up.
    for _ in 0..2 {
        sweep.run(started.elapsed().as_nanos() as u64);
        published.publish(&sweep, started.elapsed().as_nanos() as u64, &roster);
        let _ = published.read();
    }

    let before = ALLOCATIONS.with(Cell::get);
    let mut worst = Duration::ZERO;
    let loop_started = Instant::now();
    for _ in 0..TICKS {
        let at = Instant::now();
        sweep.run(at_ns_of(&sweep));
        published.publish(&sweep, started.elapsed().as_nanos() as u64, &roster);
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
    // Two priming ticks, not one: see the loop above. The published sequence is what the
    // sweep counted, so it is the whole run and not only the measured part.
    assert_eq!(snapshot.seq, TICKS + 2, "the sequence skipped a tick");
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
    let roster = roster::Roster::from_entries(&entries_for_every_slot());
    sweep.run(at_ns_of(&sweep));
    published.publish(&sweep, 0, &roster);

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
    let roster = roster::Roster::from_entries(&entries_for_every_slot());

    sweep.run(at_ns_of(&sweep));
    published.publish(&sweep, 1, &roster);
    let held = published.read();
    assert_eq!(held.at_ns, 1);

    // Two ticks: the first one publishes the spare, the second one wants the buffer `held`
    // is still pointing at.
    sweep.run(at_ns_of(&sweep));
    published.publish(&sweep, 2, &roster);
    sweep.run(at_ns_of(&sweep));
    published.publish(&sweep, 3, &roster);

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
