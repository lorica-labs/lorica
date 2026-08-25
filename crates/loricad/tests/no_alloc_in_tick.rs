//! Assertion 6: the tick allocates nothing.
//!
//! Not a style rule. The counter read is the only work the tick does, and the
//! single-element form of that read allocates once per slot: fifty thousand allocations
//! per tick, half a million a second. An allocator under that is a source of jitter in
//! the one process that promised not to be one, and the malloc arena grows to hold a peak
//! it gives back nine seconds later, which is long enough to fail the RSS assertion on a
//! perfectly healthy agent.
//!
//! The counting allocator lives in the binary, and an integration test cannot reach into
//! a binary. So the counter is declared here too, over the same batch reader the agent
//! uses: what is under test is that reading the map allocates nothing, and that is a
//! property of the reader, not of the process that owns it.

#![cfg(all(target_os = "linux", feature = "kernel-tests"))]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    path::PathBuf,
};

use aya::EbpfLoader;
use lorica_common::{CounterId, DEFAULT_SETTINGS, SETTINGS_SYMBOL};
use lorica_dataplane::maps;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every method forwards to System unchanged, so the contract is System's.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Thread-local, because cargo runs tests in parallel threads and a global count
        // would be whatever the other tests happened to be doing.
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

const SLOTS: u32 = 4_096;

fn object_path() -> PathBuf {
    if let Ok(path) = std::env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

#[test]
fn a_thousand_sweeps_allocate_nothing_after_the_first() {
    let bytes = std::fs::read(object_path()).expect("cannot read the eBPF object");
    let ebpf = EbpfLoader::new()
        .override_global(SETTINGS_SYMBOL, &DEFAULT_SETTINGS, true)
        .map_max_entries("COUNTERS", SLOTS)
        .load(&bytes)
        .expect("loading the object failed");

    let mut reader = maps::counters(&ebpf, SLOTS, 1_000).expect("building the reader failed");
    // The first read is allowed whatever it needs: the buffers are sized once and the
    // assertion is about steady state, which is where the agent spends its life.
    let first = reader.read().expect("the first read failed").len();
    assert_eq!(first, SLOTS as usize, "the reader skipped slots");

    let before = ALLOCATIONS.with(Cell::get);
    for round in 0..1_000 {
        let totals = reader
            .read()
            .unwrap_or_else(|err| panic!("read {round} failed: {err}"));
        // Consumed, so the read cannot be optimised into nothing. The counters are all
        // zero on a program nothing has run through, and that is fine: the cost of the
        // read does not depend on the values.
        assert_eq!(totals.len(), SLOTS as usize);
    }
    let after = ALLOCATIONS.with(Cell::get);

    assert_eq!(
        after,
        before,
        "the sweep allocated {} times over 1000 reads of {SLOTS} slots",
        after - before
    );
}

/// The named counters have to be readable on their own, because that is the cadence the
/// control loop actually needs: the per-entry slots above them are forensic and the whole
/// cost of the sweep is linear in how many of them are read.
#[test]
fn the_named_counters_can_be_read_without_the_per_entry_slots() {
    let bytes = std::fs::read(object_path()).expect("cannot read the eBPF object");
    let ebpf = EbpfLoader::new()
        .override_global(SETTINGS_SYMBOL, &DEFAULT_SETTINGS, true)
        .map_max_entries("COUNTERS", SLOTS)
        .load(&bytes)
        .expect("loading the object failed");

    let mut named = maps::counters(&ebpf, CounterId::COUNT, 64).expect("reader");
    assert_eq!(
        named.read().expect("read failed").len(),
        CounterId::COUNT as usize
    );
}
