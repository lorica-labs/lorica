//! What the hand-written vector paths are allowed to be trusted on.
//!
//! The central test is not "the scan finds the attack". It is that every instruction set
//! answers the *same* reduction as the scalar reference on the same bytes. Hand-written
//! SIMD earns nothing if it is only ever compared against itself, and the four paths here
//! are four separate pieces of arithmetic: a saturating subtract, an unsigned compare
//! against a floor, an unsigned maximum and a sum, each expressed differently in AVX-512,
//! AVX2, NEON and plain Rust.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::Instant;

use zerocopy::IntoBytes;

use lorica_detect::cardinality::estimator;
use lorica_detect::cardinality::scan::{Isa, reduce_with};
use lorica_detect::cardinality::view::{CounterSlots, SlotsError};
use lorica_detect::cardinality::{Params, PrefixCardinality};
use lorica_detect::snapshot::{BucketView, NAMED_SLOTS};
use lorica_detect::window::FAST_PERIOD_NS;

/// Allocations, so `scan_fits_the_tick_budget_without_allocating` can assert on a number
/// rather than on a reading of the source. A counter and not a hook that panics: a panic
/// inside the allocator says nothing about which line allocated.
///
/// **Thread-local and not a global atomic.** The harness runs these tests in parallel, so a
/// process-wide count of allocations is a count of what every *other* test allocated as
/// well — which is how this file first reported 37 allocations for a scan that makes none.
/// A `Cell<usize>` with a `const` initialiser and no destructor is a per-thread word that
/// the allocator can touch without re-entering itself.
struct Counting;

thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

fn allocs() -> usize {
    ALLOCS.try_with(|n| n.get()).unwrap_or(0)
}

// SAFETY: every method forwards to `System` unchanged, so the allocator contract held is
// whatever `System` guarantees. `try_with` is what keeps the count from re-entering the
// allocator: it answers `Err` during thread-local teardown instead of initialising.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Slots as the counter map holds them: the named counters, then one slot per unified-list
/// entry. Kept as words and turned into bytes at the call site, because a `Vec<u8>` is
/// aligned to one byte and the view is entitled to refuse it — the alignment of the buffer
/// under test has to be the buffer's property and not the allocator's mood.
fn slot_words(entries: &[u64]) -> Vec<u64> {
    let mut words = vec![0u64; NAMED_SLOTS];
    words.extend_from_slice(entries);
    words
}

/// A spread that no per-entry threshold catches: `prefixes` slots each taking `per_prefix`,
/// which is under any ceiling above it, and nothing else moving.
fn carpet(prefixes: usize, per_prefix: u64, slots: usize) -> Vec<u64> {
    let mut entries = vec![0u64; slots];
    for slot in entries.iter_mut().take(prefixes) {
        *slot = per_prefix;
    }
    entries
}

/// Every path this machine can actually run, scalar included.
fn runnable() -> Vec<Isa> {
    Isa::ALL.into_iter().filter(|i| i.available()).collect()
}

#[test]
fn vector_and_scalar_agree_on_the_same_snapshot() {
    // Deliberately not a multiple of eight: the tail of every vector loop is where an
    // off-by-one in the chunking hides, and a length of 1024 would let all three vector
    // paths skip their tails entirely.
    let slots = 1021;
    let mut prev = vec![0u64; slots];
    let mut cur = vec![0u64; slots];
    for i in 0..slots {
        // Mixed on purpose: values under the floor, values over it, one pair that would
        // underflow a plain subtract, and one that would break a signed compare.
        prev[i] = (i as u64 * 7) % 13;
        cur[i] = match i % 5 {
            0 => prev[i],
            1 => prev[i] + 1,
            2 => prev[i] + 900,
            3 => prev[i].saturating_sub(1),
            _ => u64::MAX - (i as u64),
        };
    }

    let reference = reduce_with(Isa::Scalar, &cur, &prev, 2).expect("the scalar path always runs");
    let mut ran = Vec::new();
    for isa in runnable() {
        let got = reduce_with(isa, &cur, &prev, 2).expect("an available path answers");
        assert_eq!(
            got,
            reference,
            "{} disagrees with the scalar reference",
            isa.name()
        );
        ran.push(isa.name());
    }
    let missing: Vec<_> = Isa::ALL
        .into_iter()
        .filter(|i| !i.available())
        .map(Isa::name)
        .collect();
    println!(
        "cardinality-equivalence: ran={ran:?} unavailable={missing:?} reference={reference:?}"
    );

    // A machine with no vector path at all would pass every assertion above by comparing
    // the scalar path against itself, and that is exactly the vacuous green this test
    // exists to refuse.
    assert!(
        ran.len() > 1,
        "no vector path was exercised: {missing:?} were all unavailable"
    );
}

#[test]
fn forced_fallback_runs_avx2_then_scalar() {
    let entries = carpet(300, 640, 1024);
    let prev = vec![0u64; 1024];

    // Forcing, not detecting. `reduce_with` takes the instruction set as a value precisely
    // so the fallback is a path a test can enter, rather than a branch that is only ever
    // taken on hardware nobody in the loop owns.
    let scalar = reduce_with(Isa::Scalar, &entries, &prev, 1).expect("scalar always runs");
    assert_eq!(scalar.active, 300);

    match reduce_with(Isa::Avx2, &entries, &prev, 1) {
        Some(avx2) => {
            assert_eq!(avx2, scalar, "the forced AVX2 path disagrees");
            println!("cardinality-fallback: forced avx2 then scalar, both {scalar:?}");
        }
        None => panic!(
            "AVX2 answered nothing on {}: the fallback chain was not exercised",
            std::env::consts::ARCH
        ),
    }
}

#[test]
fn carpet_bombing_on_256_prefixes_is_detected_with_no_hot_counter() {
    let p = Params::default();
    let per_prefix = p.per_prefix_ceiling - 100;
    let quiet = slot_words(&carpet(0, 0, 1024));
    let spread = slot_words(&carpet(256, per_prefix, 1024));

    // A bank the attack has spread across: 900 of 1024 buckets carrying something, which
    // is what a source set larger than the bank looks like from the outside.
    let bank = BucketView::new((0..1024u64).map(|i| u64::from(i < 900) * 4096).collect());

    let mut stage = PrefixCardinality::new();
    // The first reading is the baseline, exactly as the engine's is: a live agent attaches
    // to maps that already hold counts.
    stage.observe(
        &CounterSlots::new(quiet.as_bytes()).expect("a well-formed batch read"),
        &bank,
        &p,
    );
    let v = stage.observe(
        &CounterSlots::new(spread.as_bytes()).expect("a well-formed batch read"),
        &bank,
        &p,
    );

    assert_eq!(v.prefixes, 256, "the width of the spread");
    assert!(
        v.hottest < p.per_prefix_ceiling,
        "a per-entry threshold would have caught this: hottest={} ceiling={}",
        v.hottest,
        p.per_prefix_ceiling
    );
    assert!(
        v.carpet,
        "256 prefixes under the ceiling is a carpet: {v:?}"
    );
    println!("cardinality-carpet: {v:?}");

    // The same total on one prefix is the case the ladder's own keyed path already
    // handles, and this stage must not claim it.
    let one = slot_words(&carpet(1, per_prefix * 256, 1024));
    let mut stage = PrefixCardinality::new();
    stage.observe(
        &CounterSlots::new(quiet.as_bytes()).expect("a well-formed batch read"),
        &bank,
        &p,
    );
    let v = stage.observe(
        &CounterSlots::new(one.as_bytes()).expect("a well-formed batch read"),
        &bank,
        &p,
    );
    assert!(!v.carpet, "one hot prefix is not a carpet: {v:?}");
    assert_eq!(v.prefixes, 1);
}

#[test]
fn scan_fits_the_tick_budget_without_allocating() {
    // The named slots plus the 1024 unified-list entries the kernel side declares, sized
    // from the buffer rather than from a constant this crate would have to keep in step.
    let words = slot_words(&carpet(512, 300, 1024));
    let slots = CounterSlots::new(words.as_bytes()).expect("a well-formed batch read");
    let bank = BucketView::new(vec![4096; 1024]);
    let p = Params::default();

    let mut stage = PrefixCardinality::new();
    stage.observe(&slots, &bank, &p);

    let rounds = 1000u32;
    let before = allocs();
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(stage.observe(&slots, &bank, &p));
    }
    let elapsed = start.elapsed();
    let allocated = allocs() - before;

    let per_scan_ns = elapsed.as_nanos() / u128::from(rounds);
    println!(
        "cardinality-budget: isa={} slots={} ns_per_scan={} fast_period_ns={} allocations={}",
        Isa::detect().name(),
        slots.entries().len(),
        per_scan_ns,
        FAST_PERIOD_NS,
        allocated
    );

    assert_eq!(allocated, 0, "the scan allocated on a primed stage");
    // One per cent of the fast cadence. Not a measurement of the hardware: a ceiling that
    // fails loudly if the scan ever becomes a term in the tick's budget instead of a
    // rounding error in it.
    let budget = u128::from(FAST_PERIOD_NS) / 100;
    assert!(
        per_scan_ns < budget,
        "the scan took {per_scan_ns} ns against a budget of {budget} ns"
    );
}

#[test]
fn map_bytes_the_view_cannot_interpret_are_refused() {
    let words = slot_words(&[1, 2, 3]);
    let bytes = words.as_bytes();
    assert!(CounterSlots::new(bytes).is_ok());

    // Shorter than the named counters: a truncated batch read, which would otherwise be
    // read as a map with a negative number of entry slots.
    assert_eq!(
        CounterSlots::new(&bytes[..8]).map(|_| ()),
        Err(SlotsError::Short)
    );
    // A length that is not a whole number of slots.
    assert_eq!(
        CounterSlots::new(&bytes[..bytes.len() - 3]).map(|_| ()),
        Err(SlotsError::Ragged)
    );
    // Off an eight-byte boundary by one, and still a whole number of slots. This is the
    // case that would be undefined behaviour under a hand-rolled `from_raw_parts`, and it
    // is the reason the view is a checked cast rather than a pointer cast.
    assert_eq!(
        CounterSlots::new(&bytes[1..bytes.len() - 7]).map(|_| ()),
        Err(SlotsError::Misaligned)
    );
}

#[test]
fn a_full_bank_answers_nothing_rather_than_a_manufactured_count() {
    let buckets = 1024;
    // Half the bank occupied: linear counting is at its most informative here.
    let half = estimator::distinct_sources(buckets / 2, buckets).expect("an occupancy under one");
    assert!(
        half > u64::from(buckets) / 2,
        "the estimate must exceed the occupied count: {half}"
    );
    assert_eq!(estimator::distinct_sources(0, buckets), Some(0));
    assert_eq!(estimator::distinct_sources(buckets, buckets), None);
    println!(
        "cardinality-estimator: buckets={buckets} occupied={} -> {half}",
        buckets / 2
    );
}
