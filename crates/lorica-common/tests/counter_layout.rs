//! The arithmetic both sides of the counter map depend on, checked without a kernel.
//!
//! The map is one flat `ARRAY` striped by processor — `index = cpu * stripe + slot` — because
//! the kernel refuses `BPF_F_MMAPABLE` on a per-CPU map and reading the counters through a
//! mapping instead of `BPF_MAP_LOOKUP_BATCH` is what took the agent's sweep from milliseconds
//! to microseconds. That layout puts one expression in three places: the eBPF program computes
//! it from a patched stripe width, the mapped reader walks it, and the batch reader inverts it
//! with a remainder. All three come from [`CounterLayout`], and this file is what says the
//! answers are the ones they think they are.
//!
//! It needs no kernel and no privileges, which is the point: everything else about this design
//! is asserted in `lorica-dataplane/tests/batch.rs` behind `kernel-tests`, and the arithmetic
//! is the half that can be wrong on any machine.

use lorica_common::{COUNTER_STRIPE_SLOTS, CounterId, CounterLayout, MAX_CPUS};

/// A stripe boundary must never fall inside a cache line.
///
/// Without the rounding, the last slots of one processor's stripe share a sixty-four byte line
/// with the first of the next, so two processors counting different things invalidate each
/// other's line on every packet — which is exactly the cost a per-CPU map exists to avoid,
/// reintroduced by the layout that replaced it. Eight `u64` is one line.
#[test]
fn a_stripe_is_a_whole_number_of_cache_lines() {
    for slots in [1u32, 7, 8, 9, 34, 1_058, 50_000, 1_048_610] {
        let layout = CounterLayout::new(slots, 8).expect("eight processors is a valid layout");
        assert_eq!(
            layout.stripe % COUNTER_STRIPE_SLOTS,
            0,
            "a stripe of {} slots for {slots} slots is not a whole number of cache lines",
            layout.stripe
        );
        assert!(
            layout.stripe >= slots,
            "a stripe of {} cannot hold {slots} slots",
            layout.stripe
        );
        // Rounded up and not over: at most one line of waste per processor.
        assert!(
            layout.stripe - slots < COUNTER_STRIPE_SLOTS,
            "a stripe of {} wastes {} slots for {slots}, which is more than one line",
            layout.stripe,
            layout.stripe - slots
        );
    }
}

/// Each processor owns a contiguous region and no two of them overlap.
///
/// This is the property that lets the increment in the program stay non-atomic — it was the
/// per-CPU map's guarantee and it is the layout's now — so it is the assertion the soundness
/// of the data path rests on rather than a spot check on multiplication.
#[test]
fn every_stripe_is_disjoint_and_in_processor_order() {
    let slots = CounterId::COUNT + 3;
    let cpus = 5;
    let layout = CounterLayout::new(slots, cpus).expect("a valid layout");

    let mut seen = std::collections::HashSet::new();
    for cpu in 0..cpus {
        for slot in 0..slots {
            let index = layout.index(cpu, slot);
            assert!(
                index < layout.entries(),
                "processor {cpu} slot {slot} lands at {index}, past the {} entries the map is \
                 created with",
                layout.entries()
            );
            assert!(
                seen.insert(index),
                "processor {cpu} slot {slot} lands at {index}, which another processor already \
                 owns: the increment is non-atomic, so an overlap is a lost count and not a \
                 wrong one"
            );
        }
    }

    // CPU-major, which is the whole point: one processor's slots are consecutive. The other
    // order would put every processor's value for one slot inside one cache line.
    assert_eq!(layout.index(0, 1), layout.index(0, 0) + 1);
    assert_eq!(layout.index(1, 0), layout.index(0, 0) + layout.stripe);
}

/// The batch reader has only the flat key, and it recovers the slot with a remainder. So the
/// remainder has to agree with the index, and the padding at the top of a stripe has to fall
/// outside the slots — otherwise a value nobody wrote lands in a real counter.
#[test]
fn a_flat_key_reduces_to_the_slot_it_came_from() {
    let slots = 34;
    let cpus = 4;
    let layout = CounterLayout::new(slots, cpus).expect("a valid layout");

    for cpu in 0..cpus {
        for slot in 0..slots {
            assert_eq!(layout.index(cpu, slot) % layout.stripe, slot);
        }
        // The padding: indices inside the stripe and above the last slot. They must reduce to
        // something the reader discards, which is any value at or above `slots`.
        for pad in slots..layout.stripe {
            assert!(layout.index(cpu, pad) % layout.stripe >= slots);
        }
    }
}

#[test]
fn the_map_is_created_for_every_stripe_and_nothing_more() {
    let layout = CounterLayout::new(1_058, 8).expect("a valid layout");
    assert_eq!(layout.entries(), layout.stripe * layout.cpus);
    assert_eq!(layout.bytes(), u64::from(layout.entries()) * 8);
}

/// The three refusals, because a layout that came back wrong would be a map the kernel
/// creates and the program indexes differently.
#[test]
fn an_impossible_layout_is_refused_rather_than_wrapped() {
    // No processors is not a machine.
    assert!(CounterLayout::new(34, 0).is_none());
    // Past the dimensioning ceiling the map is a size no profile budgeted for, so the answer
    // is a refusal the caller can attribute rather than an allocation the kernel refuses.
    assert!(CounterLayout::new(34, MAX_CPUS).is_some());
    assert!(CounterLayout::new(34, MAX_CPUS + 1).is_none());
    // And the product has to fit the entry count the kernel takes.
    assert!(CounterLayout::new(u32::MAX / 2, MAX_CPUS).is_none());
}
