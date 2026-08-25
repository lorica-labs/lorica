//! What one tick's reduction costs, per instruction set, in userspace nanoseconds.
//!
//! **What this bench is and is not.** It measures a reduction over a buffer in the agent's
//! own address space: no syscall, no map, no kernel. So it is not touched by the metrology
//! correction that applies to `BPF_PROG_TEST_RUN` timings elsewhere in this tree, and a
//! nanosecond figure printed here is a nanosecond. What it is not is a figure about any
//! machine but the one it ran on — `scripts/lab/replay-carpet-bombing.sh` is what runs it
//! on the measurement host and records which processor answered.
//!
//! One id per instruction set per size, and **only for the sets the processor can run**. A
//! path that is absent from the results is absent because the hardware is, which is the
//! difference between "not measured" and "measured as zero" — and a harness that reports a
//! number for a path it never entered is worse than one that reports nothing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use lorica_detect::cardinality::scan::{Isa, reduce_with};

/// Entry counts to measure at, from the environment so the campaign script can ask for the
/// width it is replaying. Defaults to the map the kernel side declares, 1024 entry slots,
/// and to a quarter of it.
fn sizes() -> Vec<usize> {
    match std::env::var("LORICA_CARD_PREFIXES") {
        Ok(list) => list
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .filter(|n| *n > 0)
            .collect(),
        Err(_) => vec![256, 1024],
    }
}

/// A spread across half the slots, which is the shape the reduction is being asked about:
/// a uniform buffer would let the branch predictor answer the comparison for free.
fn spread(slots: usize) -> (Vec<u64>, Vec<u64>) {
    let prev: Vec<u64> = (0..slots as u64).map(|i| i * 3).collect();
    let cur: Vec<u64> = prev
        .iter()
        .enumerate()
        .map(|(i, p)| if i % 2 == 0 { p + 640 } else { *p })
        .collect();
    (cur, prev)
}

fn scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");
    for slots in sizes() {
        let (cur, prev) = spread(slots);
        for isa in Isa::ALL {
            if !isa.available() {
                continue;
            }
            // An underscore and not a slash. criterion rewrites a slash inside a function
            // id into an underscore on its way to the results directory, so an id written
            // with one is an id the campaign script would have to guess the spelling of.
            group.bench_function(format!("{}_{slots}", isa.name()), |b| {
                b.iter(|| reduce_with(isa, black_box(&cur), black_box(&prev), 1))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, scan);
criterion_main!(benches);
