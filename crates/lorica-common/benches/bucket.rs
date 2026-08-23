//! Cost of one bucket update, on the three shapes that take different branches.
//!
//! A report and not a gate: this measures userspace on a general-purpose core, and
//! the number that matters is the per-packet cost in the kernel.

use criterion::{Criterion, criterion_group, criterion_main};
use lorica_common::{BankLayout, Bucket, Rate};
use std::hint::black_box;

fn charge(c: &mut Criterion) {
    let mut group = c.benchmark_group("bucket");
    group.sample_size(50);
    let rate = Rate {
        per_sec: 1_000_000_000,
        burst: 1 << 16,
    };

    // idle: the gap is long enough that the drain product saturates. steady: one
    // 1500-byte packet every 1.5 us, exactly the leak rate. flood: no gap at all, so
    // the level pins to the ceiling and every call is refused without a write.
    for (name, gap) in [("idle", 1u64 << 35), ("steady", 1_500), ("flood", 0)] {
        group.bench_function(name, |b| {
            let mut bucket = Bucket {
                level: 0,
                last_ns: 0,
            };
            let mut now = 0u64;
            b.iter(|| {
                // Wrapping, because a long enough run of the idle shape walks off
                // the end of the clock, and a clock that jumps backwards is a case
                // the update already handles.
                now = now.wrapping_add(gap);
                black_box(bucket.charge(black_box(rate), now, 1_500))
            });
        });
    }

    group.bench_function("shard_rate", |b| {
        let layout = BankLayout {
            buckets: 1 << 16,
            shards: 16,
        };
        b.iter(|| black_box(layout.shard_rate(black_box(rate), 4_096)));
    });

    group.finish();
}

criterion_group!(bucket, charge);
criterion_main!(bucket);
