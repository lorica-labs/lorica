//! The bucket index is keyed, and what that buys.
//!
//! Two claims, and they are not the same one. That an unkeyed index is steerable and the
//! keyed one is not — which is arithmetic, and asserted as arithmetic here because
//! `lorica-common` compiles identically into the program and into this test. And that the
//! key is actually drawn per load, which is not arithmetic: it is asserted by loading the
//! program twice and reading where the same addresses landed.

#![cfg(feature = "kernel-tests")]

mod support;

use std::collections::BTreeSet;

use lorica_common::{BankLayout, DEFAULT_SETTINGS, Drain, MultiplyShift, Rate, fast_hash};
use lorica_dataplane::loader::draw_index_key;
use support::{BucketGlobals, PktBuilder, program_with_buckets};

/// The bank the program declares. Read from the map in the load-time cases below; stated
/// here for the arithmetic case, which loads nothing.
const BUCKETS: u32 = 1024;

/// Collisions to build. Ten thousand is not a round number chosen for looks: it is about
/// ten times the bucket count, so a spread distribution puts a two-figure count in every
/// bucket and the criterion below has a denominator worth dividing by.
const COLLISIONS: usize = 10_000;

/// A fixed key for the arithmetic case.
///
/// Not a drawn one: a criterion evaluated against a fresh key each run is a criterion that
/// fails one morning for no reason a reader can reconstruct. That the *draw* works is the
/// other test in this file, and it does not need this one to be random.
const KEY: [u8; 16] = *b"lorica keyed ix.";

fn v4_mapped(n: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..].copy_from_slice(&n.to_be_bytes());
    out
}

fn layout() -> BankLayout {
    BankLayout {
        buckets: BUCKETS,
        shards: 1,
    }
}

/// How far a distribution over `BUCKETS` bins is from uniform, as Pearson's statistic.
fn chi_square(counts: &[u64], total: usize) -> f64 {
    let expected = total as f64 / counts.len() as f64;
    counts
        .iter()
        .map(|observed| {
            let d = *observed as f64 - expected;
            d * d / expected
        })
        .sum()
}

fn histogram(indices: impl Iterator<Item = u32>) -> Vec<u64> {
    let mut counts = vec![0u64; BUCKETS as usize];
    for index in indices {
        counts[index as usize] += 1;
    }
    counts
}

/// Ten thousand source addresses that share a bucket under the unkeyed hash are spread by
/// the keyed one.
///
/// **What is collided, and why it is the index and not the hash.** Finding two inputs with
/// the same 64-bit FNV output needs a birthday search, and nothing about this attack does.
/// The bank has a four-figure number of buckets, so an attacker who wants ten thousand
/// addresses in one bucket enumerates candidates and keeps one in a thousand. That loop is
/// what runs below, and it is cheap. Keying does not make it expensive — it makes its
/// answer worthless, because the answer is only valid against the key of the running load.
///
/// **The criterion.** Pearson's chi-square against the uniform null over `BUCKETS` bins.
/// Under the null it has `BUCKETS - 1` degrees of freedom, so its mean is `BUCKETS - 1` and
/// its standard deviation `sqrt(2 * (BUCKETS - 1))`; the threshold is six of those
/// deviations above the mean, which is a one-sided tail of about 1e-9. That is where the
/// number comes from rather than from the value this happens to observe — a threshold read
/// off the observed statistic asserts nothing. The same statistic is computed for the
/// unkeyed hash and has to fail it: a criterion that both distributions pass is measuring
/// nothing, and everything in one bucket is the most extreme distribution there is.
#[test]
fn collisions_against_the_fast_hash_are_spread_by_the_keyed_one() {
    let df = f64::from(BUCKETS - 1);
    let threshold = df + 6.0 * (2.0 * df).sqrt();

    let target = layout().index(fast_hash(&v4_mapped(1)));
    let colliding: Vec<[u8; 16]> = (1u32..)
        .map(v4_mapped)
        .filter(|addr| layout().index(fast_hash(addr)) == target)
        .take(COLLISIONS)
        .collect();

    let unkeyed = histogram(colliding.iter().map(|addr| layout().index(fast_hash(addr))));
    assert_eq!(
        unkeyed[target as usize] as usize, COLLISIONS,
        "the collisions were not built against the fast hash at all"
    );

    let hasher = MultiplyShift::from_bytes(KEY);
    let keyed = histogram(
        colliding
            .iter()
            .map(|addr| layout().index(hasher.hash(addr))),
    );

    let unkeyed_chi = chi_square(&unkeyed, COLLISIONS);
    let keyed_chi = chi_square(&keyed, COLLISIONS);
    let worst = keyed.iter().max().copied().unwrap_or(0);
    println!(
        "{COLLISIONS} addresses colliding in the fast hash: chi-square {unkeyed_chi:.0} \
         unkeyed, {keyed_chi:.1} keyed, threshold {threshold:.1}, largest keyed bucket \
         {worst} against a mean of {:.1}",
        COLLISIONS as f64 / f64::from(BUCKETS)
    );

    assert!(
        unkeyed_chi > threshold,
        "the unkeyed distribution passed the criterion, so the criterion accepts anything"
    );
    assert!(
        keyed_chi < threshold,
        "the keyed distribution is {keyed_chi:.1} against a threshold of {threshold:.1}: \
         the collisions of the fast hash survived the keying"
    );
}

/// Two loads, two distributions.
///
/// Through the program and not through the arithmetic, because what is being asserted is
/// that the key is drawn per load and reaches the program — the arithmetic would only
/// re-assert that a multiply depends on its multiplier. The observable is the bank itself: a verdict
/// cannot say which bucket a packet landed in, and two different indices both answer pass.
#[test]
fn two_loads_put_the_same_addresses_in_different_buckets() {
    const SOURCES: u32 = 64;

    // Nothing drains and nothing overflows, so a bucket carries a level exactly when a
    // packet hashed to it.
    let unlimited = Rate {
        drain: Drain::NONE,
        burst: u64::MAX,
    };

    let occupied = |key: [u8; 16]| -> BTreeSet<usize> {
        let prog = program_with_buckets(
            DEFAULT_SETTINGS,
            BucketGlobals {
                key,
                normal: unlimited,
                suspect: unlimited,
            },
        );
        assert_eq!(
            prog.bank_len(),
            BUCKETS,
            "the bank the program declares is not the one the arithmetic case above bins into"
        );
        for n in 1..=SOURCES {
            let addr = n.to_be_bytes();
            prog.run(
                &PktBuilder::eth()
                    .ipv4()
                    .src_v4([10, addr[1], addr[2], addr[3]])
                    .udp(20_000, 30_120)
                    .payload(64)
                    .build(),
            );
        }
        prog.bank_levels()
            .iter()
            .enumerate()
            .filter(|(_, level)| **level != 0)
            .map(|(index, _)| index)
            .collect()
    };

    let first = occupied(draw_index_key().expect("drawing a key failed"));
    let second = occupied(draw_index_key().expect("drawing a key failed"));

    // The guard that makes the comparison mean something: two empty sets are equal for a
    // reason that has nothing to do with the key.
    assert!(!first.is_empty() && !second.is_empty());
    assert_ne!(
        first, second,
        "two independently drawn keys put {SOURCES} addresses in the same buckets, which \
         with a four-figure bank means the key is not reaching the program"
    );
}
