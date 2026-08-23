//! Properties of the leaky bucket, on generated arrival sequences.
//!
//! Written against the arithmetic and not against an implementation: every one of
//! these holds for `c <- max(c - rho*dt, 0) + size` on paper, and each is here
//! because the integer form of that rule can break it. The crate is `no_std` but an
//! integration test is its own crate, so `u128` is available for the bounds; it is
//! available here precisely because it is not available in the kernel.

use lorica_common::{
    BURST_MAX, BankLayout, Bucket, Charge, DRAIN_FRACTION_BITS, Drain, Rate, SHARE_SCALE,
    UNITS_PER_BYTE,
};
use proptest::prelude::*;

const NS_PER_SEC: u128 = 1_000_000_000;

fn empty() -> Bucket {
    Bucket {
        level: 0,
        last_tick: 0,
    }
}

proptest! {
    /// A flow at half the leak rate, with room for four packets in the burst. The
    /// fixed-point drain truncates downward, so this is where a scale too coarse to
    /// resolve one inter-packet gap would show up as a drop.
    #[test]
    fn a_flow_below_the_rate_is_never_over(
        per_sec in 1_000u64..1_000_000_000,
        size in 64u32..1_500,
        packets in 1usize..512,
    ) {
        let gap_ns = 2 * u64::from(size) * 1_000_000_000 / per_sec;
        let rate = Rate { drain: Drain::per_nanosecond(per_sec), burst: 4 * u64::from(size) };
        let mut bucket = empty();
        let mut now = 1_000_000_000u64;
        for _ in 0..packets {
            prop_assert_eq!(bucket.charge(rate, now, size), Charge::Within);
            now += gap_ns;
        }
    }

    /// Metering accuracy, and the reason a level is not counted in bytes. Arrivals
    /// at the leak rate with jittered gaps: every update rounds its drain down, and
    /// the shortfall accumulates against a burst that does not grow. Counted in
    /// bytes the shortfall reaches one byte per packet, so a few hundred packets eat
    /// a whole MTU of burst and a conformant flow starts being refused.
    #[test]
    fn jitter_at_the_leak_rate_does_not_accumulate_into_a_drop(
        per_sec in 100_000u64..10_000_000,
        size in 64u32..1_500,
        jitter in 1u64..64,
        pairs in 1usize..2_000,
    ) {
        let mean = u64::from(size) * 1_000_000_000 / per_sec;
        prop_assume!(mean > jitter);
        let rate = Rate { drain: Drain::per_nanosecond(per_sec), burst: 4 * u64::from(size) };
        let mut bucket = empty();
        let mut now = 1_000_000_000u64;
        for _ in 0..pairs {
            for gap in [mean - jitter, mean + jitter] {
                now += gap;
                prop_assert_eq!(bucket.charge(rate, now, size), Charge::Within);
            }
        }
    }

    /// Conservation. The window starts far from zero so the first packet also
    /// exercises an enormous initial gap against a freshly zeroed map value.
    #[test]
    fn accepted_bytes_stay_under_rho_t_plus_burst(
        per_sec in 0u64..10_000_000_000,
        burst in 0u64..1_000_000,
        arrivals in prop::collection::vec((0u64..2_000_000, 0u32..9_000), 1..2_000),
    ) {
        let rate = Rate { drain: Drain::per_nanosecond(per_sec), burst };
        let mut bucket = empty();
        let start = 1u64 << 40;
        let mut now = start;
        let mut accepted = 0u128;
        for (gap, size) in arrivals {
            now += gap;
            if bucket.charge(rate, now, size) == Charge::Within {
                accepted += u128::from(size);
            }
        }
        let elapsed = u128::from(now - start);
        let bound = u128::from(per_sec) * elapsed / NS_PER_SEC + u128::from(burst.min(BURST_MAX));
        prop_assert!(
            accepted <= bound,
            "accepted {accepted} bytes over {elapsed} ns, bound {bound}"
        );
    }

    /// Gaps of zero and of the whole clock range, at rates and sizes up to the type
    /// maximum. Debug builds trap on any wrap, so the assertion left to make is that
    /// the ceiling the overflow argument rests on actually holds.
    #[test]
    fn extreme_gaps_never_wrap_the_level(
        per_sec in any::<u64>(),
        burst in any::<u64>(),
        size in any::<u32>(),
        stamps in prop::collection::vec(
            prop_oneof![Just(0u64), Just(u64::MAX), Just(1u64), any::<u64>()],
            1..64,
        ),
    ) {
        let rate = Rate { drain: Drain::per_nanosecond(per_sec), burst };
        let mut bucket = empty();
        for now in stamps {
            let _ = bucket.charge(rate, now, size);
            prop_assert!(bucket.level <= BURST_MAX * UNITS_PER_BYTE);
        }
    }

    /// A clock reading that does not advance, or that goes backwards, must produce a
    /// gap of zero: no drain, and no huge unsigned gap on the packet after it.
    #[test]
    fn a_clock_that_does_not_advance_drains_nothing(
        per_sec in 1u64..10_000_000_000,
        burst in 1_000u64..1_000_000,
        now in 1_000_000u64..(u64::MAX / 2),
        back in 0u64..1_000_000,
    ) {
        let rate = Rate { drain: Drain::per_nanosecond(per_sec), burst };
        let mut bucket = Bucket { level: 0, last_tick: now };
        prop_assert_eq!(bucket.charge(rate, now, 100), Charge::Within);
        let level = bucket.level;

        prop_assert_eq!(bucket.charge(rate, now - back, 100), Charge::Within);
        prop_assert_eq!(bucket.level, level + 100 * UNITS_PER_BYTE);
        prop_assert_eq!(bucket.last_tick, now);
    }

    /// The floor, over every share including zero and shares above the scale.
    #[test]
    fn a_shard_never_falls_below_its_share_of_the_rate(
        buckets in any::<u32>(),
        shards in 0u32..4_096,
        drain in 0u64..10_000_000_000,
        burst in 0u64..1_000_000_000,
        share in 0u32..(2 * SHARE_SCALE),
    ) {
        let layout = BankLayout { buckets, shards };
        let global = Rate { drain: Drain::from_raw(drain), burst };
        let shard = layout.shard_rate(global, share);
        let n = u64::from(shards.max(1));
        let apportioned = shard.drain.into_raw();

        prop_assert!(apportioned >= drain / n, "{} < {}", apportioned, drain / n);
        prop_assert!(shard.burst >= burst / n, "{} < {}", shard.burst, burst / n);
        prop_assert!(apportioned <= drain);
        prop_assert!(shard.burst <= burst);
    }

    #[test]
    fn an_index_always_lands_inside_the_bank(buckets in any::<u32>(), hash in any::<u64>()) {
        let layout = BankLayout { buckets, shards: 4 };
        prop_assert!(layout.index(hash) < buckets.max(1));
    }

    /// The drain word times `dt` is the one product here that can leave 64 bits, and it is written out
    /// in halves rather than as `u64::saturating_mul` because the intrinsic behind that
    /// method lowers to a `__multi3` call the BPF target has no implementation of. This
    /// pins the halves against the wide product: exact where it fits, `u64::MAX` where it
    /// does not, and nowhere a wrap. The ranges straddle 2^64 so both answers are reached.
    ///
    /// The scaling of that product is a shift and not a division, so the expectation is
    /// written as one. A `u128` wide product shifted by the same amount is the only
    /// independent statement of what the packet path computes.
    #[test]
    fn the_drain_is_the_wide_product_or_saturated(
        per_sec in 1u64..(1 << 34),
        dt in 1u64..(1 << 34),
    ) {
        let drain = Drain::per_nanosecond(per_sec);
        let start = u64::MAX / 2;
        let expected = ((u128::from(drain.into_raw()) * u128::from(dt))
            .min(u128::from(u64::MAX))) >> DRAIN_FRACTION_BITS;

        // A burst of zero refuses the packet, so the level the drain left is the only
        // thing the call changed and the drain is readable as a difference.
        let mut bucket = Bucket { level: start, last_tick: 0 };
        prop_assert_eq!(bucket.charge(Rate { drain, burst: 0 }, dt, 64), Charge::Over);
        prop_assert_eq!(u128::from(start - bucket.level), expected.min(u128::from(start)));
    }
}

/// The floor stated on its own, because it is the reason the function is not a
/// multiplication. Without it a shard an attacker has starved of observed traffic
/// gets a rate of zero and drops every legitimate packet that hashes to it.
#[test]
fn a_starved_shard_keeps_its_floor() {
    let layout = BankLayout {
        buckets: 4_096,
        shards: 8,
    };
    let shard = layout.shard_rate(
        Rate {
            drain: Drain::from_raw(8_000_000),
            burst: 80_000,
        },
        0,
    );
    assert_eq!(shard.drain, Drain::from_raw(1_000_000));
    assert_eq!(shard.burst, 10_000);
}

/// The drain is built against the clock `charge` is handed, and in the program that clock
/// counts jiffies.
///
/// Half a second of jiffies has to drain half a second of bytes. It fails in both
/// directions of the swap that was in the tree, which is the only thing that makes it worth
/// writing: a byte rate handed over unscaled drains 64 units where 256 million are owed,
/// and half a second of *nanoseconds* against a scaled rate saturates the product and
/// empties the bucket.
///
/// Not an equality any more, and the inequality is the trade the shift bought. The drain
/// word is `UNITS_PER_BYTE << DRAIN_FRACTION_BITS` over `hz`, which at 250 Hz is 2147483.648
/// rounded down, so half a second comes out 78 units — 0.15 byte — short of the 256 million
/// owed where the division by `10^9 / 512` was exact. Stated as short-and-never-over,
/// because under-draining is the direction that cannot let traffic through, and bounded at
/// one part in a million, which both directions of the swap above miss by four orders.
#[test]
fn half_a_second_of_jiffies_drains_half_a_second_of_bytes() {
    const HZ: u32 = 250;
    const BYTES_PER_SEC: u64 = 1_000_000;

    let rate = Rate {
        drain: Drain::per_jiffy(BYTES_PER_SEC, HZ),
        burst: BYTES_PER_SEC,
    };
    let full = BYTES_PER_SEC * UNITS_PER_BYTE;
    let mut bucket = Bucket {
        level: full,
        last_tick: 0,
    };

    assert_eq!(
        bucket.charge(rate, u64::from(HZ) / 2, 0),
        Charge::Within,
        "half the level is drained, so a zero-length packet fits under the burst"
    );
    let owed = full / 2;
    let drained = full - bucket.level;
    assert!(
        drained <= owed && owed - drained <= owed / 1_000_000,
        "half a second of jiffies drained {drained} units where {owed} are owed"
    );
}
