use super::leaky::{Drain, Rate};

/// Denominator of an observed share: a share of `SHARE_SCALE` is all the traffic.
///
/// A power of two so apportioning is a shift, and 16 bits because the share comes
/// from packet counters sampled over a window: resolving finer than 1/65536 of the
/// traffic would be measuring the sampling noise.
pub const SHARE_SCALE: u32 = 1 << 16;

/// Buckets the bank holds, and the one number the kernel side and the memlock budget both
/// have to agree on.
///
/// Here rather than beside the map, because the map is declared in the eBPF crate and the
/// memlock budget is computed in the policy crate, and neither can see the other. A bank
/// that the budget does not know about is a map whose kernel memory nobody counted, which
/// is how a profile passes its own audit while overrunning its limit.
///
/// A power of two, so the index is the top `log2` of this many bits of the keyed hash and
/// no division is emitted.
pub const DEFAULT_BANK_BUCKETS: u32 = 1024;

/// Bytes one bucket occupies in the map, which is a cache line and not the sixteen bytes
/// [`Bucket`](super::Bucket) needs.
///
/// The padding is a measurement: four cores updating four *different* buckets inside one
/// 64-byte line scaled 1.99 where four cores on four lines scaled 3.88. It is the value
/// size the kernel allocates, so it is the value size the budget charges.
pub const BANK_SLOT_BYTES: u64 = 64;

/// Shape of a bucket bank: how many buckets it holds, and across how many per-CPU
/// shards the global rate is split.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BankLayout {
    pub buckets: u32,
    pub shards: u32,
}

impl BankLayout {
    /// Bucket a keyed hash lands in: the **top** `log2(buckets)` bits of it.
    ///
    /// The top bits and never the low ones. The hash is multiply-shift, the low bits of a
    /// wrapping multiply are weak, and taking the high end is what the 2-universality proof
    /// of multiply-shift is about; a mask or a modulo of a power-of-two count would keep
    /// exactly the wrong end. It is also the whole reduction — one shift, no division.
    ///
    /// The modulo below survives for a bucket count that is not a power of two, which a
    /// configuration file is free to name. It is a real division, so the count has to stay
    /// a compile-time constant for the compiler to strength-reduce it; the bank the program
    /// declares is 1024 and takes the shift. A bank of zero or one bucket answers `0`, which
    /// is the only answer that cannot become an out-of-bounds map index — and the shift
    /// would be by 64, which is not a shift.
    pub const fn index(&self, hash: u64) -> u32 {
        if self.buckets <= 1 {
            return 0;
        }
        if self.buckets.is_power_of_two() {
            return (hash >> (64 - self.buckets.trailing_zeros())) as u32;
        }
        (hash % self.buckets as u64) as u32
    }

    /// Rate a single shard enforces, floored at `global / shards`.
    ///
    /// The floor is the whole point of this function. Apportioning strictly by
    /// observed share lets an attacker who keeps one shard's share at zero drive
    /// that shard's rate to zero with it, and every legitimate packet that hashes
    /// there is then dropped at a rate nobody configured. The burst takes the same
    /// floor, because a shard with a rate and no burst still drops its first packet.
    pub fn shard_rate(&self, global: Rate, observed_share: u32) -> Rate {
        let shards = u64::from(self.shards.max(1));
        let share = u64::from(observed_share.min(SHARE_SCALE));
        Rate {
            // Apportioning is linear, so it works on the scaled word and does not care
            // which clock the drain was built against.
            drain: Drain::from_raw(apportion(global.drain.into_raw(), share, shards)),
            burst: apportion(global.burst, share, shards),
        }
    }
}

/// Saturating, so a nonsensically large total apportions low rather than wrapping;
/// the floor then decides, which is the strict direction.
fn apportion(total: u64, share: u64, shards: u64) -> u64 {
    let measured = total.saturating_mul(share) / u64::from(SHARE_SCALE);
    measured.max(total / shards)
}
