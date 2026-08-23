use super::leaky::Rate;

/// Denominator of an observed share: a share of `SHARE_SCALE` is all the traffic.
///
/// A power of two so apportioning is a shift, and 16 bits because the share comes
/// from packet counters sampled over a window: resolving finer than 1/65536 of the
/// traffic would be measuring the sampling noise.
pub const SHARE_SCALE: u32 = 1 << 16;

/// Shape of a bucket bank: how many buckets it holds, and across how many per-CPU
/// shards the global rate is split.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BankLayout {
    pub buckets: u32,
    pub shards: u32,
}

impl BankLayout {
    /// Bucket a keyed hash lands in.
    ///
    /// A modulo and not a mask: the bucket count comes from a configuration file and
    /// is not required to be a power of two. An empty bank answers `0`, which is the
    /// only answer that cannot become an out-of-bounds map index.
    pub const fn index(&self, hash: u64) -> u32 {
        if self.buckets == 0 {
            return 0;
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
            per_sec: apportion(global.per_sec, share, shards),
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
