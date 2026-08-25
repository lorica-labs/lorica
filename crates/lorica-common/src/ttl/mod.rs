/// A deadline on the kernel's jiffy counter, compared in-kernel at every lookup.
///
/// This is what makes an accidental permanent blackhole structurally impossible: if
/// the agent dies, if the node reboots, if a bug stops the removal, the entry stays
/// in the map and stops being applied.
///
/// Jiffies and not nanoseconds because the data path pays for the reading. A jiffy is
/// `1/CONFIG_HZ`, so 1 to 4 ms, and TTLs are configured in whole seconds: the coarser
/// unit loses nothing an operator can express.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Deadline(pub u64);

/// The value that never expires. `u64::MAX` jiffies is 584 million years of uptime at
/// `CONFIG_HZ=1000` and ten times that at 100, so reserving it as a sentinel costs no
/// reachable deadline.
const NEVER: u64 = u64::MAX;

impl Deadline {
    pub const fn never() -> Self {
        Self(NEVER)
    }

    /// Saturates rather than wraps: a TTL long enough to overflow the counter is the
    /// operator asking for never, and wrapping would turn it into already expired,
    /// which is the dangerous direction for an `Allow` entry.
    pub const fn after(now: u64, ttl: u64) -> Self {
        Self(now.saturating_add(ttl))
    }

    pub const fn is_never(self) -> bool {
        self.0 == NEVER
    }

    /// The comparison against the sentinel is deliberate: without it a clock reading
    /// of `u64::MAX` would expire an entry declared never to expire.
    pub const fn expired(self, now: u64) -> bool {
        self.0 != NEVER && now >= self.0
    }
}

/// The kernel's coarse clock as userspace sees it: the rate it ticks at and one reading
/// of it.
///
/// The two travel together because neither is usable alone. `CONFIG_HZ` has no reliable
/// userspace interface, so the rate is measured rather than assumed, and a jiffy count
/// means nothing without the rate that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub hz: u32,
    pub jiffies: u64,
}

impl Clock {
    /// A TTL in whole seconds as an absolute deadline on this clock.
    ///
    /// Seconds are what the configuration language offers, so the conversion is exact up
    /// to the width of one jiffy, which no rule can name.
    pub const fn deadline(self, ttl_secs: u64) -> Deadline {
        Deadline::after(self.jiffies, ttl_secs.saturating_mul(self.hz as u64))
    }
}
