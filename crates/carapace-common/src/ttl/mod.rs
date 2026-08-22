/// A deadline on the kernel monotonic clock, compared in-kernel at every lookup.
///
/// This is what makes an accidental permanent blackhole structurally impossible: if
/// the agent dies, if the node reboots, if a bug stops the removal, the entry stays
/// in the map and stops being applied.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Deadline(pub u64);

/// The value that never expires. `u64::MAX` nanoseconds is 584 years of uptime, so
/// reserving it as a sentinel costs no reachable deadline.
const NEVER: u64 = u64::MAX;

impl Deadline {
    pub const fn never() -> Self {
        Self(NEVER)
    }

    /// Saturates rather than wraps: a TTL long enough to overflow the clock is the
    /// operator asking for never, and wrapping would turn it into already expired,
    /// which is the dangerous direction for an `Allow` entry.
    pub const fn after(now_ns: u64, ttl_ns: u64) -> Self {
        Self(now_ns.saturating_add(ttl_ns))
    }

    pub const fn is_never(self) -> bool {
        self.0 == NEVER
    }

    /// The comparison against the sentinel is deliberate: without it a clock reading
    /// of `u64::MAX` would expire an entry declared never to expire.
    pub const fn expired(self, now_ns: u64) -> bool {
        self.0 != NEVER && now_ns >= self.0
    }
}
