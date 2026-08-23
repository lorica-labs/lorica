use core::mem::size_of;

/// One byte, in the sub-byte units a bucket level is counted in.
///
/// The level is not counted in bytes because the drain of one update,
/// `per_sec * dt / 10^9`, is an integer division: it rounds down, and the shortfall
/// is charged to the burst. In whole bytes that shortfall reaches one byte per
/// packet, so a few hundred conformant packets whose gaps merely jitter around the
/// rate eat an MTU of burst and start being refused. Sub-byte units divide it by the
/// scale, and 512 is the scale that costs nothing: `10^9 = 2^9 * 1953125`, so the
/// nanosecond conversion and the unit conversion collapse into one division by one
/// constant, the same single instruction the byte version needs.
pub const UNITS_PER_BYTE: u64 = 512;

/// `10^9 / UNITS_PER_BYTE`: nanoseconds per drained unit at one byte per second.
const NS_PER_UNIT: u64 = 1_953_125;

/// Largest burst honoured; a larger one is clamped to it.
///
/// A burst above 16 GiB is not a rate limit. Clamping it closes the arithmetic:
/// `per_sec * dt` saturates for a long enough gap, and the saturated quotient
/// (`u64::MAX / NS_PER_UNIT`, about 9.4e12 units) has to stay above every reachable
/// level (`BURST_MAX * UNITS_PER_BYTE`, 8.8e12 units) or an idle bucket configured
/// with an absurd burst would fail to drain.
pub const BURST_MAX: u64 = 1 << 34;

/// A leak rate, in bytes per second, and the burst it tolerates, in bytes.
///
/// `per_sec == 0` and `burst == 0` are both reachable configurations and both mean
/// refuse everything; neither is a division by zero, because the only division in
/// the update is by `NS_PER_UNIT`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rate {
    pub per_sec: u64,
    pub burst: u64,
}

/// Level of one leaky bucket and the clock reading it was last drained at.
///
/// Exactly two `u64` and nothing else. A `bpf_spin_lock` cannot live here anyway:
/// `map_check_btf()` accepts one only in the value of a HASH, an ARRAY or a storage
/// map, never a `BPF_MAP_TYPE_PERCPU_ARRAY`. And a per-CPU bucket needs no
/// synchronisation at all, because driver XDP runs inside a single NAPI poll under
/// `local_bh_disable()` and softirq processing does not nest on a CPU. A shared bank
/// wraps this type on the kernel side, where the aya lock exists.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bucket {
    /// In units of `1 / UNITS_PER_BYTE` byte. Never in bytes.
    pub level: u64,
    pub last_ns: u64,
}

const _: () = assert!(size_of::<Bucket>() == 16);

/// Whether the packet fit under the burst. `Over` means the bucket was left as the
/// drain found it and this packet was not charged to it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub enum Charge {
    Within,
    Over,
}

/// `a * b`, saturating, computed in halves so nothing ever asks for a 128-bit product.
///
/// `u64::saturating_mul` is the same function and does not compile for this program. It
/// becomes `umul.with.overflow.i64`, BPF has no 64-by-64-to-128 multiply, and LLVM answers
/// with a call to `__multi3` that compiler-builtins does not provide for the target: the
/// object comes out carrying an undefined symbol and aya refuses to relocate the caller.
/// Writing the check as `dt != 0 && per_sec > u64::MAX / dt` does not help either —
/// InstCombine recognises that idiom and folds it straight back into the same intrinsic.
/// Splitting the operands keeps every partial product inside 64 bits, and costs no
/// division and no call on the packet path.
const fn saturating_mul(a: u64, b: u64) -> u64 {
    const HALF: u64 = u32::MAX as u64;
    let (a_hi, a_lo) = (a >> 32, a & HALF);
    let (b_hi, b_lo) = (b >> 32, b & HALF);

    // `a_hi * b_hi` weighs 2^64, so one bit in each high half is already too much.
    if a_hi != 0 && b_hi != 0 {
        return u64::MAX;
    }
    // One of the two terms is therefore zero, so the sum fits; it weighs 2^32, so it has
    // to fit in a half for the shift below not to lose the top of it.
    let mid = a_hi * b_lo + a_lo * b_hi;
    if mid > HALF {
        return u64::MAX;
    }
    match (a_lo * b_lo).checked_add(mid << 32) {
        Some(product) => product,
        None => u64::MAX,
    }
}

impl Bucket {
    /// Drains for the time elapsed since the last packet, then charges this one if
    /// the result stays under the burst.
    ///
    /// An over-budget packet is deliberately not charged. Charging it would pin the
    /// level at the ceiling for as long as a flood lasts and keep dropping
    /// legitimate traffic after it stops, and it would leave the level unbounded,
    /// which is the only way this arithmetic could overflow.
    pub fn charge(&mut self, rate: Rate, now_ns: u64, size: u32) -> Charge {
        // The clock is read per packet on the CPU that handles the packet and is not
        // monotonic across cores, so a reading from the past becomes a gap of zero
        // and never a huge unsigned one. `last_ns` is a high-water mark for the same
        // reason: moving it backwards would hand the next packet the drain of a gap
        // that never elapsed.
        let dt = now_ns.saturating_sub(self.last_ns);
        self.last_ns = self.last_ns.max(now_ns);

        // Saturating rather than wrapping: the eBPF crate builds with
        // overflow-checks off, so a wrap there would be silent, and a saturated
        // product means a gap long enough to empty any level `BURST_MAX` allows.
        let drained = saturating_mul(rate.per_sec, dt) / NS_PER_UNIT;
        self.level = self.level.saturating_sub(drained);

        let ceiling = rate.burst.min(BURST_MAX) * UNITS_PER_BYTE;
        let cost = u64::from(size) * UNITS_PER_BYTE;
        if self.level + cost > ceiling {
            Charge::Over
        } else {
            self.level += cost;
            Charge::Within
        }
    }
}
