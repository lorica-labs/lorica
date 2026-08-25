use core::mem::size_of;

/// One byte, in the sub-byte units a bucket level is counted in.
///
/// The level is not counted in bytes because the drain of one update rounds down and the
/// shortfall is charged to the burst. In whole bytes that shortfall reaches one byte per
/// packet, so a few hundred conformant packets whose gaps merely jitter around the rate eat
/// an MTU of burst and start being refused. Sub-byte units divide it by the scale, and this
/// scale keeps it under 1/512 byte per update, which is the same answer to the same argument
/// as before.
///
/// 512 used to be the scale for a second reason that has expired: `10^9 = 2^9 * 1953125`,
/// so against a *nanosecond* clock the time conversion and the unit conversion collapsed
/// into one division by 1953125. The clock is `bpf_jiffies64` and the conversion is
/// [`Drain::per_jiffy`], in userspace, once per load. What the scale still has to be is a
/// power of two, because it reaches the packet path as `<< 9` in the cost and in the
/// ceiling.
pub const UNITS_PER_BYTE: u64 = 512;

/// Fractional bits the [`Drain`] word carries, and the whole reason [`Bucket::charge`] has
/// no division left in it.
///
/// The drain of one update is `drain * dt` scaled down. Any scale is available, because the
/// word is built in userspace and can carry whatever fixed point suits the kernel side, and
/// a power of two is the only kind that costs one cycle: BPF has no 64-by-64-to-128
/// multiply, so LLVM cannot turn a division by a constant into a reciprocal multiply on this
/// target however constant the constant is — it emits a real `BPF_DIV` and the x86 JIT emits
/// a real `div`, tens of cycles and not pipelined, on the dependency chain of every packet.
///
/// 20 fractional bits and not more, because the saturated quotient has to stay above every
/// reachable level: see [`BURST_MAX`]. Not fewer either, because these bits are the
/// precision of the *rate* and not of the level: the word for one byte per second at 1000 Hz
/// is 536870, so the configured rate is honoured to 2e-6 of itself, and every bit dropped
/// here doubles that.
pub const DRAIN_FRACTION_BITS: u32 = 20;

/// Largest burst honoured; a larger one is clamped to it.
///
/// A burst above 16 GiB is not a rate limit. Clamping it closes the arithmetic:
/// `drain * dt` saturates for a long enough gap, and the saturated quotient
/// (`u64::MAX >> DRAIN_FRACTION_BITS`, 1.76e13 units) has to stay above every reachable
/// level (`BURST_MAX * UNITS_PER_BYTE`, 8.8e12 units) or an idle bucket configured
/// with an absurd burst would fail to drain. The margin is a factor of two, where the
/// division this shift replaced left 1.07.
pub const BURST_MAX: u64 = 1 << 34;

/// A leak, and the burst it tolerates, in bytes.
///
/// A zero drain and a zero burst are both reachable configurations and both mean refuse
/// everything; neither is a division by zero, because there is no division in the update
/// at all.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rate {
    pub drain: Drain,
    pub burst: u64,
}

/// How fast one bucket leaks, against the clock [`Bucket::charge`] is handed: bucket units
/// per tick of that clock, in fixed point with [`DRAIN_FRACTION_BITS`] fractional bits so
/// the update is one multiply and one shift.
///
/// **A newtype and not the `u64` it wraps, because the `u64` was called `per_sec` and was
/// read as bytes per second.** The data path hands `charge` `bpf_jiffies64` — 4 ns against
/// the 54 of `bpf_ktime_get_ns`, which is why it reads jiffies at all — and a jiffy is 1 to
/// 4 ms, so every drain was out by about a factor of a million. Nothing caught it: the one
/// test with a real rate converted at its own call site, and the conversion factor for a
/// nanosecond clock is 1. There is now no way to build one of these without naming the tick
/// it is built for, and the conversion happens once per load in userspace.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Drain(u64);

impl Drain {
    /// Never leaks. The strictest configuration there is, and what a case about a burst
    /// wants: a bucket that does not drain admits exactly its burst whatever the clock does.
    pub const NONE: Self = Self(0);

    /// From bytes per second — what an operator configures — for a `charge` whose clock
    /// counts jiffies, which is the data path's clock and the only one that ships.
    ///
    /// `hz` is measured through `CLOCK_PROBE`, because the kernel exports neither
    /// `CONFIG_HZ` nor the counter. The factor is the units one byte per second leaks in one
    /// jiffy, in the fixed point `charge` shifts back out: `UNITS_PER_BYTE << 20` over `hz`.
    /// The factor rounds down, so the error is relative and the same at every rate: 1.7e-6 at
    /// 1000 Hz, its worst case, where the division it replaced was exact at 100, 250 and 1000
    /// and 3.3e-8 low at 300. Both are orders below the tolerance the rate itself is
    /// recognised to, and both round down, which is the direction that never leaks. This
    /// division is in userspace: the kernel side sees only the word.
    ///
    /// Saturating, because the unconfigured budget the program carries is `u64::MAX` and
    /// scaling it must not wrap into a strict one.
    pub const fn per_jiffy(bytes_per_sec: u64, hz: u32) -> Self {
        let hz = if hz == 0 { 1 } else { hz as u64 };
        Self(saturating_mul(
            bytes_per_sec,
            (UNITS_PER_BYTE << DRAIN_FRACTION_BITS) / hz,
        ))
    }

    /// From bytes per second, for a `charge` whose clock counts nanoseconds. No clock in the
    /// program is this one, and the properties of the arithmetic are stated against it.
    ///
    /// No power of two divides `10^9`, so this conversion cannot be exact whatever the level
    /// unit is — which is the whole reason the *kernel* side no longer performs it. The
    /// product is taken first so the rounding is relative rather than a floor on the factor,
    /// and it rounds down: the conservation property is stated as never draining more than
    /// the rate owed, and rounding to nearest breaks it by a few bytes over a long run. One
    /// byte per second is under half a unit per nanosecond-tick and scales to a drain of
    /// zero, which no jiffy rate does and which only a nanosecond clock could ask for.
    pub const fn per_nanosecond(bytes_per_sec: u64) -> Self {
        Self(saturating_mul(bytes_per_sec, UNITS_PER_BYTE << DRAIN_FRACTION_BITS) / 1_000_000_000)
    }

    /// The scaled word itself.
    ///
    /// It crosses into the program's `.rodata` as a bare `u64` and comes back out as one,
    /// and apportioning it across shards is linear, so both need the number without the
    /// type. Nothing else does: `from_raw` on a byte rate is the mistake this type exists
    /// to prevent.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn into_raw(self) -> u64 {
        self.0
    }
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
    /// The clock reading of the last update, in whatever tick the [`Drain`] was built
    /// against. Jiffies in the program.
    pub last_tick: u64,
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
    /// `now` is in the ticks `rate.drain` was built against, and the type is where that is
    /// said: nothing here can tell a jiffy from a nanosecond.
    pub fn charge(&mut self, rate: Rate, now: u64, size: u32) -> Charge {
        // The clock is read per packet on the CPU that handles the packet and is not
        // monotonic across cores, so a reading from the past becomes a gap of zero
        // and never a huge unsigned one. `last_tick` is a high-water mark for the same
        // reason: moving it backwards would hand the next packet the drain of a gap
        // that never elapsed.
        let dt = now.saturating_sub(self.last_tick);
        self.last_tick = self.last_tick.max(now);

        // Saturating rather than wrapping: the eBPF crate builds with
        // overflow-checks off, so a wrap there would be silent, and a saturated
        // product means a gap long enough to empty any level `BURST_MAX` allows.
        //
        // A shift and not a division. This is the only arithmetic on the packet path that
        // was ever a `BPF_DIV`, and a `div` the x86 JIT cannot pipeline sat on the
        // dependency chain between the load and the store of the bucket.
        let drained = saturating_mul(rate.drain.into_raw(), dt) >> DRAIN_FRACTION_BITS;
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
