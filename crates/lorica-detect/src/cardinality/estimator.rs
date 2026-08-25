//! Distinct sources, read off a bank that was never built to count them.
//!
//! **Why the bucket bank is already a sketch.** The bank index is the top `log2(m)` bits of
//! a keyed hash of the source address — see
//! [`BankLayout::index`](lorica_common::BankLayout::index) — so which buckets are occupied
//! is a uniform hash signature of the active source set. That is exactly the input
//! linear counting takes: with `m` buckets and `v` of them still empty, the number of
//! distinct keys that produced the occupancy is `-m ln(v/m)`. Whang, Vander-Zanden and
//! Taylor, 1990. No register array, no second map, and no extra byte read per tick, because
//! the tick already reads the bank.
//!
//! **The alternative that was rejected, with its number.** HyperLogLog++, of which
//! `cloudflare/cardinality-estimator` is the production precedent worth citing. It is the
//! right structure when the cardinality can exceed the register count by orders of
//! magnitude — that is what the harmonic mean of leading-zero counts buys. Here it would
//! cost a **new map of 1024 six-bit registers, 768 bytes, plus one more batch read on every
//! tick**, to estimate a quantity the 1024 buckets already in the tick's read path estimate
//! for zero bytes. What is given up is the range: linear counting loses resolution as the
//! bank fills and has none at all once every bucket is occupied, where HLL keeps answering.
//! [`distinct_sources`] answers `None` there rather than a number, which is the honest end
//! of the estimator's range and is itself a signal — see
//! [`Verdict::spoofed`](super::Verdict::spoofed).
//!
//! **What is not implemented here, deliberately.** SegSketch (WWW 2026) is a candidate to
//! re-verify against its primary source, not a dependency: its authors do not evaluate its
//! robustness, which makes it a subject for an adversarial chapter rather than a brick in a
//! mitigation path. Nothing in this file rests on it.

use lorica_common::SHARE_SCALE;

/// Buckets occupied, from the share [`BucketView::loaded_share`](crate::snapshot::
/// BucketView::loaded_share) answers at a level of zero.
///
/// `buckets` is a parameter because `BucketView` publishes shares and not its own length,
/// and a share cannot be turned back into a count without it. The caller's default is
/// [`DEFAULT_BANK_BUCKETS`](lorica_common::DEFAULT_BANK_BUCKETS), which is the number the
/// kernel side declares.
pub const fn occupied(share: u32, buckets: u32) -> u32 {
    ((share as u64 * buckets as u64) / SHARE_SCALE as u64) as u32
}

/// Distinct sources behind an occupancy, or `None` when the bank is full.
///
/// The estimate is always at or above `occupied`: collisions are what the logarithm
/// corrects for, and at half occupancy on 1024 buckets it corrects 512 up to 709.
pub fn distinct_sources(occupied: u32, buckets: u32) -> Option<u64> {
    if buckets == 0 || occupied >= buckets {
        return None;
    }
    let m = f64::from(buckets);
    let empty = f64::from(buckets - occupied);
    // Truncating and not rounding: the estimate is a lower shelf the decision above
    // compares against a threshold, and rounding up would be the one direction that
    // manufactures a source nobody observed.
    Some((-m * (empty / m).ln()) as u64)
}
