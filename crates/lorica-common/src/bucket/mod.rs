//! Leaky-bucket arithmetic: `c <- max(c - rho*dt, 0) + size`.
//!
//! No sketch and no periodic reset. A sketch zeroes on a cadence of its own, and a
//! zeroing that lands mid-burst forgets exactly the traffic it was there to measure.
//! This bank never resets; a bucket that stops receiving simply drains to zero.

mod bank;
mod leaky;

pub use bank::{BANK_SLOT_BYTES, BankLayout, DEFAULT_BANK_BUCKETS, SHARE_SCALE};
pub use leaky::{BURST_MAX, Bucket, Charge, Drain, Rate, UNITS_PER_BYTE};
