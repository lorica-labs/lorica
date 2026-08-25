//! Application-level latency for the two workloads Lorica claims to protect.
//!
//! The measurement chain the whitepaper will rest on: a calibrated TSC, kernel
//! software receive timestamps, HdrHistogram percentiles, and an explicit record
//! of every reason the numbers might be wrong.

pub mod clock;
pub mod gap;
pub mod profile;
pub mod report;
