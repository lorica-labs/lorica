//! What survives a restart, and what a restart is allowed to cost.
//!
//! Two things are persisted and they share nothing but this module. The mitigation state
//! is tiny, rewritten every tick, and its whole difficulty is how often it is flushed. The
//! operator blocklist is large, rewritten rarely, and its whole difficulty is what kind of
//! page it lands on.
//!
//! **The hardening cadence is worth a factor of 77 and the engine is not.** Measured on
//! carapace-dev, release, ext4: the same commit costs 45.4 us without `fsync` and 3487 us
//! with it. Every engine in the running is within a small factor of every other on the first
//! number and none of them can do anything about the second, so the engine choice — redb, one
//! thread, no C dependency — is the small half of this decision and the cadence is the half
//! [`state`] exposes as a parameter.
//!
//! Nothing here is reached from `main` yet: the tick that calls it lands separately.

#![allow(dead_code)]

pub mod blocklist;
pub mod state;
