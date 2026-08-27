//! What survives a restart, and what a restart is allowed to cost.
//!
//! Two things are persisted and they share nothing but this module. The mitigation state
//! is tiny, rewritten every tick, and its whole difficulty is how often it is flushed. The
//! operator blocklist is large, rewritten rarely, and its whole difficulty is what kind of
//! page it lands on.
//!
//! **The hardening cadence is worth two orders of magnitude and the engine is not.** Measured
//! on carapace-dev, release, ext4, redb 2.6.3: the same commit costs 45.4 us without `fsync`
//! and 3487 us with it. Re-measured on redb 4.2.0 the gap is wider, not narrower — 4.0 us
//! against 1447 — because the upgrade made the cheap commit 4.4x faster and left the `fsync`
//! exactly where the disk put it. Every engine in the running is within a small factor of
//! every other on the first number and none of them can do anything about the second, so the
//! engine choice — redb, one thread, no C dependency — is the small half of this decision and
//! the cadence is the half [`state`] exposes as a parameter, at one second by default.
//!
//! Nothing here is reached from `main` yet: the tick that calls it lands separately.

#![allow(dead_code)]

pub mod blocklist;
pub mod state;
