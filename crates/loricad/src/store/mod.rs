//! What survives a restart, and what a restart is allowed to cost.
//!
//! Two things are persisted and they share nothing but this module. The mitigation state
//! is tiny, rewritten every tick, and its whole difficulty is how often it is flushed. The
//! operator blocklist is large, rewritten rarely, and its whole difficulty is what kind of
//! page it lands on.
//!
//! **The engine is worth a factor of two, the hardening cadence a factor of two hundred.**
//! One `Durability::None` commit costs redb 7 us and SQLite 15 us. One `fsync` per tick
//! takes redb to 1448 us and SQLite to 2638 us. So the engine choice — redb, one thread,
//! no C dependency, 3 MiB of RSS, 17 us to open — is the small half of this decision, and
//! the cadence is the half [`state`] exposes as a parameter.
//!
//! Nothing here is reached from `main` yet: the tick that calls it lands separately.

#![allow(dead_code)]

pub mod blocklist;
pub mod state;
