//! Keyed hashing for every index an attacker can influence.
//!
//! `fast.rs` of the tree layout is deliberately absent: an unkeyed hash is only
//! admissible for an index no attacker can choose, and this phase has none.

mod siphash;

pub use siphash::SipHasher24;
