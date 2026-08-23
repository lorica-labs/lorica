//! Keyed hashing for every index an attacker can influence.
//!
//! `fast.rs` holds an unkeyed hash, and holds it for one consumer only: the adversarial
//! test of the bucket index needs a weak hash to build collisions against before it can
//! show that the keyed hash spreads them. It must never index anything an attacker can
//! choose. Every such index in this program goes through [`SipHasher24`] with a secret
//! drawn at load.

pub mod fast;
mod siphash;

pub use fast::fast_hash;
pub use siphash::SipHasher24;
