//! Keyed hashing for every index an attacker can influence.
//!
//! Two keyed hashes, and they are not interchangeable. [`MultiplyShift`] is 2-universal and
//! costs four instructions, which is what the bucket index takes: 2-universality is the
//! whole property that index needs, and the packet path cannot pay for more. [`SipHasher24`]
//! is the one to reach for wherever the key itself has to survive an attacker who sees
//! outputs; each file says what it does and does not promise.
//!
//! `fast.rs` holds an unkeyed hash, and holds it for one consumer only: the adversarial
//! test of the bucket index needs a weak hash to build collisions against before it can
//! show that the keyed hash spreads them. It must never index anything an attacker can
//! choose.

pub mod fast;
mod multiply_shift;
mod siphash;

pub use fast::fast_hash;
pub use multiply_shift::MultiplyShift;
pub use siphash::SipHasher24;

/// Reads a 16-byte secret as the two little-endian words both keyed hashes take.
///
/// One place decides the byte order, so a key read from `/dev/urandom` needs no decision at
/// the call site and the loader — which patches the two words into the program's `.rodata`
/// one `u64` at a time — cannot disagree with the program about which half is which.
pub const fn key_words(key: [u8; 16]) -> [u64; 2] {
    let mut k0 = 0u64;
    let mut k1 = 0u64;
    let mut i = 0;
    while i < 8 {
        k0 |= (key[i] as u64) << (8 * i);
        k1 |= (key[i + 8] as u64) << (8 * i);
        i += 1;
    }
    [k0, k1]
}
