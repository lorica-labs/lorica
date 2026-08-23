//! FNV-1a, unkeyed, for the one place an unkeyed hash is admissible.
//!
//! **Nothing an attacker can choose may be indexed with this.** It carries no key, so
//! the inputs that collide under it are the same inputs on every host and at every
//! boot, and finding ten thousand of them costs a loop. That property is exactly what
//! its only legitimate consumer wants: the adversarial test of the bucket index builds
//! its collisions against this hash and then shows the keyed hash spreads them. Reach
//! for [`super::SipHasher24`] for anything else — indexing the bucket bank with this
//! would hand an attacker one bucket to fill and the rest of the bank to walk past.

const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

pub const fn fast_hash(bytes: &[u8]) -> u64 {
    let mut hash = OFFSET_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}
