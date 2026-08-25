//! SipHash-2-4, reimplemented here because every index an attacker can influence
//! has to be keyed with a secret drawn at boot, and because the same code has to
//! compile into the eBPF program and into the tests.

/// Keyed 64-bit SipHash-2-4. The key is the boot secret: two attackers-chosen inputs
/// that collide under one key do not collide under the next boot.
#[derive(Clone, Copy)]
pub struct SipHasher24 {
    k0: u64,
    k1: u64,
}

macro_rules! sipround {
    ($v0:ident, $v1:ident, $v2:ident, $v3:ident) => {
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13);
        $v1 ^= $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17);
        $v1 ^= $v2;
        $v2 = $v2.rotate_left(32);
    };
}

impl SipHasher24 {
    pub const fn new(key: [u64; 2]) -> Self {
        Self {
            k0: key[0],
            k1: key[1],
        }
    }

    /// Reads a 16-byte secret as the two little-endian words the reference vectors
    /// use. The byte order lives in [`super::key_words`], which both keyed hashes and
    /// the loader share.
    pub const fn from_bytes(key: [u8; 16]) -> Self {
        Self::new(super::key_words(key))
    }

    pub fn hash(&self, bytes: &[u8]) -> u64 {
        let mut v0 = self.k0 ^ 0x736f_6d65_7073_6575;
        let mut v1 = self.k1 ^ 0x646f_7261_6e64_6f6d;
        let mut v2 = self.k0 ^ 0x6c79_6765_6e65_7261;
        let mut v3 = self.k1 ^ 0x7465_6462_7974_6573;

        let (words, tail) = bytes.as_chunks::<8>();
        for chunk in words {
            let m = u64::from_le_bytes(*chunk);
            v3 ^= m;
            sipround!(v0, v1, v2, v3);
            sipround!(v0, v1, v2, v3);
            v0 ^= m;
        }

        // The last word carries the trailing bytes in the low positions and the
        // total length in the top one. Without the length, "ab" and "ab\0" would
        // hash the same.
        let mut b = (bytes.len() as u64) << 56;
        let mut i = 0;
        while i < tail.len() {
            b |= (tail[i] as u64) << (8 * i);
            i += 1;
        }
        v3 ^= b;
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);
        v0 ^= b;

        v2 ^= 0xff;
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);

        v0 ^ v1 ^ v2 ^ v3
    }
}
