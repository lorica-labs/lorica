//! Multiply-shift, keyed, for the index of the bucket bank.
//!
//! **What it replaced, and what that cost.** SipHash-2-4 on this one index measured 61 to
//! 73 ns of a 210 ns pipeline on the 901 — a third of the whole program, on a legitimate
//! path this phase had just taken from 243 ns to 81 ns. The price is structural rather than
//! a coding defect: BPF has no rotate instruction, so each of the six rotations of a
//! sipround becomes a shift, a shift and an or, and a 16-byte input runs ten siprounds.
//! What is here instead is two multiplies, an add and a shift, and the shift is taken by
//! [`BankLayout::index`](crate::BankLayout::index).
//!
//! **Why 2-universality is the whole requirement.** What the key defends against is
//! offline chosen-collision construction: an attacker who can compute the index picks
//! addresses that land in the bucket a chosen legitimate source lands in, and starves that
//! source alongside their own traffic. Two-universality answers exactly that — two distinct
//! addresses collide with probability 1/m whatever the attacker picks, m being the bucket
//! count — and the requirement is narrower than it looks because of an asymmetry: an
//! attacker who merely makes *their own* addresses collide gains nothing, since sources
//! sharing a bucket share one budget and are therefore limited harder.
//!
//! **What was traded away.** This is not cryptographic and does not claim to be. It does
//! not resist key recovery from observed outputs, and SipHash-2-4 does. That margin is
//! judged not worth a third of the program here because the only oracle for an output is
//! behavioural — "was my packet refused alongside this other source?" — which costs the
//! attacker real traffic per query, answers noisily, and is rate-limited by the very stage
//! being probed. Anything that needs more than 2-universality goes to
//! [`SipHasher24`](super::SipHasher24), which is still in the tree.

/// Keyed multiply-shift over the two 64-bit words of a 16-byte address.
///
/// Dietzfelbinger's multiply-shift, extended to a vector of words the way Thorup states it.
/// Only the low 64 bits of each product are needed, which is the one multiply BPF does
/// cheaply, and only the **high** bits of the sum are usable: the low bits of a wrapping
/// multiply are weak, and taking the top `log2(m)` bits is what the 2-universality proof is
/// about. Reducing this output with a mask or a modulo would keep the wrong end of it.
#[derive(Clone, Copy)]
pub struct MultiplyShift {
    k0: u64,
    k1: u64,
}

impl MultiplyShift {
    /// The two key words, forced odd.
    ///
    /// Forced here and not where the key is drawn, because an even multiplier breaks the
    /// guarantee silently and one in two random words is even: the type that rests on the
    /// property is the one that has to enforce it, whichever path the key arrived by.
    pub const fn new(key: [u64; 2]) -> Self {
        Self {
            k0: key[0] | 1,
            k1: key[1] | 1,
        }
    }

    pub const fn from_bytes(key: [u8; 16]) -> Self {
        Self::new(super::key_words(key))
    }

    /// The hash of one address. Sixteen bytes exactly, because the only thing this indexes
    /// is a source address and a length would buy a loop nobody needs.
    ///
    /// An IPv4-mapped address carries zero in its first eight bytes, so on IPv4 traffic
    /// `k0` multiplies zero and `k1` alone keys the index. That is single-word
    /// multiply-shift, which is the form the bound is originally stated for and is not a
    /// weaker case of it; the second multiply earns itself on IPv6.
    pub const fn hash(&self, addr: &[u8; 16]) -> u64 {
        let w0 = u64::from_le_bytes([
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        ]);
        let w1 = u64::from_le_bytes([
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
        ]);
        self.k0
            .wrapping_mul(w0)
            .wrapping_add(self.k1.wrapping_mul(w1))
    }
}
