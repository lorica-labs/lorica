/// Bits an IPv4 address sits behind in the unified key. `::ffff:0:0/96` is reserved
/// by RFC 4291, so no legitimate IPv6 prefix can collide with the mapped range and
/// one trie can hold both families behind one lookup.
pub const V4_MAPPED_PREFIX_BITS: u32 = 96;

/// Key of the unified list. `prefix_len` first and as a `u32` is what the kernel
/// LPM_TRIE requires, not a choice.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LpmKey {
    pub prefix_len: u32,
    pub addr: [u8; 16],
}

impl LpmKey {
    pub const fn v6(addr: [u8; 16], prefix_len: u32) -> Self {
        Self { prefix_len, addr }
    }

    pub const fn v4(addr: [u8; 4], prefix_len: u32) -> Self {
        Self {
            prefix_len: V4_MAPPED_PREFIX_BITS + prefix_len,
            addr: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr[0], addr[1], addr[2], addr[3],
            ],
        }
    }

    /// Single host, the form the data path builds for every packet.
    pub const fn host_v6(addr: [u8; 16]) -> Self {
        Self::v6(addr, 128)
    }

    pub const fn host_v4(addr: [u8; 4]) -> Self {
        Self::v4(addr, 32)
    }
}
