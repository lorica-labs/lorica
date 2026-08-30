/// Address family of a parsed packet.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4 = 0,
    V6 = 1,
}

/// Where a packet sits in a fragment train.
///
/// `Later` has no L4 header at all, so it carries no port and can never match a
/// scope. That is why it gets a stage of its own instead of dying silently in
/// sanity.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FragState {
    None = 0,
    First = 1,
    Later = 2,
}

/// What only the parser can see, because it is the only code that reads the option
/// and extension header chains. The sanity checks turn these into verdicts; the
/// parser states no policy.
pub mod anomaly {
    pub const IP_OPTIONS_PRESENT: u8 = 1 << 0;
    pub const IPV6_EXT_PRESENT: u8 = 1 << 1;
}

/// Largest header offset the parser will look at: a 9216-byte jumbo frame.
///
/// The value is not cosmetic. `find_good_pkt_pointers` refuses to grant a range when
/// the verifier upper estimate of the offset plus the size of the read exceeds
/// MAX_PACKET_OFF, which is 0xffff. Bounding the offset here is what keeps that sum
/// inside the limit, and a bound of 0xffff sat exactly on it: every read was refused.
/// No header offset in a frame this pipeline sees can reach it, so nothing legitimate
/// is lost.
///
/// It lives beside [`PacketView`] because both users of the bound need the same one:
/// the window the parser reads headers through, and the payload accessor below, whose
/// offset is a `u16` and would otherwise sit exactly on MAX_PACKET_OFF.
pub const MAX_OFFSET: usize = 9216;

/// Everything a stage decides on, built once per packet.
///
/// Scalars, one address, and the two packet pointers. The pointers were once left out
/// on the argument that a stage able to reach back into the packet would re-parse, and
/// that a packet pointer crossing a bpf-to-bpf call boundary is the kind of thing the
/// verifier changes its mind about between kernel versions. The second half was tested
/// and is false: `frame1: R1=pkt(...)` appears in the verifier log on 6.8, so a packet
/// pointer does cross the boundary. The first half was a real cost that turned into a
/// gap — the signature stage cannot read an A2S or a RakNet MAGIC without the packet,
/// so those vectors were decided on port and size alone. What replaces the argument is
/// [`PacketView::payload_bytes`]: one accessor, bounds-checked once, so no stage
/// re-parses and none hand-rolls the comparison the verifier demands.
///
/// Offsets are `u16` and the pointers `u64` so the layout does not depend on the width
/// of the target.
///
/// It lives in this crate rather than beside the parser because the instrumented
/// build writes it into a map for the tests to read, and a second declaration of the
/// same layout is exactly the drift the assertions here exist to prevent.
///
/// Every byte pattern is a valid value, which is what makes it safe to read back out
/// of a kernel map. That is why the family and the fragment state are stored raw and
/// decoded by total functions rather than kept as enums: an out-of-range enum
/// discriminant read from a map would be undefined behaviour.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PacketView {
    pub src: [u8; 16],
    pub l3_off: u16,
    pub l4_off: u16,
    /// The first byte after the L4 header, or the L4 offset when the packet carries no
    /// L4 header — a later fragment, or a protocol this parser writes no header for.
    /// One meaning, so a stage reading a signature never has to ask which.
    pub payload_off: u16,
    pub sport: u16,
    pub dport: u16,
    /// Length the IP header claims, fixed header included on both families, to compare
    /// against what arrived.
    pub ip_total_len: u16,
    /// Length the L4 header claims, when it carries one. Zero otherwise.
    pub l4_len: u16,
    pub packet_len: u16,
    pub family_raw: u8,
    pub proto: u8,
    pub frag_raw: u8,
    pub tcp_flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub anomalies: u8,
    pub vlan_tags: u8,
}

impl PacketView {
    /// A fixed-size run of payload bytes at `at` from the start of the payload.
    ///
    /// The one place a stage reaches back into the packet. `N` is at least two for the
    /// same reason [`MAX_OFFSET`] is 9216: for `N == 1` the compiler rewrites
    /// `ptr + 1 > end` into `ptr >= end`, which folds the offset into the register, and
    /// `find_good_pkt_pointers` grants no range to a packet pointer whose constant
    /// offset is zero. A four-byte MAGIC is readable; a one-byte type check at a
    /// variable offset is not, and never will be.
    #[inline(always)]
    pub fn payload_bytes<const N: usize>(
        &self,
        data: u64,
        data_end: u64,
        at: u16,
    ) -> Option<[u8; N]> {
        const {
            assert!(
                N >= 2,
                "a one-byte read at a variable offset cannot be verified"
            )
        };
        let off = self.payload_off as usize + at as usize;
        if off > MAX_OFFSET {
            return None;
        }
        let ptr = data as usize + off;
        if ptr + N > data_end as usize {
            return None;
        }
        // SAFETY: the comparison above is the shape the verifier recognises for a
        // packet access, and `[u8; N]` has alignment 1, so this cannot become an
        // unaligned load whatever the offset.
        Some(unsafe { *(ptr as *const [u8; N]) })
    }

    pub const fn family(&self) -> Family {
        if self.family_raw == Family::V4 as u8 {
            Family::V4
        } else {
            Family::V6
        }
    }

    pub const fn frag(&self) -> FragState {
        match self.frag_raw {
            0 => FragState::None,
            1 => FragState::First,
            _ => FragState::Later,
        }
    }

    pub const fn has(&self, anomaly: u8) -> bool {
        self.anomalies & anomaly != 0
    }
}
