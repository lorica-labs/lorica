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
/// and extension header chains. The sanity stage turns these into verdicts; the
/// parser states no policy.
pub mod anomaly {
    pub const IP_OPTIONS_PRESENT: u8 = 1 << 0;
    pub const IPV6_EXT_PRESENT: u8 = 1 << 1;
}

/// Everything a stage decides on, built once per packet.
///
/// Scalars and two addresses, and deliberately no packet pointer: a stage able to
/// reach back into the packet would re-parse, and a packet pointer crossing a
/// bpf-to-bpf call boundary is the kind of thing the verifier changes its mind about
/// between kernel versions. Offsets are `u32` rather than `usize` so the layout does
/// not depend on the width of the target.
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
    pub dst: [u8; 16],
    pub l3_off: u32,
    pub l4_off: u32,
    pub sport: u16,
    pub dport: u16,
    /// Length the IP header claims, fixed header included on both families, for the
    /// sanity stage to compare against what arrived.
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
    pub fn zeroed() -> Self {
        // SAFETY: every byte pattern is a valid value of this type, and going through
        // zeroed also initialises the tail padding, which is copied verbatim into a
        // map by the instrumented build.
        unsafe { core::mem::zeroed() }
    }

    pub const fn family(&self) -> Family {
        if self.family_raw == Family::V4 as u8 {
            Family::V4
        } else {
            Family::V6
        }
    }

    pub const fn set_family(&mut self, family: Family) {
        self.family_raw = family as u8;
    }

    pub const fn frag(&self) -> FragState {
        match self.frag_raw {
            0 => FragState::None,
            1 => FragState::First,
            _ => FragState::Later,
        }
    }

    pub const fn set_frag(&mut self, frag: FragState) {
        self.frag_raw = frag as u8;
    }

    pub const fn has(&self, anomaly: u8) -> bool {
        self.anomalies & anomaly != 0
    }
}
