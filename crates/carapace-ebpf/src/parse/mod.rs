//! Parsing, once per packet, into the view every stage consumes.
//!
//! The reference kernel selftest lets VLAN traffic and IPv6 extension headers
//! through as a silent `XDP_PASS`, commented `XXX` upstream. Not reproducing those
//! two bypasses is what this module is for.

pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod l4;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use carapace_common::{CounterId, Family, FragState, MAX_OFFSET, PacketView};

#[derive(Clone, Copy)]
pub enum ParseError {
    /// A header the parser needed reaches past the end of the packet.
    Truncated,
    /// More encapsulation than the hard bound allows. An explicit policy with a
    /// counter, never an implicit pass: that bypass is the whole point of the module.
    DepthExceeded,
    /// Not something this pipeline judges, such as ARP or LLDP.
    UnknownEncap,
    /// Parseable bytes that cannot describe a packet, such as an IPv4 header length
    /// below its own fixed part.
    Malformed,
}

impl ParseError {
    /// Verdict and counter. `UnknownEncap` passes on purpose: dropping ARP would
    /// break the network the pipeline is supposed to protect, and non-IP traffic is
    /// not what this program judges.
    pub const fn outcome(self) -> (u32, CounterId) {
        match self {
            Self::Truncated => (xdp_action::XDP_DROP, CounterId::ParseTruncated),
            Self::DepthExceeded => (xdp_action::XDP_DROP, CounterId::ParseDepthExceeded),
            Self::UnknownEncap => (xdp_action::XDP_PASS, CounterId::ParseUnknownEncap),
            Self::Malformed => (xdp_action::XDP_DROP, CounterId::SanityIpLength),
        }
    }
}

/// What the network layer contributes, handed back rather than written through a
/// pointer.
///
/// The parsers used to take `&mut PacketView` and fill a zeroed struct in stages. The
/// zeroing was a 60-byte memset on every packet — 15.8 % of all cycles in a profile —
/// and no optimiser could remove it, because each parser was a call and the stores
/// happened on the other side of the boundary. Each layer returning its own small
/// result is what lets `parse` build the view once, in one struct literal, with every
/// field named.
pub struct L3 {
    pub family: Family,
    pub src: [u8; 16],
    pub ip_total_len: u16,
    pub frag: FragState,
    pub proto: u8,
    pub l4_off: usize,
    pub anomalies: u8,
}

/// The packet window.
///
/// Not a `&[u8]`: the verifier tracks the start and the end of a packet as two
/// separate registers and only recognises a read as a packet access when it is
/// guarded by a comparison against the end register. A slice would hide exactly the
/// comparison the kernel demands to see.
#[derive(Clone, Copy)]
pub struct Window {
    pub start: usize,
    pub end: usize,
}

impl Window {
    #[inline(always)]
    pub fn of(ctx: &XdpContext) -> Self {
        Self {
            start: ctx.data(),
            end: ctx.data_end(),
        }
    }

    #[inline(always)]
    pub fn total_len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Reads a fixed-size run of bytes at a bounds-checked offset.
    ///
    /// `N` is at least two, and that is a verifier constraint rather than a taste.
    /// For `N == 1` the compiler rewrites `at + 1 > end` into the equivalent
    /// `at >= end`, which folds the constant offset into the pointer register;
    /// `find_good_pkt_pointers` then refuses to grant a range to a packet pointer
    /// whose constant offset is zero, and every single-byte read at a variable
    /// offset is rejected. Reading a whole header in one go and taking fields out of
    /// the array is both the way around it and one bound check instead of six.
    #[inline(always)]
    pub fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        const {
            assert!(
                N >= 2,
                "a one-byte read at a variable offset cannot be verified"
            )
        };
        if off > MAX_OFFSET {
            return None;
        }
        let at = self.start + off;
        if at + N > self.end {
            return None;
        }
        // SAFETY: the comparison above is the shape the verifier recognises for a
        // packet access, and `[u8; N]` has alignment 1, so this cannot become an
        // unaligned load whatever the offset.
        Some(unsafe { *(at as *const [u8; N]) })
    }

    #[inline(always)]
    pub fn be16(&self, off: usize) -> Option<u16> {
        self.bytes::<2>(off).map(u16::from_be_bytes)
    }
}

pub fn parse(ctx: &XdpContext) -> Result<PacketView, ParseError> {
    let win = Window::of(ctx);
    let l2 = eth::parse(&win)?;
    let l3 = match l2.ethertype {
        eth::ETH_P_IP => ipv4::parse(&win, l2.l3_off)?,
        eth::ETH_P_IPV6 => ipv6::parse(&win, l2.l3_off)?,
        _ => return Err(ParseError::UnknownEncap),
    };
    let l4 = l4::parse(&win, &l3)?;

    Ok(PacketView {
        data: win.start as u64,
        data_end: win.end as u64,
        src: l3.src,
        l3_off: l2.l3_off as u16,
        l4_off: l3.l4_off as u16,
        payload_off: (l3.l4_off + l4.hdr_len) as u16,
        sport: l4.sport,
        dport: l4.dport,
        ip_total_len: l3.ip_total_len,
        l4_len: l4.l4_len,
        packet_len: win.total_len().min(u16::MAX as usize) as u16,
        family_raw: l3.family as u8,
        proto: l3.proto,
        frag_raw: l3.frag as u8,
        tcp_flags: l4.tcp_flags,
        icmp_type: l4.icmp_type,
        icmp_code: l4.icmp_code,
        anomalies: l3.anomalies,
        vlan_tags: l2.vlan_tags,
    })
}
