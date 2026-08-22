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
use carapace_common::{CounterId, FragState, PacketView};

/// Largest header offset the parser will look at: a 9216-byte jumbo frame.
///
/// The value is not cosmetic. `find_good_pkt_pointers` refuses to grant a range when
/// the verifier upper estimate of the offset plus the size of the read exceeds
/// MAX_PACKET_OFF, which is 0xffff. Bounding the offset here is what keeps that sum
/// inside the limit, and a bound of 0xffff sat exactly on it: every read was refused.
/// No header offset in a frame this pipeline sees can reach it, so nothing legitimate
/// is lost.
pub const MAX_OFFSET: usize = 9216;

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

    let mut view = PacketView::zeroed();
    view.packet_len = win.total_len().min(u16::MAX as usize) as u16;
    view.l3_off = l2.l3_off as u32;
    view.vlan_tags = l2.vlan_tags;
    view.set_frag(FragState::None);

    match l2.ethertype {
        eth::ETH_P_IP => ipv4::parse(&win, &mut view)?,
        eth::ETH_P_IPV6 => ipv6::parse(&win, &mut view)?,
        _ => return Err(ParseError::UnknownEncap),
    }

    l4::parse(&win, &mut view)?;
    Ok(view)
}
