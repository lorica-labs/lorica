//! Parsing, once per packet, into the view every stage consumes.
//!
//! The reference kernel selftest lets VLAN traffic and IPv6 extension headers
//! through as a silent `XDP_PASS`, commented `XXX` upstream. Not reproducing those
//! two bypasses is what this module is for.
//!
//! Two paths, one result. [`fast`] handles untagged IPv4 without options carrying UDP
//! or TCP, which is what a game server actually receives, in a straight line with one
//! bounds check. Everything else — tags, options, extension headers, later fragments —
//! goes to the walker, which is where the loops live. Nothing optional decides a
//! verdict, so the two paths build the same view for the same packet and [`refuse`]
//! then applies the same checks to both.

pub mod eth;
pub mod fast;
pub mod ipv4;
pub mod ipv6;
pub mod l4;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use lorica_common::{CounterId, Family, FragState, MAX_OFFSET, PacketView, anomaly};

use crate::{parse::l4::L4, settings};

#[derive(Clone, Copy)]
pub enum ParseError {
    /// A header the parser needed reaches past the end of the packet.
    Truncated,
    /// More encapsulation than the hard bound allows. An explicit policy with a
    /// counter, never an implicit pass: that bypass is the whole point of the module.
    DepthExceeded,
    /// Not something this pipeline judges, such as ARP or LLDP.
    UnknownEncap,
    /// An IP header that cannot describe the packet it arrived in: a header length
    /// below its own fixed part, or a total length that disagrees with what arrived.
    IpLength,
    /// A transport length that disagrees with what arrived.
    L4Length,
    /// A combination of TCP flags no endpoint produces, which makes it a scan and not
    /// traffic.
    TcpFlags,
    /// IP options present and the operator has not said they are acceptable. A policy
    /// and not a fact about the packet, which is why it is stated as one.
    IpOptions,
    /// The measurement build stopped the parse here. Absent from the object that ships,
    /// and intercepted by `stage::run` before `outcome` so that a cut level does not bump
    /// a counter the levels around it do not.
    #[cfg(feature = "stage-cutoff")]
    Cutoff,
}

impl ParseError {
    /// Verdict and counter. `UnknownEncap` passes on purpose: dropping ARP would
    /// break the network the pipeline is supposed to protect, and non-IP traffic is
    /// not what this program judges.
    ///
    /// The four sanity counters are here rather than in a stage because the checks are,
    /// but they keep their names: an operator dashboard reads them.
    pub const fn outcome(self) -> (u32, CounterId) {
        match self {
            Self::Truncated => (xdp_action::XDP_DROP, CounterId::ParseTruncated),
            Self::DepthExceeded => (xdp_action::XDP_DROP, CounterId::ParseDepthExceeded),
            Self::UnknownEncap => (xdp_action::XDP_PASS, CounterId::ParseUnknownEncap),
            Self::IpLength => (xdp_action::XDP_DROP, CounterId::SanityIpLength),
            Self::L4Length => (xdp_action::XDP_DROP, CounterId::SanityL4Length),
            Self::TcpFlags => (xdp_action::XDP_DROP, CounterId::SanityTcpFlags),
            Self::IpOptions => (xdp_action::XDP_DROP, CounterId::SanityIpOptionsRefused),
            // Never reached: `stage::run` matches this variant first. It is here because
            // the match is exhaustive and a wildcard would swallow a real variant added
            // later.
            #[cfg(feature = "stage-cutoff")]
            Self::Cutoff => (xdp_action::XDP_PASS, CounterId::ParseUnknownEncap),
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
/// result is what lets the walker build the view once, in one struct literal, with
/// every field named.
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

/// Ends the parse here when the measurement asked for one this deep.
///
/// A second macro rather than `stage::cut!` because this one returns a `Result` and that one
/// returns an action.
///
/// **There is one cut inside the parse and not three, and the verifier is why.** The split
/// this was written for was headers / view construction / checks, with `black_box` holding
/// each phase in place so the optimiser could not sink dead work past the branch. Passing
/// `black_box` a `&PacketView` forces the fifty-six bytes onto the stack, and the code after
/// it reads `u16` fields back out: the verifier refuses a fill narrower than the eight-byte
/// slot a spill occupies — `invalid size of register fill` — and the program does not load.
///
/// What that refusal says is the answer to the question the split was asking. The view never
/// touches memory in the shipped program; it lives in registers and `refuse` reads it there.
/// So "materialising the struct" is not a cost that exists to be measured, and the two
/// separable halves are the reading and the checking.
///
/// Nothing holds the loads in place, and nothing needs to: what the reading half costs is the
/// bounds comparisons, and those are control flow — `Window::bytes` returns `None` and the
/// parse returns an error — which the optimiser may not remove. Only the raw loads could sink,
/// and `stage_cost.rs` asserts that the two halves sum to the whole precisely so that a
/// reordering around the instrument shows up as a failing test rather than as a ventilation.
#[cfg(feature = "stage-cutoff")]
macro_rules! cut_parse {
    ($stages:expr) => {
        if crate::settings::stage_cutoff() == $stages {
            return Err(ParseError::Cutoff);
        }
    };
}

#[cfg(not(feature = "stage-cutoff"))]
macro_rules! cut_parse {
    ($stages:expr) => {};
}

pub fn parse(ctx: &XdpContext) -> Result<PacketView, ParseError> {
    let win = Window::of(ctx);
    let (l2, l3, l4) = match fast::headers(&win) {
        Some(headers) => headers,
        None => walk(&win)?,
    };
    let view = PacketView {
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
    };

    // Level 2: every header is read and the view is built. What is left is the checks, whose
    // cost used to be inside the one `parse` figure with no way to see it.
    cut_parse!(2);

    refuse(&view)?;
    Ok(view)
}

/// Every encapsulation the fast path declined: tags, options, extension headers, and
/// the fragments that carry no transport header at all. The loops of the module are all
/// here.
fn walk(win: &Window) -> Result<(eth::L2, L3, L4), ParseError> {
    let l2 = eth::parse(win)?;
    let l3 = match l2.ethertype {
        eth::ETH_P_IP => ipv4::parse(win, l2.l3_off)?,
        eth::ETH_P_IPV6 => ipv6::parse(win, l2.l3_off)?,
        _ => return Err(ParseError::UnknownEncap),
    };
    let l4 = l4::parse(win, &l3)?;
    Ok((l2, l3, l4))
}

/// The checks that used to be stage 1, applied here because they are comparisons on
/// fields the parse has just put in registers: paying a stage boundary and a second
/// load for them bought nothing. Malformed is still not the same as unwanted — a
/// fragmented packet is not malformed and goes to stage 4 — and the policy among them
/// is still stated as a policy.
fn refuse(view: &PacketView) -> Result<(), ParseError> {
    let ip_bytes = view.packet_len.saturating_sub(view.l3_off);
    let header_bytes = view.l4_off.saturating_sub(view.l3_off);

    // Both directions are inconsistencies. A total length below the headers that were
    // parsed describes an impossible packet; one above what arrived is a forged
    // length, because XDP sees the whole frame. A frame padded to the Ethernet
    // minimum is the legitimate case of a total length below what arrived, so only
    // the strict excess is refused.
    if view.ip_total_len < header_bytes || view.ip_total_len > ip_bytes {
        return Err(ParseError::IpLength);
    }

    if view.has(anomaly::IP_OPTIONS_PRESENT) && !settings::accept_ip_options() {
        return Err(ParseError::IpOptions);
    }

    // A later fragment carries no transport header, so there is no length and no flag
    // to be consistent about. It is stage 4 that decides its fate.
    if view.frag() == FragState::Later {
        return Ok(());
    }

    match view.proto {
        l4::IPPROTO_UDP => udp_length(view),
        l4::IPPROTO_TCP if !l4::flags_are_possible(view.tcp_flags) => Err(ParseError::TcpFlags),
        _ => Ok(()),
    }
}

/// A UDP length field cannot be smaller than the header it is in.
const UDP_HDR_LEN: u16 = 8;

/// The lower bound holds in every fragment; the upper bound holds in none of the first
/// ones.
///
/// A first fragment carries the UDP header of the datagram, and that header states the
/// length of the whole reassembly rather than of the bytes in this fragment. Comparing
/// the two dropped every fragmented UDP datagram here, with `sanity_l4_length`, before
/// stage 4 could apply the fragment policy: IKE over 500 without RFC 7383, fragmented
/// DNS, fragmented QUIC. That is the class of false positive this pipeline exists to
/// forbid, so the upper bound is skipped for a first fragment and the lower one — a
/// UDP length below its own eight-byte header, impossible in any fragment — is kept.
fn udp_length(view: &PacketView) -> Result<(), ParseError> {
    if view.l4_len < UDP_HDR_LEN {
        return Err(ParseError::L4Length);
    }
    let l4_bytes = view.packet_len.saturating_sub(view.l4_off);
    if view.frag() != FragState::First && view.l4_len > l4_bytes {
        return Err(ParseError::L4Length);
    }
    Ok(())
}
