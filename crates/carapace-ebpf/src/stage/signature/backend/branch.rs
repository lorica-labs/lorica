//! The branch cascade. One `#[inline(never)]` subprogram per family of vectors.
//!
//! Every one of them decides on the parsed view alone. That is not a shortcut, it is
//! the shape of the pipeline: `PacketView` deliberately carries no packet pointer, so a
//! stage cannot reach back into the frame, and stage 6 is called with the view and
//! nothing else. What a signature gets is therefore the ports, the two length fields,
//! the flags and the fragment state — and every vector below is decided on a single
//! datagram out of those. Where a magic string would have made a match tighter, the
//! comment says so.
//!
//! The families are separate subprograms rather than one inlined cascade so that each
//! gets its own frame and its own JIT symbol: a stack limit of 512 bytes per frame is
//! not a constraint this stage is anywhere near, but a per-family symbol is what makes
//! the cost of the cascade readable in a profile.

use carapace_common::{FragState, PacketView};

use crate::{
    parse::l4::{IPPROTO_TCP, IPPROTO_UDP},
    stage::{
        sanity::{TCP_ACK, TCP_RST, TCP_SYN},
        signature::{backend::SignatureBackend, catalog::VectorId},
    },
};

const UDP_HDR_LEN: u16 = 8;

/// A first fragment has to carry the ports of the datagram it opens. Eight bytes is
/// the RFC 1858 floor: below it the transport header is split across fragments and the
/// ports of the reassembled packet are decided by a fragment no filter judged.
const MIN_FIRST_FRAGMENT_L4: u16 = 8;

/// The fragment offset counts eight-byte units, so every fragment that is not the last
/// one carries a multiple of eight.
const FRAGMENT_GRANULARITY: u16 = 8;

const TCP_URG: u8 = 1 << 5;

/// Reflectors, by the port an unsolicited answer arrives *from*, and the payload size
/// above which that answer is an amplification rather than a reply.
///
/// The direction is what makes the port meaningful: a packet arriving from source port
/// 53 is something a resolver sent, and nothing behind this pipeline asked it to. The
/// size is what separates the vector from the reply it imitates, and it is the whole
/// discriminator available on one datagram — every threshold here sits above what the
/// protocol's own answer costs and below what its amplifier returns.
const AMPLIFIERS: [(u16, u16, VectorId); 6] = [
    // A response that fits the 512-byte floor of DNS without EDNS is a reply. Above
    // it lives the ANY/DNSSEC/TXT family the reflectors are chosen for.
    (53, 512, VectorId::AmpDns),
    // Mode 3 and 4 are 48 bytes, 76 with the largest authenticator. `monlist` and
    // `peer_list` answer in the hundreds, one datagram per six associations.
    (123, 100, VectorId::AmpNtp),
    // A unicast M-SEARCH answer is a few hundred bytes of headers. The amplifier
    // returns the device description list.
    (1900, 512, VectorId::AmpSsdp),
    // The largest factor in the field, four to five orders of magnitude: a legitimate
    // UDP `get` answer for a small value does not reach a kilobyte.
    (11211, 1024, VectorId::AmpMemcached),
    // A2S_INFO is 25 bytes on the wire and produces 250 at minimum, up to about three
    // kilobytes with the player list.
    (27015, 250, VectorId::AmpA2s),
    // UNCONNECTED_PING is 25 bytes, UNCONNECTED_PONG 35 plus a server-controlled MOTD.
    // The floor is above a bare pong and above the MOTD of an ordinary server; it is
    // the weakest threshold of the six, because the string the pong carries is the
    // server's to choose and a verbose one is legitimate.
    (19132, 128, VectorId::AmpRaknet),
];

/// `(port_a, port_b)` couples where each end answers whatever the other sends, so one
/// spoofed datagram addressed to both of them never stops (Loopy Hellow, NDSS 2024).
///
/// Only the legacy diagnostic services are here. The paper also names DNS-to-DNS and
/// NTP-to-NTP as loopable, and those two are deliberately absent: a legacy resolver
/// really does query from port 53, symmetric NTP really does peer 123 to 123, and a
/// signature that fires on either is a false positive on any reference trace that has
/// an old resolver or an NTP peer in it. Nothing has answered on echo, chargen, qotd,
/// daytime, time or systat in thirty years, so those cost nothing to refuse.
const LOOP_PAIRS: [(u16, u16); 7] = [
    (7, 7),
    (7, 19),
    (19, 19),
    (11, 11),
    (13, 13),
    (17, 17),
    (37, 37),
];

pub struct Branch;

impl SignatureBackend for Branch {
    fn classify(view: &PacketView) -> Option<VectorId> {
        // Ordered cheapest-and-most-certain last: the two port families are the ones a
        // flood is made of, so they answer first and the coherence checks, which every
        // packet reaches, are the ones a matching packet never gets to.
        if let Some(vector) = amplification(view) {
            return Some(vector);
        }
        if let Some(vector) = loop_pair(view) {
            return Some(vector);
        }
        if let Some(vector) = fragment_abuse(view) {
            return Some(vector);
        }
        if let Some(vector) = impossible_flags(view) {
            return Some(vector);
        }
        length_mismatch(view)
    }
}

/// The payload of a UDP datagram as its own header states it. Zero for anything else,
/// which is why every caller tests the protocol first.
const fn udp_payload_len(view: &PacketView) -> u16 {
    view.l4_len.saturating_sub(UDP_HDR_LEN)
}

/// Bytes the IP header says come after it. Not the bytes that arrived: a padded frame
/// carries more, and the point of the two coherence families below is that the headers
/// agree with each other and not with the wire.
const fn stated_l4_len(view: &PacketView) -> u16 {
    let l3_hdr = view.l4_off.saturating_sub(view.l3_off) as u16;
    view.ip_total_len.saturating_sub(l3_hdr)
}

#[inline(never)]
fn amplification(view: &PacketView) -> Option<VectorId> {
    if view.proto != IPPROTO_UDP {
        return None;
    }
    let payload = udp_payload_len(view);
    // A `for` over an array whose length is a literal: the bound is structural, so the
    // verifier reads it out of the code and no index needs masking.
    for (port, floor, vector) in AMPLIFIERS {
        if view.sport == port && payload >= floor {
            return Some(vector);
        }
    }
    None
}

#[inline(never)]
fn loop_pair(view: &PacketView) -> Option<VectorId> {
    if view.proto != IPPROTO_UDP {
        return None;
    }
    for (a, b) in LOOP_PAIRS {
        if (view.sport == a && view.dport == b) || (view.sport == b && view.dport == a) {
            return Some(VectorId::LoopyPortPair);
        }
    }
    None
}

/// What stage 4 does not cover. It decides the fate of a *later* fragment, which has no
/// transport header to be incoherent about; these two are properties of a *first*
/// fragment, which walked every earlier stage as an ordinary packet.
#[inline(never)]
fn fragment_abuse(view: &PacketView) -> Option<VectorId> {
    if view.frag() != FragState::First {
        return None;
    }
    let carried = stated_l4_len(view);
    if carried < MIN_FIRST_FRAGMENT_L4 || carried % FRAGMENT_GRANULARITY != 0 {
        return Some(VectorId::FragAbuse);
    }
    None
}

/// The complement to sanity, which already refuses the null scan, SYN with FIN, SYN
/// with RST, and FIN without ACK.
///
/// What is left are combinations that parse, that sanity accepts, and that no endpoint
/// emits. A segment with none of SYN, ACK and RST is neither opening a connection nor
/// answering on one nor tearing one down, so whatever else it carries is a probe: that
/// covers PSH alone, URG alone, PSH with URG, and the Xmas tree minus its FIN. RST
/// alone is deliberately outside it — a reset for a segment that carried no ACK is sent
/// with the ACK bit clear, and refusing it would break the one legitimate flags-without-
/// ACK case there is.
///
/// SYN with URG is the second: no stack has ever put an urgent pointer on a handshake.
/// SYN with PSH is *not* here, because TCP Fast Open really does push data on the SYN.
#[inline(never)]
fn impossible_flags(view: &PacketView) -> Option<VectorId> {
    if view.proto != IPPROTO_TCP {
        return None;
    }
    // Zero is the null scan, which sanity already refused. Reaching here with zero
    // means a later fragment the operator allowed, and it carries no flags byte at all.
    let flags = view.tcp_flags;
    if flags == 0 {
        return None;
    }
    if flags & (TCP_SYN | TCP_ACK | TCP_RST) == 0 || flags & TCP_SYN != 0 && flags & TCP_URG != 0 {
        return Some(VectorId::ImpossibleTcpFlags);
    }
    None
}

/// The disagreement sanity cannot see: it compares each length field against the frame
/// and never the two fields against each other.
///
/// That gap is exactly where the evasion lives. Ethernet pads a short frame, so a UDP
/// length below what arrived is legitimate and sanity has to allow it — which lets a
/// datagram claim any length under the frame size, and the receiver reassembles a
/// different number of bytes than the filter measured. The two headers, however, are
/// bound to each other by both specifications: the IP payload of an unfragmented packet
/// *is* the UDP datagram, so the numbers are equal or the packet is forged.
///
/// Unfragmented only, and UDP only. A fragment's length field describes the whole
/// datagram rather than the piece that arrived, and TCP states no length at all.
#[inline(never)]
fn length_mismatch(view: &PacketView) -> Option<VectorId> {
    if view.proto != IPPROTO_UDP || view.frag() != FragState::None {
        return None;
    }
    let stated = stated_l4_len(view);
    // Zero is what an IPv6 jumbogram looks like from here: the payload length field is
    // zero and the real length lives in a hop-by-hop option this parser does not read.
    // A frame that large cannot reach this pipeline, and answering "mismatch" to a
    // packet whose length was never in the header would be a guess.
    if stated == 0 || stated == view.l4_len {
        return None;
    }
    Some(VectorId::LengthMismatch)
}
