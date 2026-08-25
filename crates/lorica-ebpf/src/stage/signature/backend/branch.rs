//! The branch cascade. One subprogram per family of vectors.
//!
//! Eight of the ten vectors decide on the parsed view alone â€” the ports, the two length
//! fields, the flags, the fragment state â€” and that is enough, because each of them is a
//! statement about a single datagram. The other two reach into the payload, which the
//! paragraph this one replaces said they could not: `PacketView` carried no packet
//! pointer, so A2S and RakNet were recognised by a source port and a size threshold and
//! the report that shipped them called both weak. The view now carries `data` and
//! `data_end`, and [`PacketView::payload_bytes`] reads through them, so those two match
//! the bytes their protocol puts on the wire and keep the port and the size as
//! corroboration.
//!
//! Every vector is behind its bit of the activation word, tested before anything it
//! guards. That is not a run-time skip: the word is a `.rodata` global the loader patches
//! before verification, so the verifier propagates it and takes the branch of an
//! unconfigured vector out of the program. A configuration naming two vectors carries two
//! comparisons, and the cascade a packet matching nothing walks is as long as the
//! catalogue the operator asked for rather than as long as the catalogue.
//!
//! The families stay separate functions because each answers a different question, but
//! their `inline(never)` is conditional now: the object that ships merges them into the
//! stage frame and only a `profiling` build gives each a JIT symbol. Merging frames is
//! what brings the 512-byte stack limit within reach, and the largest thing held here is
//! a sixteen-byte MAGIC.

use lorica_common::{FragState, PacketView};

use crate::{
    parse::l4::{IPPROTO_TCP, IPPROTO_UDP, TCP_ACK, TCP_RST, TCP_SYN},
    settings,
    stage::signature::{backend::SignatureBackend, catalog::VectorId},
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
/// size is what separates the vector from the reply it imitates, and for these four it
/// is the whole discriminator â€” every threshold here sits above what the protocol's own
/// answer costs and below what its amplifier returns. The two game protocols below have
/// a MAGIC to match instead, which is why they are not in this table.
const AMPLIFIERS: [(u16, u16, VectorId); 4] = [
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
];

/// Every bit of the reflector family, so a configuration holding none of it loses the
/// protocol test and both length computations below along with the rows.
///
/// Derived from the table rather than written beside it: a row added without its bit would
/// be a vector that never fires however the operator configures it.
const AMP_MASK: u32 = {
    let mut mask = VectorId::AmpA2s.bit() | VectorId::AmpRaknet.bit();
    let mut row = 0;
    while row < AMPLIFIERS.len() {
        mask |= AMPLIFIERS[row].2.bit();
        row += 1;
    }
    mask
};

const A2S_PORT: u16 = 27_015;

/// A2S_INFO is 25 bytes on the wire and produces 250 at minimum, up to about three
/// kilobytes with the player list.
const A2S_FLOOR: u16 = 250;

/// The Source query protocol header: four `0xff` bytes opening every A2S request and
/// every A2S answer.
///
/// The fifth byte names the message â€” `T` for the A2S_INFO request, `I` for the answer
/// it produces â€” and is deliberately not compared. The accusation is that a datagram
/// arrived from a query port unbidden, and both directions of the query protocol are
/// that. What the four bytes buy is the separation from the game: a Source server serves
/// gameplay on the same port, and a gameplay datagram opens with a sequence number, or
/// with `0xfffffffe` when it is one piece of a split one. Never with `0xffffffff`.
const SOURCE_QUERY_MAGIC: [u8; 4] = [0xff; 4];

const RAKNET_PORT: u16 = 19_132;

/// UNCONNECTED_PONG is 35 bytes plus a server-controlled MOTD. This was the weakest
/// claim in the catalogue while it was the whole claim, because a verbose MOTD is
/// legitimate and crossing a size threshold was the entire accusation. With the MAGIC
/// matched it is corroboration, and what it excludes is a pong too short for any
/// amplification to have happened.
const RAKNET_FLOOR: u16 = 128;

/// RakNet's offline message identifier, carried verbatim by every unconnected message.
const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// Where the MAGIC sits in an UNCONNECTED_PONG: one identifier byte, an eight-byte
/// timestamp, an eight-byte server GUID.
///
/// It sits at nine in an UNCONNECTED_PING and that offset is not read. A ping is 33 bytes
/// on the wire and cannot reach the floor above, so the only unconnected message this
/// vector can ever see is the answer.
const RAKNET_PONG_MAGIC_OFF: u16 = 17;

/// The bottom of the local port range Linux picks a source port from, so the bottom of
/// what a reply to something this host sent can be addressed to.
///
/// `net.ipv4.ip_local_port_range` starts here by default. An operator who moved it has a
/// knob this phase does not add, and moving it *down* is the direction that would cost
/// precision rather than safety.
const EPHEMERAL_FLOOR: u16 = 32_768;

/// Whether a datagram arriving at this port could be an answer to something that left.
///
/// A reflected flood is aimed at its victim, and the attacker picks the port; nothing
/// stops them picking an ephemeral one, so this is not a complete filter and is not meant
/// to be. What it establishes is a fact about one datagram: an answer arriving at a
/// *service* port cannot be an answer, because nothing here queries from a service port.
/// The flood aimed at an ephemeral port is a flood at a single port, which is what the
/// leaky buckets of stage 7 are for — this stage exists to drop what it can name, not to
/// name everything.
const fn could_be_solicited(dport: u16) -> bool {
    dport >= EPHEMERAL_FLOOR
}

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
        // Read once and passed down. Ten reads of the same word would each be a load the
        // verifier keeps — a `read_volatile` is never folded, and the instruction before a
        // branch is a visited instruction whatever the branch resolves to. One read and ten
        // compares against it means an empty catalogue costs one load and nothing else.
        let armed = settings::signature_vectors();

        // Ordered cheapest-and-most-certain last: the two port families are the ones a
        // flood is made of, so they answer first and the coherence checks, which every
        // packet reaches, are the ones a matching packet never gets to.
        if armed & AMP_MASK != 0 {
            if let Some(vector) = amplification(view, armed) {
                return Some(vector);
            }
        }
        if armed & VectorId::LoopyPortPair.bit() != 0 {
            if let Some(vector) = loop_pair(view) {
                return Some(vector);
            }
        }
        if armed & VectorId::FragAbuse.bit() != 0 {
            if let Some(vector) = fragment_abuse(view) {
                return Some(vector);
            }
        }
        if armed & VectorId::ImpossibleTcpFlags.bit() != 0 {
            if let Some(vector) = impossible_flags(view) {
                return Some(vector);
            }
        }
        if armed & VectorId::LengthMismatch.bit() != 0 {
            return length_mismatch(view);
        }
        None
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
    let l3_hdr = view.l4_off.saturating_sub(view.l3_off);
    view.ip_total_len.saturating_sub(l3_hdr)
}

/// The port and the size are tested before the payload in both game vectors, so the one
/// packet read of the stage happens only for a datagram already coming from that port at
/// that size. A flood of anything else pays two compares for it.
#[cfg_attr(feature = "profiling", inline(never))]
fn amplification(view: &PacketView, armed: u32) -> Option<VectorId> {
    if view.proto != IPPROTO_UDP {
        return None;
    }
    // A reply that could have been asked for is not an accusation, whatever its size.
    // This is not caution: the reference trace carries a 1100-byte DNS answer to a
    // DNSSEC query, entirely legitimate, and every threshold below sits under it. Size
    // alone cannot separate a reflected datagram from a large solicited one, and this
    // stage sees one datagram with no memory of what left the host.
    if could_be_solicited(view.dport) {
        return None;
    }
    let payload = udp_payload_len(view);
    // A `for` over an array whose length is a literal: the bound is structural, so the
    // verifier reads it out of the code and no index needs masking.
    for (port, floor, vector) in AMPLIFIERS {
        if armed & vector.bit() != 0 && view.sport == port && payload >= floor {
            return Some(vector);
        }
    }
    if armed & VectorId::AmpA2s.bit() != 0
        && view.sport == A2S_PORT
        && payload >= A2S_FLOOR
        && view.payload_bytes::<4>(0) == Some(SOURCE_QUERY_MAGIC)
    {
        return Some(VectorId::AmpA2s);
    }
    if armed & VectorId::AmpRaknet.bit() != 0
        && view.sport == RAKNET_PORT
        && payload >= RAKNET_FLOOR
        && view.payload_bytes::<16>(RAKNET_PONG_MAGIC_OFF) == Some(RAKNET_MAGIC)
    {
        return Some(VectorId::AmpRaknet);
    }
    None
}

#[cfg_attr(feature = "profiling", inline(never))]
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
#[cfg_attr(feature = "profiling", inline(never))]
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
/// alone is deliberately outside it â€” a reset for a segment that carried no ACK is sent
/// with the ACK bit clear, and refusing it would break the one legitimate flags-without-
/// ACK case there is.
///
/// SYN with URG is the second: no stack has ever put an urgent pointer on a handshake.
/// SYN with PSH is *not* here, because TCP Fast Open really does push data on the SYN.
#[cfg_attr(feature = "profiling", inline(never))]
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
/// length below what arrived is legitimate and sanity has to allow it â€” which lets a
/// datagram claim any length under the frame size, and the receiver reassembles a
/// different number of bytes than the filter measured. The two headers, however, are
/// bound to each other by both specifications: the IP payload of an unfragmented packet
/// *is* the UDP datagram, so the numbers are equal or the packet is forged.
///
/// Unfragmented only, and UDP only. A fragment's length field describes the whole
/// datagram rather than the piece that arrived, and TCP states no length at all.
#[cfg_attr(feature = "profiling", inline(never))]
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
