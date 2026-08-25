//! Stage 6. One matching packet per vector, and one legitimate neighbour per vector.
//!
//! The neighbours are the point of the file. A signature is a claim that some shape of
//! packet is never legitimate, and the only way to hold that claim honest is to build
//! the nearest packet that *is* legitimate and watch it walk through untouched. So
//! every assertion here comes in a pair, and both halves check that no other counter
//! moved either: a vector that fires on its neighbour's traffic is worse than a vector
//! that does not exist.
//!
//! Every case runs with the default policy word, where the stage is unarmed, because
//! observation is the mode being asserted: the packet passes and the counter moves. The
//! two arming tests at the end are the only ones that load an armed program.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{CounterId, setting};
use support::{PktBuilder, TestProg, XdpAction, program, program_with};

const GAME_PORT: u16 = 30_120;

/// Impossible flag combinations, and the legitimate ones they sit next to.
const TCP_SYN: u8 = 1 << 1;
const TCP_RST: u8 = 1 << 2;
const TCP_PSH: u8 = 1 << 3;
const TCP_ACK: u8 = 1 << 4;
const TCP_URG: u8 = 1 << 5;

/// The reflectors, each with a payload that amplifies and the reply it imitates.
///
/// The legitimate column is the same source port under the threshold, which is the
/// tightest neighbour there is: everything the stage can see is identical except the
/// size, so a threshold set one step too low fails here and nowhere else.
const AMPLIFIERS: [(u16, usize, usize, CounterId); 4] = [
    // A DNS answer above the 512-byte floor against an ordinary A-record reply.
    (53, 600, 80, CounterId::SignatureAmpDns),
    // A mode 7 monlist answer against a mode 4 reply, which is 48 bytes.
    (123, 440, 48, CounterId::SignatureAmpNtp),
    // A device description list against a unicast M-SEARCH answer.
    (1900, 700, 300, CounterId::SignatureAmpSsdp),
    // An MTU-filling stat dump against a `get` answer for a small value.
    (11211, 1400, 60, CounterId::SignatureAmpMemcached),
];

/// The Source query header, four `0xff` opening every A2S request and every A2S answer.
/// A gameplay datagram on the same port opens with a sequence number instead.
const SOURCE_QUERY_MAGIC: [u8; 4] = [0xff; 4];

/// RakNet's offline message identifier, carried by every unconnected message, at the
/// offset an UNCONNECTED_PONG puts it: one identifier byte, a timestamp, a server GUID.
const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];
const RAKNET_PONG_MAGIC_OFF: usize = 17;

fn signature_counters() -> Vec<CounterId> {
    CounterId::ALL
        .into_iter()
        .filter(|id| id.name().starts_with("signature_"))
        .collect()
}

/// The packet matched `expected` and no other vector, and it passed: the stage is
/// unarmed, so a match is an observation and not a verdict.
fn fires(prog: &TestProg, pkt: &[u8], expected: CounterId) {
    let before: Vec<u64> = signature_counters()
        .iter()
        .map(|id| prog.counter(id.name()))
        .collect();

    assert_eq!(
        prog.run(pkt),
        XdpAction::Pass,
        "{} was dropped by an unarmed stage",
        expected.name()
    );

    for (id, was) in signature_counters().iter().zip(before) {
        let want = if *id == expected { was + 1 } else { was };
        assert_eq!(
            prog.counter(id.name()),
            want,
            "expected only {} to move, {} did not match",
            expected.name(),
            id.name()
        );
    }
}

/// No vector at all matched. Stated as "none of the ten" rather than "not this one",
/// because a neighbour caught by a different signature is the same outage.
fn quiet(prog: &TestProg, pkt: &[u8], what: &str) {
    let before: Vec<u64> = signature_counters()
        .iter()
        .map(|id| prog.counter(id.name()))
        .collect();

    assert_eq!(prog.run(pkt), XdpAction::Pass, "{what} was dropped");

    for (id, was) in signature_counters().iter().zip(before) {
        assert_eq!(
            prog.counter(id.name()),
            was,
            "{} fired on {what}",
            id.name()
        );
    }
}

fn reflected(sport: u16, payload: usize) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 9])
        .udp(sport, GAME_PORT)
        .payload(payload)
        .build()
}

#[test]
fn every_amplification_vector_fires_on_its_own_counter() {
    let prog = program();
    for (sport, amplified, _, counter) in AMPLIFIERS {
        fires(&prog, &reflected(sport, amplified), counter);
    }
}

#[test]
fn a_reply_from_the_same_service_port_is_left_alone() {
    let prog = program();
    for (sport, _, legitimate, counter) in AMPLIFIERS {
        let pkt = reflected(sport, legitimate);
        quiet(&prog, &pkt, &format!("a {} reply", counter.name()));
    }
}

/// The two game vectors match the bytes their protocol puts on the wire, so their fixtures
/// carry those bytes and their counter-examples are the same port at the same size with the
/// MAGIC absent. That is a much tighter neighbour than a size threshold: a Source server
/// serves gameplay on the query port, and a gameplay datagram is exactly this — same port,
/// same size, different first four bytes.
#[test]
fn the_game_vectors_match_their_magic_and_nothing_else() {
    let prog = program();

    let a2s = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 9])
        .udp(27_015, GAME_PORT)
        .payload(1200)
        .payload_at(0, &SOURCE_QUERY_MAGIC)
        .build();
    fires(&prog, &a2s, CounterId::SignatureAmpA2s);

    let gameplay = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 9])
        .udp(27_015, GAME_PORT)
        .payload(1200)
        .payload_at(0, &[0x01, 0x00, 0x00, 0x00])
        .build();
    quiet(&prog, &gameplay, "a gameplay datagram from the query port");

    let pong = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 9])
        .udp(19_132, GAME_PORT)
        .payload(400)
        .payload_at(RAKNET_PONG_MAGIC_OFF, &RAKNET_MAGIC)
        .build();
    fires(&prog, &pong, CounterId::SignatureAmpRaknet);

    // The same size from the same port with no MAGIC. Before the payload was readable this
    // packet fired, which is why the vector was rated weak: a verbose MOTD is legitimate
    // and crossing a size threshold was the whole accusation.
    let verbose = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 9])
        .udp(19_132, GAME_PORT)
        .payload(400)
        .build();
    quiet(
        &prog,
        &verbose,
        "a long datagram from the RakNet port with no MAGIC",
    );
}

/// **The false positive the reference trace caught.**
///
/// Every amplified reply above, re-addressed to an ephemeral port instead of a service
/// port, must be silent. A datagram arriving where this host picks its own source ports
/// could be the answer to something it sent, and no size threshold separates a reflected
/// datagram from a large solicited one: the reference trace carries a 1100-byte DNS answer
/// to a DNSSEC query, and every threshold in the table sits under it.
///
/// This is not a hypothetical. Before the check existed, `legit_trace` failed on exactly
/// that packet with `signature_amp_dns is 1 after the reference trace and should be 0`,
/// which is what that fixture is for.
#[test]
fn an_amplified_reply_to_an_ephemeral_port_could_have_been_asked_for() {
    let prog = program();
    for (sport, amplified, _, counter) in AMPLIFIERS {
        let pkt = PktBuilder::eth()
            .ipv4()
            .src_v4([203, 0, 113, 9])
            .udp(sport, 47_001)
            .payload(amplified)
            .build();
        quiet(
            &prog,
            &pkt,
            &format!("a {} sized reply to an ephemeral port", counter.name()),
        );
    }
}

/// Chargen answering echo: one spoofed datagram and the two services feed each other
/// until something restarts.
#[test]
fn a_self_sustaining_port_pair_fires() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().udp(19, 7).payload(40).build();
    fires(&prog, &pkt, CounterId::SignatureLoopyPortPair);
}

/// The two pairs the catalogue deliberately leaves out. A legacy resolver really does
/// query from port 53 and symmetric NTP really does peer 123 to 123, so both are
/// loopable and neither can be a signature without breaking real traffic.
#[test]
fn the_loopable_pairs_that_carry_real_traffic_are_left_alone() {
    let prog = program();

    let dns_query = PktBuilder::eth().ipv4().udp(53, 53).payload(40).build();
    quiet(&prog, &dns_query, "a resolver querying from port 53");

    let ntp_peer = PktBuilder::eth().ipv4().udp(123, 123).payload(48).build();
    quiet(&prog, &ntp_peer, "symmetric NTP peering");
}

/// A first fragment carrying a payload that is not a multiple of eight. The offset
/// field counts eight-byte units, so no stack can produce it and no reassembler can
/// place what follows.
#[test]
fn a_first_fragment_off_the_eight_byte_grid_fires() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .frag(0, true)
        .payload(4)
        .build();
    fires(&prog, &pkt, CounterId::SignatureFragAbuse);
}

/// A first fragment that announces more fragments and carries nothing, so the ports of
/// the reassembled datagram come from a piece no stage judged.
#[test]
fn a_first_fragment_with_no_transport_header_fires() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .frag(0, true)
        .ip_total_len(20)
        .build();
    fires(&prog, &pkt, CounterId::SignatureFragAbuse);
}

#[test]
fn an_ordinary_first_fragment_is_left_alone() {
    let prog = program();
    for payload in [64usize, 1400] {
        let pkt = PktBuilder::eth()
            .ipv4()
            .udp(1111, GAME_PORT)
            .frag(0, true)
            .payload(payload)
            .build();
        quiet(&prog, &pkt, &format!("a {payload}-byte first fragment"));
    }
}

/// Neither opening a connection, nor answering on one, nor tearing one down. Sanity
/// accepts both of these because neither is one of the four combinations it names.
#[test]
fn flag_combinations_no_endpoint_emits_fire() {
    let prog = program();
    for flags in [TCP_PSH, TCP_URG, TCP_PSH | TCP_URG, TCP_SYN | TCP_URG] {
        let pkt = PktBuilder::eth()
            .ipv4()
            .tcp(1111, 443)
            .tcp_flags(flags)
            .build();
        fires(&prog, &pkt, CounterId::SignatureImpossibleTcpFlags);
    }
}

/// The near misses. A reset answering a segment that carried no ACK is sent with the
/// ACK bit clear, and TCP Fast Open really does push data on the handshake, so both
/// look like the vector and are not it.
#[test]
fn the_legitimate_flags_next_door_are_left_alone() {
    let prog = program();
    for flags in [
        TCP_RST,
        TCP_SYN,
        TCP_SYN | TCP_ACK,
        TCP_ACK | TCP_PSH,
        TCP_SYN | TCP_PSH,
    ] {
        let pkt = PktBuilder::eth()
            .ipv4()
            .tcp(1111, 443)
            .tcp_flags(flags)
            .build();
        quiet(&prog, &pkt, &format!("TCP flags {flags:#04x}"));
    }
}

/// A UDP length below what arrived, which sanity has to allow because that is what a
/// padded frame looks like, but which disagrees with the length the IP header states.
/// The receiver would reassemble a different datagram than the filter measured.
#[test]
fn two_headers_disagreeing_about_the_same_datagram_fires() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .payload(64)
        .udp_len(40)
        .build();
    fires(&prog, &pkt, CounterId::SignatureLengthMismatch);
}

/// The frame the vector above imitates: a runt padded to the Ethernet minimum. The
/// padding sits past the end of the IP packet, so the two headers still agree with each
/// other even though neither agrees with the wire.
#[test]
fn a_padded_runt_is_left_alone() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .payload(18)
        .ip_total_len(20 + 8)
        .udp_len(8)
        .build();
    assert!(pkt.len() > 14 + 28);
    quiet(&prog, &pkt, "a padded runt");
}

#[test]
fn the_steady_state_packet_touches_no_signature() {
    let prog = program();
    let v4 = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 1])
        .udp(1111, GAME_PORT)
        .payload(200)
        .build();
    quiet(&prog, &v4, "an ordinary IPv4 datagram");

    let v6 = PktBuilder::eth()
        .ipv6()
        .udp(1111, GAME_PORT)
        .payload(200)
        .build();
    quiet(&prog, &v6, "an ordinary IPv6 datagram");
}

/// Armed, a vector that is a fact about the packet ends its walk here. This is the
/// licence the stage has that no other defense except the bogon list does: a drop
/// without the buckets having a say.
#[test]
fn an_armed_impossible_packet_is_dropped_here() {
    let prog = program_with(setting::ENFORCE_SIGNATURES);
    let before = prog.counter("signature_impossible_tcp_flags");
    let pkt = PktBuilder::eth()
        .ipv4()
        .tcp(1111, 443)
        .tcp_flags(TCP_PSH)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("signature_impossible_tcp_flags"), before + 1);
}

/// Armed, a vector recognised by a port and a size threshold does *not* end its walk:
/// it is routed to the buckets on the tighter budget, which is a routing decision and
/// not a verdict.
///
/// Stage 7 is a stub that passes everything this phase, so `RateLimit` and `Continue`
/// reach the same action and no test can tell them apart from the outside. What this
/// asserts is the half that is observable and the half that matters: arming the stage
/// did not turn a judgement about a large reply into a drop.
#[test]
fn an_armed_amplification_vector_is_routed_and_not_dropped() {
    let prog = program_with(setting::ENFORCE_SIGNATURES);
    for (sport, amplified, _, counter) in AMPLIFIERS {
        let before = prog.counter(counter.name());
        assert_eq!(
            prog.run(&reflected(sport, amplified)),
            XdpAction::Pass,
            "{} was dropped instead of rate-limited",
            counter.name()
        );
        assert_eq!(prog.counter(counter.name()), before + 1);
    }
}

/// The default. Arming the stage is a decision, and until it is taken a matching packet
/// is counted and delivered.
#[test]
fn an_unarmed_stage_delivers_what_it_counts() {
    let unarmed = program();
    let armed = program_with(setting::ENFORCE_SIGNATURES);
    let pkt = PktBuilder::eth()
        .ipv4()
        .tcp(1111, 443)
        .tcp_flags(TCP_PSH)
        .build();

    assert_eq!(unarmed.run(&pkt), XdpAction::Pass);
    assert_eq!(armed.run(&pkt), XdpAction::Drop);
}
