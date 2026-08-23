//! Stage 4. The named case at the bottom of this file is a regression the reordering
//! of the pipeline introduced once: fragmented administration traffic stopped
//! arriving, and nothing said so.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{Action, Deadline, LpmKey, LpmValue, Scope, setting};
use support::{PktBuilder, XdpAction, program, program_with};

const UDP: u8 = 17;
/// Encapsulating Security Payload. It carries no port at all, fragmented or not.
const IPPROTO_ESP: u8 = 50;
const IKE_PORT: u16 = 500;
const GAME_PORT: u16 = 30_120;

fn later_fragment(dport: u16) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .udp(1111, dport)
        .frag(64, false)
        .payload(64)
        .build()
}

fn allow_proto(proto: u8, lo: u16, hi: u16) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.deadline = Deadline::never();
    value.action = Action::Allow;
    value.scope_len = 1;
    value.scopes[0] = Scope::new(proto, lo, hi);
    value.counter_idx = lorica_common::CounterId::COUNT;
    value
}

fn deny_everything() -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.deadline = Deadline::never();
    value.action = Action::Drop;
    value
}

/// It carries its transport header, so it went through every earlier stage the way an
/// unfragmented packet does.
#[test]
fn a_first_fragment_takes_the_normal_path() {
    let prog = program();
    let before = prog.counter("fragment_first_passed");

    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .frag(0, true)
        .payload(64)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.counter("fragment_first_passed"), before + 1);
    assert_eq!(
        prog.parsed().dport,
        GAME_PORT,
        "a first fragment still has its port read"
    );
}

/// The production bug this pairs with. A first fragment carries the UDP header of the
/// datagram, and that header states the length of the whole reassembly, not of the bytes
/// in this fragment. Comparing the two refused **every fragmented UDP datagram** with
/// `sanity_l4_length` before stage 4 could apply its policy: IKE over 500 without
/// RFC 7383, fragmented DNS, fragmented QUIC. The upper bound is now skipped for a first
/// fragment.
#[test]
fn a_first_fragment_may_state_the_length_of_the_whole_reassembly() {
    let prog = program();
    let passed = prog.counter("fragment_first_passed");
    let refused = prog.counter("sanity_l4_length");

    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(IKE_PORT, IKE_PORT)
        .frag(0, true)
        .payload(1400)
        .udp_len(4000)
        .build();

    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(
        prog.counter("sanity_l4_length"),
        refused,
        "the stated reassembly length was read as an inconsistency"
    );
    assert_eq!(prog.counter("fragment_first_passed"), passed + 1);
}

/// The lower bound holds in every fragment: a UDP length below its own header describes
/// no datagram at all, first fragment or not.
#[test]
fn a_udp_length_below_its_own_header_is_refused_in_a_first_fragment_too() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .frag(0, true)
        .payload(64)
        .udp_len(4)
        .build();

    let before = prog.counter("sanity_l4_length");
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("sanity_l4_length"), before + 1);
}

/// The other end of the same datagram. It has no transport header at all, so no length
/// to be consistent about, and the only thing entitled to decide it is stage 4.
#[test]
fn a_non_first_fragment_reaches_the_fragment_policy_and_not_a_length_check() {
    let prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    let allowed = prog.counter("fragment_later_allowed");
    let refused = prog.counter("sanity_l4_length");

    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(IKE_PORT, IKE_PORT)
        .frag(184, false)
        .payload(1400)
        .build();

    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.counter("sanity_l4_length"), refused);
    assert_eq!(prog.counter("fragment_later_allowed"), allowed + 1);
}

#[test]
fn a_later_fragment_is_dropped_by_default_and_counted() {
    let prog = program();
    let before = prog.counter("fragment_later_dropped");
    assert_eq!(prog.run(&later_fragment(GAME_PORT)), XdpAction::Drop);
    assert_eq!(prog.counter("fragment_later_dropped"), before + 1);
}

#[test]
fn a_later_fragment_passes_when_the_operator_allows_it() {
    let prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    let before = prog.counter("fragment_later_allowed");
    assert_eq!(prog.run(&later_fragment(GAME_PORT)), XdpAction::Pass);
    assert_eq!(prog.counter("fragment_later_allowed"), before + 1);
}

/// The authorisation is not a way around the list. A source the list denies stays
/// denied, fragmented or not.
#[test]
fn allowing_later_fragments_is_not_a_bypass_of_the_list() {
    let mut prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny_everything());

    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 5])
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(64)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
}

/// What the operator gives up by allowing later fragments, stated as a test: a scope
/// that names a port cannot cover a packet that has none, so a port filter no longer
/// applies to them. The degraded key of the specification is this, and it is what the
/// list already does.
#[test]
fn a_port_scope_cannot_cover_a_later_fragment() {
    let mut prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_proto(UDP, GAME_PORT, GAME_PORT),
    );

    let slot = lorica_common::CounterId::COUNT;
    let before = prog.counter_at(slot);

    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(64)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(
        prog.counter_at(slot),
        before,
        "it passed as an allowed fragment, not as an allow-list exit"
    );
}

/// The other half: a scope written on the protocol alone does cover a later fragment,
/// which is how an allow-listed peer keeps exiting the pipeline early.
#[test]
fn a_protocol_scope_does_cover_a_later_fragment() {
    let mut prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_proto(UDP, 0, u16::MAX),
    );

    let slot = lorica_common::CounterId::COUNT;
    let before = prog.counter_at(slot);

    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(64)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(
        prog.counter_at(slot),
        before + 1,
        "a protocol-only scope has to reach the allow exit"
    );
}

/// The regression the reordering of the pipeline introduced once. IPsec and IKE
/// fragment routinely, and administration traffic that stops arriving is the failure
/// nobody attributes to the filter.
#[test]
fn fragmented_administration_traffic_survives_the_authorisation() {
    let prog = program_with(setting::ALLOW_LATER_FRAGMENTS);

    // A later fragment of an ESP packet: no port, and no transport header to read one
    // from even if there were.
    let esp = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .ip_proto(IPPROTO_ESP)
        .frag(64, false)
        .payload(512)
        .build();
    assert_eq!(
        prog.run(&esp),
        XdpAction::Pass,
        "fragmented ESP was dropped"
    );

    // A later fragment of an IKE exchange, which is large enough to fragment on any
    // ordinary MTU.
    let ike = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(IKE_PORT, IKE_PORT)
        .frag(184, false)
        .payload(512)
        .build();
    assert_eq!(
        prog.run(&ike),
        XdpAction::Pass,
        "fragmented IKE was dropped"
    );

    // And the first fragment of the same exchange, which does carry its ports.
    let ike_first = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(IKE_PORT, IKE_PORT)
        .frag(0, true)
        .payload(1400)
        .build();
    assert_eq!(prog.run(&ike_first), XdpAction::Pass);
}

#[test]
fn an_unfragmented_packet_touches_no_fragment_counter() {
    let prog = program();
    let counters = [
        "fragment_first_passed",
        "fragment_later_dropped",
        "fragment_later_allowed",
    ];
    let before: Vec<u64> = counters.iter().map(|name| prog.counter(name)).collect();

    let pkt = PktBuilder::eth().ipv4().udp(1111, GAME_PORT).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    for (name, was) in counters.iter().zip(before) {
        assert_eq!(prog.counter(name), was, "{name} moved on a whole packet");
    }
}

#[test]
fn an_ipv6_later_fragment_follows_the_same_policy() {
    let pkt = PktBuilder::eth()
        .ipv6()
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(64)
        .build();

    assert_eq!(program().run(&pkt), XdpAction::Drop);
    assert_eq!(
        program_with(setting::ALLOW_LATER_FRAGMENTS).run(&pkt),
        XdpAction::Pass
    );
}
