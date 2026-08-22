//! Stage 3. One list, one lookup, and every exit counted.

#![cfg(feature = "kernel-tests")]

mod support;

use carapace_common::{Action, CounterId, LpmKey, LpmValue, Scope};
use support::{PktBuilder, XdpAction, program};

const UDP: u8 = 17;
const GAME_PORT: u16 = 30_120;

/// Counter slot of the entry inserted first, second, and so on. The loader assigns
/// them the same way the policy compiler does.
fn entry_slot(index: u32) -> u32 {
    CounterId::COUNT + index
}

fn deny(scope_len: u8) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.scope_len = scope_len;
    value
}

fn allow_udp(port: u16, slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Allow;
    value.scope_len = 1;
    value.scopes[0] = Scope::new(UDP, port, port);
    value.counter_idx = slot;
    value
}

fn udp_from(src: [u8; 4], dport: u16) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(1111, dport)
        .build()
}

/// A host allow inside a network deny. The trie returns the longest match, so the /32
/// is what applies; nothing in the program compares prefix lengths.
#[test]
fn the_more_specific_entry_wins() {
    let mut prog = program();
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny(0));
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_udp(GAME_PORT, entry_slot(1)),
    );

    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 8], GAME_PORT)),
        XdpAction::Drop,
        "an address covered only by the /24 has to be dropped"
    );
    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 7], GAME_PORT)),
        XdpAction::Pass,
        "the /32 has to win over the /24 that contains it"
    );
}

/// The bypass the design exists to prevent. The source is on the allow list, and that
/// is not enough: the protocol and the port have to be in the scope too, or the packet
/// carries on down the pipeline like any other.
#[test]
fn a_matching_source_out_of_scope_does_not_leave_the_pipeline() {
    let mut prog = program();
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_udp(GAME_PORT, entry_slot(0)),
    );

    let before_exit = prog.counter_at(entry_slot(0));
    let before_miss = prog.counter("lpm_scope_miss");

    // Right source, wrong port.
    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 7], GAME_PORT + 1)),
        XdpAction::Pass,
        "it carries on rather than exiting, which is not the same verdict"
    );
    assert_eq!(
        prog.counter_at(entry_slot(0)),
        before_exit,
        "an out-of-scope packet must not count as an allow exit"
    );
    assert_eq!(prog.counter("lpm_scope_miss"), before_miss + 1);

    // Right source and port, wrong protocol.
    let tcp = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .tcp(1111, GAME_PORT)
        .tcp_flags(1 << 1)
        .build();
    assert_eq!(prog.run(&tcp), XdpAction::Pass);
    assert_eq!(prog.counter_at(entry_slot(0)), before_exit);
    assert_eq!(prog.counter("lpm_scope_miss"), before_miss + 2);
}

/// Without this counter the risk of a forged allow-listed source is undetectable by
/// construction: it is precisely a flow that leaves the pipeline without a trace.
#[test]
fn a_legitimate_exit_counts_against_its_own_entry() {
    let mut prog = program();
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_udp(GAME_PORT, entry_slot(0)),
    );
    prog.insert(
        LpmKey::v4([10, 90, 1, 8], 32),
        allow_udp(GAME_PORT, entry_slot(1)),
    );

    let before = [
        prog.counter_at(entry_slot(0)),
        prog.counter_at(entry_slot(1)),
    ];

    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 7], GAME_PORT)),
        XdpAction::Pass
    );

    assert_eq!(
        prog.counter_at(entry_slot(0)),
        before[0] + 1,
        "the exit was not counted"
    );
    assert_eq!(
        prog.counter_at(entry_slot(1)),
        before[1],
        "the exit was counted against the wrong entry, so the counter says nothing"
    );
}

#[test]
fn a_deny_without_a_scope_covers_everything_from_the_prefix() {
    let mut prog = program();
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny(0));

    let before = prog.counter("lpm_drop_hit");
    for port in [GAME_PORT, 443, 1] {
        assert_eq!(prog.run(&udp_from([10, 90, 1, 5], port)), XdpAction::Drop);
    }
    assert_eq!(prog.counter("lpm_drop_hit"), before + 3);
}

#[test]
fn an_address_in_no_entry_carries_on() {
    let prog = program();
    assert_eq!(
        prog.run(&udp_from([203, 0, 113, 1], GAME_PORT)),
        XdpAction::Pass
    );
}

#[test]
fn an_ipv6_entry_and_an_ipv4_entry_live_in_the_same_list() {
    let mut prog = program();
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny(0));
    prog.insert(
        LpmKey::v6(
            [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        deny(0),
    );

    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 5], GAME_PORT)),
        XdpAction::Drop
    );
    let v6 = PktBuilder::eth().ipv6().udp(1111, GAME_PORT).build();
    assert_eq!(prog.run(&v6), XdpAction::Drop);
}

/// A later fragment carries no port, so by construction it can never match a scope. It
/// has to reach stage 4 rather than be decided here.
#[test]
fn a_later_fragment_cannot_match_a_scope() {
    let mut prog = program();
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_udp(GAME_PORT, entry_slot(0)),
    );

    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(32)
        .build();

    let before = prog.counter_at(entry_slot(0));
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(
        prog.counter_at(entry_slot(0)),
        before,
        "a fragment with no port must not count as an allow exit"
    );
}

/// The per-packet budget on the path the design states it for: one lookup for the list
/// and one for the counter it lands on, plus the single clock reading.
#[cfg(feature = "count-helpers")]
#[test]
fn an_allow_exit_costs_one_lookup_for_the_list_and_one_for_its_counter() {
    let mut prog = program();
    prog.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_udp(GAME_PORT, entry_slot(0)),
    );

    assert_eq!(
        prog.run(&udp_from([10, 90, 1, 7], GAME_PORT)),
        XdpAction::Pass
    );

    let counts = prog.helper_counts();
    assert_eq!(counts.clock_reads, 1);
    assert_eq!(
        counts.map_lookups, 2,
        "expected the list lookup and the counter bump, got {counts:?}"
    );
}

/// A packet that matches nothing costs the list lookup and nothing else, which is the
/// steady-state cost of the whole stage.
#[cfg(feature = "count-helpers")]
#[test]
fn a_packet_matching_nothing_costs_one_lookup() {
    let prog = program();
    assert_eq!(
        prog.run(&udp_from([203, 0, 113, 1], GAME_PORT)),
        XdpAction::Pass
    );

    let counts = prog.helper_counts();
    assert_eq!(counts.clock_reads, 1);
    assert_eq!(counts.map_lookups, 1, "got {counts:?}");
}
