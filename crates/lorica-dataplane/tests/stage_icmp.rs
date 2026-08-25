//! Stage 2. The point of the file is the last test: no path through the configuration
//! can suppress path MTU discovery. That is a guarantee, not a default.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{Action, Deadline, LpmKey, LpmValue, setting};
use support::{PktBuilder, XdpAction, program, program_with};

const V4_ECHO_REQUEST: u8 = 8;
const V4_TIME_EXCEEDED: u8 = 11;
const V6_NEIGHBOR_SOLICIT: u8 = 135;

/// Every combination of the policy word this phase has. Sixteen loads, which is the
/// price of the assertion being about the configuration space and not about one
/// configuration.
const ALL_SETTINGS: [u32; 4] = [
    setting::ACCEPT_IP_OPTIONS,
    setting::DROP_ICMP_ECHO,
    setting::DROP_ICMP_OTHER,
    setting::ALLOW_LATER_FRAGMENTS,
];

fn every_settings_word() -> impl Iterator<Item = u32> {
    (0..(1u32 << ALL_SETTINGS.len())).map(|mask| {
        ALL_SETTINGS
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .fold(0, |word, (_, flag)| word | flag)
    })
}

fn deny_everything() -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.deadline = Deadline::never();
    value.action = Action::Drop;
    value
}

#[test]
fn fragmentation_needed_crosses_by_default() {
    let prog = program();
    let before = prog.counter("icmp_path_mtu_passed");
    let pkt = PktBuilder::eth().ipv4().icmp_ptb().build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.counter("icmp_path_mtu_passed"), before + 1);
}

#[test]
fn packet_too_big_crosses_by_default() {
    let prog = program();
    let before = prog.counter("icmp_path_mtu_passed");
    let pkt = PktBuilder::eth().ipv6().icmp_ptb().build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.counter("icmp_path_mtu_passed"), before + 1);
}

/// The stage sits above the list, so a source the list denies outright still gets its
/// path MTU message through. This is the case that makes the stage worth having: a
/// blanket deny is exactly what a tier does.
#[test]
fn path_mtu_crosses_a_source_the_list_denies() {
    let mut prog = program();
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny_everything());

    // The deny is real: ordinary traffic from that prefix is dropped.
    let udp = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 5])
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&udp), XdpAction::Drop);

    let ptb = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 5])
        .icmp_ptb()
        .build();
    assert_eq!(
        prog.run(&ptb),
        XdpAction::Pass,
        "a denied source still needs its path MTU message to arrive"
    );
}

/// The guarantee. Not that the default lets it through, but that nothing in the
/// configuration space can stop it.
#[test]
fn no_configuration_suppresses_path_mtu_discovery() {
    let v4 = PktBuilder::eth().ipv4().icmp_ptb().build();
    let v6 = PktBuilder::eth().ipv6().icmp_ptb().build();

    for settings in every_settings_word() {
        let prog = program_with(settings);
        assert_eq!(
            prog.run(&v4),
            XdpAction::Pass,
            "settings {settings:#06b} suppressed fragmentation needed"
        );
        assert_eq!(
            prog.run(&v6),
            XdpAction::Pass,
            "settings {settings:#06b} suppressed packet too big"
        );
    }
}

/// The same guarantee for the other message that cannot be dropped without breaking
/// the link: without neighbour discovery, IPv6 does not resolve at all.
#[test]
fn no_configuration_suppresses_neighbour_discovery() {
    let pkt = PktBuilder::eth()
        .ipv6()
        .icmp(V6_NEIGHBOR_SOLICIT, 0)
        .build();

    for settings in every_settings_word() {
        let prog = program_with(settings);
        assert_eq!(
            prog.run(&pkt),
            XdpAction::Pass,
            "settings {settings:#06b} suppressed neighbour solicitation"
        );
    }
}

#[test]
fn echo_follows_the_configuration() {
    let pkt = PktBuilder::eth().ipv4().icmp(V4_ECHO_REQUEST, 0).build();

    let permissive = program();
    assert_eq!(permissive.run(&pkt), XdpAction::Pass);

    let strict = program_with(setting::DROP_ICMP_ECHO);
    let before = strict.counter("icmp_echo_dropped");
    assert_eq!(strict.run(&pkt), XdpAction::Drop);
    assert_eq!(strict.counter("icmp_echo_dropped"), before + 1);
}

#[test]
fn other_types_follow_the_configuration() {
    let pkt = PktBuilder::eth().ipv4().icmp(V4_TIME_EXCEEDED, 0).build();

    let permissive = program();
    assert_eq!(permissive.run(&pkt), XdpAction::Pass);

    let strict = program_with(setting::DROP_ICMP_OTHER);
    let before = strict.counter("icmp_other_dropped");
    assert_eq!(strict.run(&pkt), XdpAction::Drop);
    assert_eq!(strict.counter("icmp_other_dropped"), before + 1);
}

/// Echo and other are separate knobs, so turning one on must not move the other.
#[test]
fn the_two_knobs_are_independent() {
    let echo = PktBuilder::eth().ipv4().icmp(V4_ECHO_REQUEST, 0).build();
    let other = PktBuilder::eth().ipv4().icmp(V4_TIME_EXCEEDED, 0).build();

    let drops_echo = program_with(setting::DROP_ICMP_ECHO);
    assert_eq!(drops_echo.run(&echo), XdpAction::Drop);
    assert_eq!(drops_echo.run(&other), XdpAction::Pass);

    let drops_other = program_with(setting::DROP_ICMP_OTHER);
    assert_eq!(drops_other.run(&echo), XdpAction::Pass);
    assert_eq!(drops_other.run(&other), XdpAction::Drop);
}

/// Echo that the configuration allows is still subject to the list, because being
/// subject to the list is part of following the configuration.
#[test]
fn allowed_echo_still_reaches_the_list() {
    let mut prog = program();
    prog.insert(LpmKey::v4([10, 90, 1, 0], 24), deny_everything());

    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 5])
        .icmp(V4_ECHO_REQUEST, 0)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
}

#[test]
fn a_packet_that_is_not_icmp_is_not_this_stage_business() {
    let prog = program();
    let counters = [
        "icmp_path_mtu_passed",
        "icmp_neighbor_passed",
        "icmp_echo_dropped",
        "icmp_other_dropped",
    ];
    let before: Vec<u64> = counters.iter().map(|name| prog.counter(name)).collect();

    let pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    for (name, was) in counters.iter().zip(before) {
        assert_eq!(prog.counter(name), was, "{name} moved on a UDP packet");
    }
}
