//! One case per encapsulation, written against the parsed view rather than against
//! the verdict: at this point every stage still says "continue", so a verdict alone
//! cannot tell a destination port read at offset 20 from one read at offset 24. That
//! is the bug this file exists to catch.
//!
//! Needs the `parse-probe` feature of carapace-ebpf in the object under test.

#![cfg(feature = "kernel-tests")]

mod support;

use carapace_common::{Family, FragState, anomaly};
use support::{
    PktBuilder, XdpAction,
    pkt::{
        IPPROTO_DSTOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, MIN_TEST_RUN_LEN,
    },
    program,
};

const ETH: u32 = 14;
const IPV4_FIXED: u32 = 20;
const IPV6_FIXED: u32 = 40;
const VLAN_TAG: u32 = 4;

#[test]
fn bare_ethernet_ipv4() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.vlan_tags, 0);
    assert_eq!(view.l3_off, ETH);
    assert_eq!(view.l4_off, ETH + IPV4_FIXED);
    assert_eq!(view.family(), Family::V4);
    assert_eq!(view.proto, IPPROTO_UDP);
    assert_eq!(view.sport, 1111);
    assert_eq!(view.dport, 30_120);
    assert_eq!(view.frag(), FragState::None);
    assert_eq!(&view.src[12..], &[10, 90, 1, 2]);
    assert_eq!(
        &view.src[10..12],
        &[0xff, 0xff],
        "IPv4 sits in the mapped range"
    );
}

#[test]
fn one_vlan_tag_shifts_the_network_header() {
    let prog = program();
    let pkt = PktBuilder::eth().vlan(42).ipv4().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.vlan_tags, 1);
    assert_eq!(view.l3_off, ETH + VLAN_TAG);
    assert_eq!(view.l4_off, ETH + VLAN_TAG + IPV4_FIXED);
    // The point of the case: the reference selftest passes tagged traffic through
    // untouched, so the port it would filter on is not the one the stack acts on.
    assert_eq!(view.dport, 30_120);
}

#[test]
fn stacked_tags_are_parsed_not_waved_through() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .qinq(100, 42)
        .ipv4()
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.vlan_tags, 2);
    assert_eq!(view.l3_off, ETH + 2 * VLAN_TAG);
    assert_eq!(view.dport, 30_120);
}

#[test]
fn a_third_tag_is_refused_with_a_counter() {
    let prog = program();
    let before = prog.counter("parse_depth_exceeded");
    let pkt = PktBuilder::eth()
        .qinq(100, 42)
        .vlan(7)
        .ipv4()
        .udp(1111, 30_120)
        .build();

    // Explicit policy, not an implicit pass. Passing here would mean judging a
    // packet on headers the stack will not use.
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("parse_depth_exceeded"), before + 1);
}

#[test]
fn ipv4_without_options() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().tcp(1111, 443).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.l4_off, ETH + IPV4_FIXED);
    assert_eq!(view.proto, IPPROTO_TCP);
    assert!(!view.has(anomaly::IP_OPTIONS_PRESENT));
}

/// The case the plan calls out by name: with options present, assuming a 20-byte
/// header reads the destination port from inside the option area. That is a parsing
/// bug and a port filter bypass at the same time.
#[test]
fn ipv4_options_move_the_destination_port() {
    let prog = program();
    // Router Alert (148), length 4, then two no-operation bytes.
    let pkt = PktBuilder::eth()
        .ipv4_options(&[148, 4, 0, 0, 1, 1, 1, 1])
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.l4_off, ETH + IPV4_FIXED + 8);
    assert_eq!(
        view.dport, 30_120,
        "the destination port was read at the wrong offset"
    );
    assert!(view.has(anomaly::IP_OPTIONS_PRESENT));
}

/// The option contents are deliberately not interpreted, so an inconsistent length
/// changes nothing: the header length is what locates the transport header, and the
/// presence of options is what the policy is stated on.
#[test]
fn an_inconsistent_option_length_does_not_move_the_transport_header() {
    let prog = program();
    // Option 148 claiming a length of 40 inside an 8-byte option area.
    let pkt = PktBuilder::eth()
        .ipv4_options(&[148, 40, 0, 0, 1, 1, 1, 1])
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert!(view.has(anomaly::IP_OPTIONS_PRESENT));
    assert_eq!(view.l4_off, ETH + IPV4_FIXED + 8);
    assert_eq!(view.dport, 30_120);
}

/// A zero-length option is the classic way to spin a naive option walker forever.
/// There is no walker to spin, and the packet still comes out with a verdict.
#[test]
fn a_zero_length_option_is_harmless() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4_options(&[148, 0, 0, 0])
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert!(prog.parsed().has(anomaly::IP_OPTIONS_PRESENT));
}

/// An option area the packet does not actually carry has to be refused, because the
/// transport header the header length points at is outside the packet.
#[test]
fn an_option_area_past_the_end_of_the_packet_is_refused() {
    let prog = program();
    let before = prog.counter("parse_truncated");
    let mut pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    pkt[ETH as usize] = 0x4f; // version 4, IHL 15 words, so 40 bytes of options
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("parse_truncated"), before + 1);
}

#[test]
fn an_ipv4_header_shorter_than_its_fixed_part_is_refused() {
    let prog = program();
    let before = prog.counter("sanity_ip_length");
    let mut pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    pkt[ETH as usize] = 0x44; // version 4, IHL 4 words
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("sanity_ip_length"), before + 1);
}

#[test]
fn ipv6_without_extension_headers() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv6().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.family(), Family::V6);
    assert_eq!(view.l4_off, ETH + IPV6_FIXED);
    assert_eq!(view.dport, 30_120);
    assert!(!view.has(anomaly::IPV6_EXT_PRESENT));
}

#[test]
fn one_ipv6_extension_header_shifts_the_transport_header() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv6()
        .ext_header(IPPROTO_DSTOPTS, 0)
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.l4_off, ETH + IPV6_FIXED + 8);
    assert_eq!(view.dport, 30_120, "the extension header was not skipped");
    assert_eq!(view.proto, IPPROTO_UDP);
    assert!(view.has(anomaly::IPV6_EXT_PRESENT));
}

#[test]
fn a_chain_past_the_depth_bound_is_refused_with_a_counter() {
    let prog = program();
    let before = prog.counter("parse_depth_exceeded");
    let mut builder = PktBuilder::eth().ipv6();
    for _ in 0..5 {
        builder = builder.ext_header(IPPROTO_DSTOPTS, 0);
    }
    let pkt = builder.udp(1111, 30_120).build();

    // The other bypass of the reference selftest: a deep chain that reaches the
    // stack without ever having been judged.
    assert_eq!(prog.run(&pkt), XdpAction::Drop);
    assert_eq!(prog.counter("parse_depth_exceeded"), before + 1);
}

#[test]
fn a_first_fragment_carries_its_transport_header() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .frag(0, true)
        .payload(32)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.frag(), FragState::First);
    assert_eq!(view.dport, 30_120);
}

#[test]
fn a_later_fragment_has_no_port_at_all() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .frag(64, false)
        .payload(32)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.frag(), FragState::Later);
    // Reading payload bytes as ports here is how a fragmented flood walks through a
    // port filter.
    assert_eq!(view.dport, 0);
    assert_eq!(view.sport, 0);
}

#[test]
fn an_ipv6_fragment_header_sets_the_fragment_state() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv6()
        .udp(1111, 30_120)
        .frag(64, false)
        .payload(32)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.parsed().frag(), FragState::Later);
}

/// Truncated at every header boundary of a tagged IPv4 UDP packet. The floor is the
/// Ethernet header because `BPF_PROG_TEST_RUN` refuses a shorter XDP input, which is
/// a limit of the tool and not of the program.
#[test]
fn truncation_at_every_header_boundary_is_refused() {
    let prog = program();
    let full = PktBuilder::eth().vlan(42).ipv4().udp(1111, 30_120).build();

    let l3 = (ETH + VLAN_TAG) as usize;
    let l4 = l3 + IPV4_FIXED as usize;
    let boundaries = [
        MIN_TEST_RUN_LEN,
        l3 - 2,
        l3,
        l3 + 8,
        l4 - 1,
        l4,
        l4 + 2,
        l4 + 6,
    ];

    for at in boundaries {
        if at >= full.len() {
            continue;
        }
        let before = prog.counter("parse_truncated");
        let pkt = PktBuilder::eth()
            .vlan(42)
            .ipv4()
            .udp(1111, 30_120)
            .truncate(at)
            .build();
        assert_eq!(
            prog.run(&pkt),
            XdpAction::Drop,
            "a packet truncated at {at} was not refused"
        );
        assert_eq!(
            prog.counter("parse_truncated"),
            before + 1,
            "truncation at {at} did not reach the counter"
        );
    }
}

#[test]
fn icmpv4_fragmentation_needed_is_parsed() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().icmp_ptb().build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.proto, IPPROTO_ICMP);
    assert_eq!((view.icmp_type, view.icmp_code), (3, 4));
}

#[test]
fn icmpv6_packet_too_big_is_parsed() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv6().icmp_ptb().build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.proto, IPPROTO_ICMPV6);
    assert_eq!((view.icmp_type, view.icmp_code), (2, 0));
}

#[test]
fn a_non_ip_frame_passes_and_is_counted() {
    let prog = program();
    let before = prog.counter("parse_unknown_encap");
    let pkt = PktBuilder::eth().build();

    // Dropping ARP would break the network this program is supposed to protect.
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
    assert_eq!(prog.counter("parse_unknown_encap"), before + 1);
}

#[test]
fn the_stated_lengths_reach_the_view() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .payload(16)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let view = prog.parsed();
    assert_eq!(view.packet_len as usize, pkt.len());
    assert_eq!(view.ip_total_len as usize, pkt.len() - ETH as usize);
    assert_eq!(view.l4_len, 8 + 16);
}

/// The per-packet budget, on the packet the budget is written about: a legitimate UDP
/// packet in steady state. This is the figure the design is stated in, and it is not
/// the static ceiling of the program, which counts every branch at once.
///
/// One clock read and no lookup at this point. The lookup arrives with the list; the
/// clock is read once in `stage::run` and passed down, and a stage taking it again
/// would double it.
#[cfg(feature = "count-helpers")]
#[test]
fn a_legitimate_packet_reads_the_clock_once_and_looks_nothing_up() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    let counts = prog.helper_counts();
    assert_eq!(
        counts.clock_reads, 1,
        "the clock was read {} times",
        counts.clock_reads
    );
    assert_eq!(counts.map_lookups, 0, "nothing looks anything up yet");
}
