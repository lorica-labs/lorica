//! The checks that used to be stage 1 and are now made inside the parse, on the fields
//! it has just loaded. What is asserted here is unchanged by that move, and deliberately:
//! each refusal names its counter, because a drop nobody can see is indistinguishable
//! from a packet that never arrived, and the counter is what an operator reads.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::setting;
use support::{PktBuilder, XdpAction, program, program_with};

/// Impossible flag combinations, from the flag predicate of the program under test.
const TCP_FIN: u8 = 1 << 0;
const TCP_SYN: u8 = 1 << 1;
const TCP_RST: u8 = 1 << 2;
const TCP_ACK: u8 = 1 << 4;
const TCP_PSH: u8 = 1 << 3;

fn refused(prog: &support::TestProg, pkt: &[u8], counter: &str) {
    let before = prog.counter(counter);
    assert_eq!(
        prog.run(pkt),
        XdpAction::Drop,
        "{counter} case was not dropped"
    );
    assert_eq!(
        prog.counter(counter),
        before + 1,
        "{counter} was not incremented"
    );
}

#[test]
fn a_total_length_below_the_header_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .ip_total_len(12)
        .build();
    refused(&prog, &pkt, "sanity_ip_length");
}

#[test]
fn a_total_length_above_what_arrived_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .ip_total_len(1400)
        .build();
    refused(&prog, &pkt, "sanity_ip_length");
}

/// The legitimate case of a total length below what arrived: a frame padded to the
/// Ethernet minimum. Refusing this would drop most small packets on a real link.
#[test]
fn a_padded_frame_is_not_a_length_inconsistency() {
    let prog = program();
    let stated = 20 + 8;
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .payload(18)
        .ip_total_len(stated)
        .build();
    assert!(pkt.len() > 14 + stated as usize);
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
}

#[test]
fn a_udp_length_above_the_packet_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .udp_len(1400)
        .build();
    refused(&prog, &pkt, "sanity_l4_length");
}

#[test]
fn a_udp_length_below_its_own_header_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .udp_len(4)
        .build();
    refused(&prog, &pkt, "sanity_l4_length");
}

#[test]
fn syn_with_fin_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .tcp(1111, 443)
        .tcp_flags(TCP_SYN | TCP_FIN)
        .build();
    refused(&prog, &pkt, "sanity_tcp_flags");
}

#[test]
fn syn_with_rst_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .tcp(1111, 443)
        .tcp_flags(TCP_SYN | TCP_RST)
        .build();
    refused(&prog, &pkt, "sanity_tcp_flags");
}

#[test]
fn fin_without_ack_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4()
        .tcp(1111, 443)
        .tcp_flags(TCP_FIN)
        .build();
    refused(&prog, &pkt, "sanity_tcp_flags");
}

#[test]
fn no_flags_at_all_is_refused() {
    let prog = program();
    let pkt = PktBuilder::eth().ipv4().tcp(1111, 443).tcp_flags(0).build();
    refused(&prog, &pkt, "sanity_tcp_flags");
}

/// The combinations a real endpoint produces have to survive, or the stage is a
/// self-inflicted outage rather than a filter.
#[test]
fn ordinary_tcp_flag_combinations_pass() {
    let prog = program();
    for flags in [
        TCP_SYN,
        TCP_SYN | TCP_ACK,
        TCP_ACK,
        TCP_ACK | TCP_PSH,
        TCP_FIN | TCP_ACK,
        TCP_RST,
        TCP_RST | TCP_ACK,
    ] {
        let pkt = PktBuilder::eth()
            .ipv4()
            .tcp(1111, 443)
            .tcp_flags(flags)
            .build();
        assert_eq!(
            prog.run(&pkt),
            XdpAction::Pass,
            "flags {flags:#04x} were refused"
        );
    }
}

/// The refusal of IP options is a policy, not a fact about the packet, so it is
/// stated as one and the operator can say otherwise.
#[test]
fn ip_options_are_refused_by_default() {
    let prog = program();
    let pkt = PktBuilder::eth()
        .ipv4_options(&[148, 4, 0, 0, 1, 1, 1, 1])
        .udp(1111, 30_120)
        .build();
    refused(&prog, &pkt, "sanity_ip_options_refused");
}

#[test]
fn ip_options_pass_when_the_operator_accepts_them() {
    let prog = program_with(setting::ACCEPT_IP_OPTIONS);
    let pkt = PktBuilder::eth()
        .ipv4_options(&[148, 4, 0, 0, 1, 1, 1, 1])
        .udp(1111, 30_120)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
}

/// A fragmented packet is not malformed. Refusing it here would make stage 4, and its
/// operator-visible policy, unreachable, so the case is stated with that policy set to
/// allow: what is being asserted is that sanity did not decide, not what stage 4 does.
#[test]
fn a_later_fragment_is_not_a_sanity_failure() {
    let prog = program_with(setting::ALLOW_LATER_FRAGMENTS);
    let pkt = PktBuilder::eth()
        .ipv4()
        .udp(1111, 30_120)
        .frag(64, false)
        .payload(32)
        .build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);
}

#[test]
fn an_ordinary_packet_reaches_no_sanity_counter() {
    let prog = program();
    let counters = [
        "sanity_ip_length",
        "sanity_l4_length",
        "sanity_tcp_flags",
        "sanity_ip_options_refused",
    ];
    let before: Vec<u64> = counters.iter().map(|name| prog.counter(name)).collect();

    let pkt = PktBuilder::eth().ipv4().udp(1111, 30_120).build();
    assert_eq!(prog.run(&pkt), XdpAction::Pass);

    for (name, was) in counters.iter().zip(before) {
        assert_eq!(prog.counter(name), was, "{name} moved on a clean packet");
    }
}
