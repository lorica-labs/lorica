//! Nanoseconds a packet costs, path by path.
//!
//! A report and not a gate. Assertion 3 compares this against a baseline at +5 %, and it
//! is armed in the next phase once there is a baseline to compare against; what this file
//! produces is that baseline, and the shape of the pipeline it describes.
//!
//! **Where the number comes from, and where it must not.** The kernel chronometers the
//! whole loop of a `BPF_PROG_TEST_RUN` with `repeat` set and reports the average, which
//! needs no `bpf_stats_enabled`. That matters: on this hardware an empty `XDP_PASS`
//! program costs 15 ns a run and turning `bpf_stats_enabled` on adds 64 ns, so the
//! instrumentation is more than four times the signal. `run_time_ns` from
//! `bpftool prog show` stays a tool for a human reading a live system, never the source of
//! a number in a document.
//!
//! Every figure below is published **minus the 15 ns floor** measured in the previous
//! phase, because that floor is the harness and not the program.

#![cfg(feature = "kernel-tests")]

mod support;

use carapace_common::{Action, Deadline, LpmKey, LpmValue, Scope, setting};
use support::{PktBuilder, XdpAction, program, program_with};

/// `bench/results/floor-20260822T093726Z.json`: an `XDP_PASS` that does nothing, same
/// harness, same machine. Subtracted from every figure here.
const FLOOR_NS: u128 = 15;

/// One million, as the plan specifies. Enough that the per-run average is stable and the
/// whole file still runs in seconds.
const REPEAT: u32 = 1_000_000;

const UDP: u8 = 17;
const GAME_PORT: u16 = 30_120;

fn never(mut value: LpmValue) -> LpmValue {
    value.deadline = Deadline::never();
    value
}

fn drop_entry() -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    never(value)
}

fn allow_entry(slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Allow;
    value.scope_len = 1;
    value.scopes[0] = Scope::new(UDP, GAME_PORT, GAME_PORT);
    value.counter_idx = slot;
    never(value)
}

/// Reports one path. `saturating_sub` rather than a signed difference: a measurement below
/// the floor means the floor is not this machine's, and reporting zero says that more
/// plainly than a negative nanosecond count.
fn report(label: &str, measured: u128) {
    println!(
        "{label:<46} {measured:>4} ns raw, {:>4} ns above the floor",
        measured.saturating_sub(FLOOR_NS)
    );
}

#[test]
fn the_cost_of_each_path_through_the_pipeline() {
    println!("floor subtracted: {FLOOR_NS} ns, repeat = {REPEAT}");

    // The steady-state path, and the one the budget is stated about: a legitimate UDP
    // packet that matches no entry and walks the whole pipeline to the end.
    let plain = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 1])
        .udp(1111, GAME_PORT)
        .build();
    let prog = program();
    assert_eq!(prog.run(&plain), XdpAction::Pass);
    report(
        "UDP matching nothing, full pipeline",
        prog.ns_per_run(&plain, REPEAT),
    );

    let v6 = PktBuilder::eth().ipv6().udp(1111, GAME_PORT).build();
    assert_eq!(prog.run(&v6), XdpAction::Pass);
    report("IPv6 UDP matching nothing", prog.ns_per_run(&v6, REPEAT));

    let vlan = PktBuilder::eth()
        .vlan(100)
        .ipv4()
        .src_v4([203, 0, 113, 1])
        .udp(1111, GAME_PORT)
        .build();
    assert_eq!(prog.run(&vlan), XdpAction::Pass);
    report(
        "VLAN, then UDP matching nothing",
        prog.ns_per_run(&vlan, REPEAT),
    );

    // A drop decided by the list: the earliest exit that costs a lookup and a counter.
    let mut blocked = program();
    blocked.insert(LpmKey::v4([198, 51, 100, 7], 32), drop_entry());
    let hostile = PktBuilder::eth()
        .ipv4()
        .src_v4([198, 51, 100, 7])
        .udp(1111, GAME_PORT)
        .build();
    assert_eq!(blocked.run(&hostile), XdpAction::Drop);
    report("dropped by the list", blocked.ns_per_run(&hostile, REPEAT));

    // The legitimate exit: two lookups, one for the list and one for the counter of the
    // entry it landed on.
    let mut allowed = program();
    allowed.insert(
        LpmKey::v4([10, 90, 1, 7], 32),
        allow_entry(carapace_common::CounterId::COUNT),
    );
    let friend = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 7])
        .udp(1111, GAME_PORT)
        .build();
    assert_eq!(allowed.run(&friend), XdpAction::Pass);
    report(
        "allowed out of the pipeline by the list",
        allowed.ns_per_run(&friend, REPEAT),
    );

    // An expired entry: the TTL branch, which is the one this phase added.
    let mut expired = program();
    expired.insert(LpmKey::v4([198, 51, 100, 8], 32), {
        let mut value = drop_entry();
        value.deadline = Deadline(1);
        value
    });
    let stale = PktBuilder::eth()
        .ipv4()
        .src_v4([198, 51, 100, 8])
        .udp(1111, GAME_PORT)
        .build();
    assert_eq!(expired.run(&stale), XdpAction::Pass);
    report(
        "list entry past its deadline",
        expired.ns_per_run(&stale, REPEAT),
    );

    // A refusal at the first stage, which should be the cheapest exit there is.
    let truncated = PktBuilder::eth()
        .ipv4()
        .udp(1111, GAME_PORT)
        .truncate(20)
        .build();
    assert_eq!(prog.run(&truncated), XdpAction::Drop);
    report("refused by parsing", prog.ns_per_run(&truncated, REPEAT));

    let later = program_with(setting::ALLOW_LATER_FRAGMENTS);
    let fragment = PktBuilder::eth()
        .ipv4()
        .src_v4([203, 0, 113, 1])
        .udp(1111, GAME_PORT)
        .frag(64, false)
        .payload(32)
        .build();
    assert_eq!(later.run(&fragment), XdpAction::Pass);
    report(
        "later fragment, allowed",
        later.ns_per_run(&fragment, REPEAT),
    );
}
