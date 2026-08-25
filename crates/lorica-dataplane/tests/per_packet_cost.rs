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

use lorica_common::{Action, DEFAULT_SETTINGS, Deadline, LpmKey, LpmValue, Scope, setting};
use support::{PktBuilder, XdpAction, program, program_with, program_with_vectors};

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

    // The same path with stage 5 armed: the difference against the line above is what the
    // loader decides to pay or not.
    //
    // **The verdict here belongs to the host and not to the program, so it is reported and
    // not asserted.** The frame carries no ingress interface, so on a machine that does not
    // forward the device check refuses before the table is consulted, the answer is
    // `FWD_DISABLED`, and the packet passes counted as `urpf_lookup_unsupported`. On a
    // machine that does forward — a CI runner, where a container runtime has turned
    // `ip_forward` on — the reverse lookup of a documentation address resolves nowhere
    // useful and the stage drops it. Both are stage 5 working, and which one a host gives is
    // not something this file can decide.
    //
    // It matters to the number and not only to the assertion: a packet the stage drops
    // leaves the pipeline at stage 5 and never pays stages 6 and 7, so the figure is the
    // cost *up to and including* the reverse-path lookup rather than of the whole pipeline.
    // That is why the verdict goes in the label — a number whose meaning depends on the
    // host has to carry the host's answer next to it. The verdicts themselves are asserted
    // in `urpf_stage.rs`, against real interfaces with real routes, which is the only place
    // they can be.
    //
    // Either way it is a floor and not the cost on a router: a host that really routes walks
    // the table, and without `SKIP_NEIGH` the neighbour cache too.
    let armed = program_with(setting::URPF_ENFORCE);
    let verdict = armed.run(&plain);
    assert_ne!(
        verdict,
        XdpAction::Aborted,
        "stage 5 aborted the program rather than deciding, so the figure below is not a cost"
    );
    report(
        &format!("UDP matching nothing, uRPF armed, {verdict:?}"),
        armed.ns_per_run(&plain, REPEAT),
    );

    // What the signature catalogue costs a packet that matches none of it, bracketed by the
    // two ends of the configuration space. The vector word is a load-time constant, so a
    // cleared bit is not a branch skipped at run time: the verifier removes that vector
    // before the program is JITed. The line above arms the whole catalogue, which is the
    // worst case and not the common one; this one arms nothing, which is the floor. A real
    // configuration sits between the two, and the byte counts of `signature_pruning` are
    // monotone in the number of vectors armed.
    let bare = program_with_vectors(DEFAULT_SETTINGS, 0);
    assert_eq!(bare.run(&plain), XdpAction::Pass);
    report(
        "UDP matching nothing, no vector in the program",
        bare.ns_per_run(&plain, REPEAT),
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
        allow_entry(lorica_common::CounterId::COUNT),
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
