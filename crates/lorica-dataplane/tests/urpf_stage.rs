//! Stage 5, role-conditional strict reverse-path filtering.
//!
//! The stage exists for one case — a source whose route back leaves by another interface —
//! and the rest of this file is about not breaking everything else on the way there.
//! `bpf_fib_lookup` has nine return codes and only one of them is about the packet:
//! `FWD_DISABLED` is the answer a host that does not forward gives to every frame, and a
//! stage that read it as "no route back" would drop all traffic on the ordinary target of
//! this tier. Both halves are asserted here, and the second one is not a corner case.
//!
//! What makes these tests heavier than the other stage tests is that a reverse-path lookup
//! is a question about a routing table, so there has to be one, on an interface the frame
//! can be said to have arrived on. `BPF_PROG_TEST_RUN` presents every frame as arriving on
//! the loopback receive queue, so the ingress interface goes in through `ctx_in`
//! ([`TestProg::run_from`]) and the interfaces and routes are built here. A host that
//! refuses to build them skips loudly: an assertion that runs against `FWD_DISABLED`
//! passes while testing nothing, which is the false pass this file is most exposed to.

#![cfg(feature = "kernel-tests")]

mod support;

use std::fs;

use lorica_common::setting;
use support::{
    PktBuilder, XdpAction,
    net::{self, Link},
    program, program_with,
};

/// The three counters of the stage, read together whenever the assertion is that none of
/// them moved.
const URPF_COUNTERS: [&str; 3] = [
    "urpf_no_route",
    "urpf_wrong_interface",
    "urpf_lookup_unsupported",
];

/// A legitimate UDP frame whose source address is the one thing under examination.
fn udp_from(src: [u8; 4]) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(1111, 30_120)
        .build()
}

/// Whether the ingress device forwards. `bpf_ipv4_fib_lookup` checks this before it looks
/// at the table at all, so it is what decides between a real answer and `FWD_DISABLED`.
/// Per device, so it disappears with the interface and nothing global is touched.
fn set_forwarding(iface: &str, on: bool) -> std::io::Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/forwarding");
    fs::write(path, if on { "1" } else { "0" })
}

/// An interface that forwards, addressed inside `10.90.<octet>.0/24` — which is also what
/// installs the connected route the reverse-path lookup has to find, so no route has to be
/// added by hand for the two cases that need one.
///
/// A `dummy` and not a `veth`: nothing here sends a packet down the wire, the frames go
/// through `BPF_PROG_TEST_RUN`, and what is needed of the interface is an index and a
/// routing table entry that points at it.
///
/// `None`, loudly, on a host that refuses either step.
fn forwarding_link(name: &str, octet: u8) -> Option<(Link, u32)> {
    let link = Link::dummy(name);
    if let Err(err) = net::ip(&["addr", "add", &format!("10.90.{octet}.1/24"), "dev", name]) {
        eprintln!("SKIP {name}: cannot address the interface: {err}");
        return None;
    }
    if let Err(err) = set_forwarding(name, true) {
        eprintln!("SKIP {name}: cannot enable forwarding: {err}");
        return None;
    }
    let index = net::ifindex(name);
    Some((link, index))
}

/// A route added for one test and removed with it. [`Link`] takes its own routes with it
/// when the interface goes; a route that names a policy rather than a device belongs to
/// nothing and would outlive the run.
struct Route(String);

impl Route {
    fn add(kind: &str, prefix: &str) -> Self {
        let _ = net::ip(&["route", "del", prefix]);
        net::ip(&["route", "add", kind, prefix])
            .unwrap_or_else(|err| panic!("adding the {kind} route for {prefix} failed: {err}"));
        Self(prefix.to_owned())
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        let _ = net::ip(&["route", "del", &self.0]);
    }
}

/// With the bit clear the stage is not a cheaper stage, it is no stage: no verdict, no
/// counter, whatever the packet. The two sources below are the two the armed stage would
/// have an opinion about.
#[test]
fn the_stage_is_silent_until_the_loader_arms_it() {
    let prog = program();
    let before: Vec<u64> = URPF_COUNTERS
        .iter()
        .map(|name| prog.counter(name))
        .collect();

    for src in [[10, 90, 71, 5], [203, 0, 113, 1]] {
        assert_eq!(prog.run(&udp_from(src)), XdpAction::Pass, "{src:?}");
    }

    for (name, was) in URPF_COUNTERS.iter().zip(before) {
        assert_eq!(
            prog.counter(name),
            was,
            "{name} moved with URPF_ENFORCE clear"
        );
    }
}

/// The legitimate packet: the table has a path back to the source and it leaves by the
/// interface the packet arrived on.
#[test]
fn a_source_routed_out_of_the_ingress_interface_passes() {
    let Some((_ingress, ifindex)) = forwarding_link("urpf-good", 71) else {
        return;
    };

    let prog = program_with(setting::URPF_ENFORCE);
    let before: Vec<u64> = URPF_COUNTERS
        .iter()
        .map(|name| prog.counter(name))
        .collect();

    assert_eq!(
        prog.run_from(&udp_from([10, 90, 71, 5]), ifindex),
        XdpAction::Pass,
        "the source is routed back out of the interface it arrived on"
    );

    for (name, was) in URPF_COUNTERS.iter().zip(before) {
        assert_eq!(
            prog.counter(name),
            was,
            "{name} moved on a legitimate source"
        );
    }
}

/// The discriminating case, and the reason the stage exists. The source is perfectly
/// reachable — just not this way round, which is what a spoofed source looks like from the
/// data plane.
#[test]
fn a_source_routed_out_of_another_interface_is_dropped() {
    let Some((_ingress, ifindex)) = forwarding_link("urpf-in", 72) else {
        return;
    };
    let Some((_elsewhere, _)) = forwarding_link("urpf-out", 73) else {
        return;
    };

    let prog = program_with(setting::URPF_ENFORCE);
    let before = prog.counter("urpf_wrong_interface");

    assert_eq!(
        prog.run_from(&udp_from([10, 90, 73, 5]), ifindex),
        XdpAction::Drop,
        "a source whose route back leaves by another interface is the spoof this stage catches"
    );
    assert_eq!(prog.counter("urpf_wrong_interface"), before + 1);
}

/// The decision this test records, so a later reader sees it was decided: a source the
/// table has no path back to is **dropped**. That is defensible only because of the
/// criterion — the stage is armed only where the loader found no default route on the
/// ingress interface, so a source the table cannot reach is one this host has no business
/// believing in. Where a default route exists every source resolves, this class is empty,
/// and the criterion disarms the stage instead.
///
/// Which is also why the class cannot be produced here by leaving the table empty: the lab
/// host has a default route, and moving the test process into its own network namespace to
/// escape it is a re-exec this suite does not do. The table is made to say "no path" in as
/// many words instead. Three of the four codes of the class, through one arm and one
/// counter.
#[test]
fn a_source_with_no_path_back_is_dropped() {
    let Some((_ingress, ifindex)) = forwarding_link("urpf-none", 74) else {
        return;
    };
    let _routes = [
        Route::add("blackhole", "203.0.113.0/25"),
        Route::add("unreachable", "203.0.113.128/26"),
        Route::add("prohibit", "203.0.113.192/26"),
    ];

    let prog = program_with(setting::URPF_ENFORCE);
    let before = prog.counter("urpf_no_route");

    for src in [[203, 0, 113, 1], [203, 0, 113, 130], [203, 0, 113, 200]] {
        assert_eq!(
            prog.run_from(&udp_from(src), ifindex),
            XdpAction::Drop,
            "{src:?} has no path back"
        );
    }
    assert_eq!(prog.counter("urpf_no_route"), before + 3);
}

/// The code the lab actually produces, and the one that would make this stage a
/// catastrophe if it were read as a verdict about the packet. `FWD_DISABLED` comes back
/// before the table is consulted at all, off the forwarding flag of the ingress device, so
/// on a host that does not route it is the answer for every frame.
///
/// The source used here has no path back either, so if the two classes were confused this
/// frame would be dropped — which on such a host means every frame.
#[test]
fn a_host_that_does_not_forward_passes_everything() {
    let link = Link::dummy("urpf-nofwd");
    set_forwarding(&link.name, false).expect("cannot clear forwarding on a fresh interface");
    let ifindex = net::ifindex(&link.name);

    let prog = program_with(setting::URPF_ENFORCE);
    let before = prog.counter("urpf_lookup_unsupported");
    let no_route_before = prog.counter("urpf_no_route");

    assert_eq!(
        prog.run_from(&udp_from([203, 0, 113, 1]), ifindex),
        XdpAction::Pass,
        "a lookup that could not answer must not become a verdict"
    );
    assert_eq!(prog.counter("urpf_lookup_unsupported"), before + 1);
    assert_eq!(
        prog.counter("urpf_no_route"),
        no_route_before,
        "FWD_DISABLED was counted as a missing route"
    );
}

/// The lookup is the most expensive call in the program, so the instrumented count has to
/// see it — and see it only where it is issued. The gate is a compare against a `.rodata`
/// word the verifier folds into an immediate, so with the bit clear the call is not
/// reached at all rather than reached and discarded.
#[cfg(feature = "count-helpers")]
#[test]
fn the_lookup_is_counted_and_only_where_it_is_issued() {
    let Some((_ingress, ifindex)) = forwarding_link("urpf-count", 75) else {
        return;
    };
    let pkt = udp_from([10, 90, 75, 5]);

    let armed = program_with(setting::URPF_ENFORCE);
    let before = armed.helper_counts();
    assert_eq!(armed.run_from(&pkt, ifindex), XdpAction::Pass);
    let counts = armed.helper_counts().since(before);
    assert_eq!(counts.fib_lookups, 1, "got {counts:?}");

    let idle = program();
    let before = idle.helper_counts();
    assert_eq!(idle.run_from(&pkt, ifindex), XdpAction::Pass);
    let counts = idle.helper_counts().since(before);
    assert_eq!(
        counts.fib_lookups, 0,
        "the gate did not keep the lookup out of the path: {counts:?}"
    );
}
