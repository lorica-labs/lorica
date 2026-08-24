//! Assertion 4: no unintended drops, strict.
//!
//! `xdp:xdp_exception` fires when the driver sees `XDP_ABORTED` or a return value it does
//! not recognise. Either is a correctness bug wearing a statistic as a disguise: the
//! packet is gone, no counter of ours moved, and nothing in the program knows it
//! happened. The threshold is zero and there is no tolerance to tune.
//!
//! The hard part is not counting the tracepoint, it is making sure packets actually
//! crossed. A count of zero over a period when nothing was attached, or when the traffic
//! never reached the interface, reads exactly like a clean run — so this test proves the
//! program ran, from its own counters, before it believes the zero.

#![cfg(feature = "kernel-tests")]

mod support;

use std::process::{Command, Stdio};

use lorica_common::setting;
use support::{
    net::{Link, ip_link_mode},
    run::{load_raw, object_path, xdp_program},
};

const ECHOES: u32 = 40;

#[test]
fn deliberate_drops_under_real_traffic_raise_no_exception() {
    let (link, near) = Link::wired("lori-exc", 77);

    // Echo is dropped by configuration, which gives the run a deliberate drop to count.
    // A stage that drops on purpose is the interesting case: the assertion has to
    // distinguish a drop the program decided from a drop the driver had to make.
    let mut ebpf = load_raw(&object_path(), setting::DROP_ICMP_ECHO);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let _attached = lorica_dataplane::loader::attach_native(program, &link.name)
        .expect("attaching to the test interface failed");
    assert_eq!(
        ip_link_mode(&link.name),
        "xdp",
        "generic mode would not exercise the driver path this tracepoint lives on"
    );

    let before = read_counter(&ebpf, "icmp_echo_dropped");

    // perf counts system-wide for the length of the ping, and its own stderr is the
    // report: `perf stat --output <existing file>` is refused even as root.
    // The binary and not the name: Ubuntu's `perf` wrapper dispatches on `uname -r`, and under
    // virtme-ng the booted kernel has no linux-tools of its own, so the wrapper counts
    // nothing. `kernel-matrix.sh` resolves one and states it here.
    let perf_bin = std::env::var("LORICA_PERF").unwrap_or_else(|_| "perf".to_owned());
    let perf = Command::new(&perf_bin)
        .args(["stat", "-e", "xdp:xdp_exception", "-a", "--", "sleep", "6"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("cannot run {perf_bin}: {err}"));

    link.in_netns(&[
        "ping",
        "-c",
        &ECHOES.to_string(),
        "-i",
        "0.02",
        "-W",
        "1",
        &near,
    ])
    // The pings are dropped by design, so ping exits non-zero. That is the point, and
    // its exit status carries no information here.
    .ok();

    let output = perf.wait_with_output().expect("perf did not finish");
    let report = String::from_utf8_lossy(&output.stderr).into_owned();

    let after = read_counter(&ebpf, "icmp_echo_dropped");
    assert!(
        after > before,
        "no packet reached the program, so a count of zero exceptions would prove \
         nothing. icmp_echo_dropped went {before} -> {after}"
    );

    let exceptions = exception_count(&report);
    println!(
        "{} packets dropped by policy, {exceptions} exceptions",
        after - before
    );
    assert_eq!(
        exceptions,
        0,
        "the driver raised {exceptions} xdp_exception while {} packets were dropped on \
         purpose. perf said:\n{report}",
        after - before
    );
}

/// The count perf printed, refused rather than defaulted when it is absent or not a
/// number. A guard that reads an empty value and compares it against zero passes for the
/// wrong reason, which is the worst way for a guard to behave.
fn exception_count(report: &str) -> u64 {
    let line = report
        .lines()
        .find(|line| line.contains("xdp:xdp_exception"))
        .unwrap_or_else(|| {
            panic!(
                "perf printed no line for xdp:xdp_exception, so nothing was counted. \
                 It said:\n{report}"
            )
        });
    let raw = line
        .split_whitespace()
        .next()
        .expect("the perf line is empty");
    // perf groups thousands with a locale separator, and prints <not counted> or
    // <not supported> when the event never armed. Both have to be refusals.
    raw.replace([',', '.', '\u{202f}', '\u{a0}'], "")
        .parse()
        .unwrap_or_else(|_| {
            panic!("perf did not count the tracepoint, it printed {raw:?} in:\n{report}")
        })
}

fn read_counter(ebpf: &aya::Ebpf, name: &str) -> u64 {
    use aya::maps::{MapData, PerCpuArray};
    let id = lorica_common::CounterId::from_name(name)
        .unwrap_or_else(|| panic!("no counter named {name}"));
    let map = ebpf.map("COUNTERS").expect("no COUNTERS map");
    let counters: PerCpuArray<&MapData, u64> =
        PerCpuArray::try_from(map).expect("COUNTERS is not a per-CPU array");
    counters
        .get(&id.index(), 0)
        .expect("reading a counter failed")
        .iter()
        .sum()
}
