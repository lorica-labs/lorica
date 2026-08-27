//! The receiver's half of the phase criterion: zero false positives on the legitimate
//! reference capture, replayed on a real wire.
//!
//! `legit_trace.rs` asserts the same criterion offline, through `BPF_PROG_TEST_RUN`, which
//! hands the program a synthetic context: no driver, no NAPI poll, no DMA, and no time
//! between packets. Three of the seven stages are indifferent to that. Stage 7 is a rate
//! limiter, so pacing is a variable the offline half cannot express at all, and stage 5
//! reads an `ingress_ifindex` that test-run reports as the loopback. This file is where
//! both become real: the production object, attached natively, holding an interface while
//! the trace arrives from another machine.
//!
//! **What is asserted and what is only reported.** Every counter that names a dropped
//! packet is asserted at zero, and so is `xdp:xdp_exception`. The pass-counters are *not*
//! asserted against the `EXPECTED` table of the offline half, and that is the one real
//! difference between the two: on a wire the interface also receives ARP, neighbour
//! discovery and whatever else the lab emits, so `parse_unknown_encap` counts frames
//! nobody replayed. Their deltas are printed instead. A reader comparing the two files
//! should not conclude that one of them is wrong.
//!
//! **Why arrivals are counted separately.** Zero drops over zero arrivals is not a pass,
//! it is a run that measured nothing, and it is the single most likely way for this file
//! to lie: a replay that never started, a cable on the wrong port, a window that closed
//! before the sender opened. So `rx_packets` is read off the interface itself, on both
//! sides of the window, and a window with no arrival fails.
//!
//! **The window and the sender are on two machines.** The campaign starts this test on the
//! target and then launches the replay on the generator, so the "ready" line below is a
//! synchronisation point and not a log: it is printed and flushed the moment the program is
//! attached and the tracepoint is armed. libtest captures stdout by default, which would
//! hold that line until the test ends — the campaign has to pass `--nocapture`.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{
    env, fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use aya::{
    Ebpf,
    programs::{Xdp, xdp::XdpLinkId},
};
use lorica_common::{CounterId, setting};
use lorica_dataplane::loader::{attach_native, detach};
use support::{
    net::{Link, ip_link_mode},
    run::{COUNTER_SLOTS, load_raw, object_path, xdp_program},
};

/// The interface the replay arrives on. The measurement machine also carries `enp6s18` on
/// a live house LAN, which is why the name is checked against the lab subnet below rather
/// than trusted.
const DEFAULT_IFACE: &str = "enp6s19";

/// The policy the offline half judges the fixture under, for the same reason: the capture
/// carries ESP datagrams the path fragmented, and under the default word a later fragment
/// is refused *by design*. Judging the trace under the default would measure that decision
/// and call it a false positive.
///
/// Nothing else is armed, so stage 6 and stage 7 observe and pass. Their counters are
/// reported as `flagged` rather than as drops, and a non-zero one is still a failure: a
/// signature matching legitimate traffic is a false positive whether or not the word that
/// would have dropped it was set.
const POLICY: u32 = setting::ALLOW_LATER_FRAGMENTS;

/// The veth the self-check builds. `10.90.1.1`, so the subnet guard of the campaign path
/// accepts it unmodified and is exercised rather than bypassed.
const SELF_CHECK_OCTET: u8 = 1;

/// Long enough for a burst of pings and shorter than the campaign window: the suite runs
/// this twice and should not spend a minute proving that a veth carries frames.
const SELF_CHECK_WINDOW: Duration = Duration::from_millis(4000);

/// What a counter says about the packet it counted, under [`POLICY`].
///
/// A `match` over every variant rather than a list of names: a counter added to
/// `CounterId` stops this file from compiling until somebody says which of the three it
/// is, which is the discipline that keeps a new drop out of the "reported" bucket.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The packet is gone, decided by the program.
    Drop,
    /// The packet passed, and would not have with the stage armed.
    Flagged,
    /// The packet passed and the counter is an exception the pipeline is making, not a
    /// verdict.
    Pass,
}

const fn kind(id: CounterId) -> Kind {
    match id {
        CounterId::ParseTruncated
        | CounterId::ParseDepthExceeded
        | CounterId::SanityIpLength
        | CounterId::SanityL4Length
        | CounterId::SanityTcpFlags
        | CounterId::SanityIpOptionsRefused
        | CounterId::IcmpEchoDropped
        | CounterId::IcmpOtherDropped
        | CounterId::LpmDropHit
        | CounterId::FragmentLaterDropped
        | CounterId::UrpfNoRoute
        | CounterId::UrpfWrongInterface
        | CounterId::BogonRefused => Kind::Drop,

        CounterId::SignatureAmpDns
        | CounterId::SignatureAmpNtp
        | CounterId::SignatureAmpSsdp
        | CounterId::SignatureAmpMemcached
        | CounterId::SignatureAmpA2s
        | CounterId::SignatureAmpRaknet
        | CounterId::SignatureLoopyPortPair
        | CounterId::SignatureFragAbuse
        | CounterId::SignatureImpossibleTcpFlags
        | CounterId::SignatureLengthMismatch
        | CounterId::BucketOverBudget
        | CounterId::BucketMarked => Kind::Flagged,

        CounterId::ParseUnknownEncap
        | CounterId::IcmpPathMtuPassed
        | CounterId::IcmpNeighborPassed
        | CounterId::LpmAllowExit
        | CounterId::LpmScopeMiss
        | CounterId::LpmExpired
        | CounterId::FragmentFirstPassed
        | CounterId::FragmentLaterAllowed
        | CounterId::UrpfLookupUnsupported => Kind::Pass,
    }
}

const fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Drop => "drop",
        Kind::Flagged => "flagged",
        Kind::Pass => "pass",
    }
}

/// How long the window stays open. A parameter and not a measurement: the committed
/// fixture spans 28 s at its own pacing and the replay has to fit inside the window, so
/// the default leaves room for tcpreplay to start and the campaign shortens or lengthens
/// it with the trace it is replaying.
fn window() -> Duration {
    let ms = env::var("LORICA_WIRE_WINDOW_MS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(45_000);
    Duration::from_millis(ms)
}

/// Refuses an interface addressed outside the lab test subnet.
///
/// `replay-legit.sh` refuses the same way on the sender, and for the same reason: the
/// measurement machine's other NIC is on a live network, and attaching an XDP program to
/// it by accident is not a thing this suite should be able to do. An interface with no
/// IPv4 address is refused too — it cannot be checked, so it cannot be cleared.
fn in_test_subnet(iface: &str) -> Result<String, String> {
    let subnet = env::var("LORICA_TEST_SUBNET").unwrap_or_else(|_| "10.90.1.".to_owned());
    let out = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
        .map_err(|err| format!("cannot run ip addr show: {err}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let addr = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(3))
        .ok_or_else(|| {
            format!("{iface} has no IPv4 address, so it cannot be checked against {subnet}")
        })?;
    if addr.starts_with(&subnet) {
        Ok(addr.to_owned())
    } else {
        Err(format!(
            "{iface} is {addr}, outside the test subnet {subnet}. Refusing: this would put \
             an XDP program on a live network"
        ))
    }
}

/// Arrivals as the interface itself counts them, which is the one number no counter of
/// ours can produce: a frame that reached the driver, whatever the program then did to it.
fn rx_packets(iface: &str) -> u64 {
    let path = format!("/sys/class/net/{iface}/statistics/rx_packets");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {path}: {err}"))
        .trim()
        .parse()
        .expect("sysfs reported an rx_packets that is not a number")
}

/// Everything read on one side of the window, in the order of `CounterId::ALL`.
struct Sample {
    rx: u64,
    counters: Vec<u64>,
}

impl Sample {
    fn take(ebpf: &Ebpf, iface: &str) -> Self {
        Self {
            rx: rx_packets(iface),
            counters: CounterId::ALL
                .iter()
                .map(|id| {
                    lorica_dataplane::maps::counter_at(ebpf, COUNTER_SLOTS, id.index())
                        .expect("reading a counter failed")
                })
                .collect(),
        }
    }
}

/// What the window decided, and the drop counters that named it.
struct Record {
    rx: u64,
    exceptions: u64,
    drops: u64,
    flagged: u64,
    named: Vec<(&'static str, u64)>,
    verdict: &'static str,
}

impl Record {
    /// The criterion. Called after the detach, so a failure here cannot leave a program on
    /// the interface.
    fn assert_clean(&self, phase: &str) {
        assert!(
            self.rx > 0,
            "the {phase} window saw no arrival, so its zero drops are the zero of a run \
             that measured nothing"
        );
        assert_eq!(
            self.verdict, "pass",
            "the {phase} window dropped {} packets and flagged {}, with {} exceptions: {:?}",
            self.drops, self.flagged, self.exceptions, self.named
        );
    }
}

/// Prints the record and returns it. The format is the campaign's interface, so the field
/// order is fixed and every line carries its own key.
fn report(
    iface: &str,
    phase: &str,
    settings: u32,
    window: Duration,
    before: &Sample,
    after: &Sample,
    exceptions: u64,
) -> Record {
    let rx = after.rx - before.rx;
    let mut drops = 0;
    let mut flagged = 0;
    let mut named = Vec::new();
    for (slot, id) in CounterId::ALL.iter().enumerate() {
        let delta = after.counters[slot] - before.counters[slot];
        if delta == 0 {
            continue;
        }
        match kind(*id) {
            Kind::Drop => {
                drops += delta;
                named.push((id.name(), delta));
            }
            Kind::Flagged => {
                flagged += delta;
                named.push((id.name(), delta));
            }
            Kind::Pass => {}
        }
        println!(
            "LORICA_WIRE_COUNTER iface={iface} phase={phase} counter={} kind={} delta={delta}",
            id.name(),
            kind_name(kind(*id))
        );
    }
    let verdict = if drops == 0 && flagged == 0 && exceptions == 0 && rx > 0 {
        "pass"
    } else {
        "fail"
    };
    println!(
        "LORICA_WIRE iface={iface} phase={phase} settings=0x{settings:08x} window_ms={} \
         rx_packets={rx} xdp_exception={exceptions} drops={drops} flagged={flagged} \
         verdict={verdict}",
        window.as_millis()
    );
    Record {
        rx,
        exceptions,
        drops,
        flagged,
        named,
        verdict,
    }
}

/// Holds the window open and returns the exceptions raised over it.
///
/// perf's own `sleep` *is* the window, so there is one clock and not two: a separate sleep
/// would leave an interval at each end where the tracepoint was armed and nothing was
/// counted against it, or the reverse. `during` runs inside the window and has to finish
/// before it closes.
fn open_window(iface: &str, phase: &str, window: Duration, during: impl FnOnce()) -> u64 {
    let seconds = format!("{:.3}", window.as_secs_f64());
    // perf counts system-wide and reports on its own stderr: `perf stat --output <existing
    // file>` is refused even as root.
    let perf = Command::new("perf")
        .args([
            "stat",
            "-e",
            "xdp:xdp_exception",
            "-a",
            "--",
            "sleep",
            &seconds,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot run perf stat");

    println!(
        "LORICA_WIRE_READY iface={iface} phase={phase} window_ms={} mode={}",
        window.as_millis(),
        ip_link_mode(iface)
    );
    // Flushed, not printed: the sender is on another machine and starts when it reads this
    // line. A line that arrives late means the replay went into a window that never opened.
    std::io::stdout().flush().expect("cannot flush stdout");

    during();
    let output = perf.wait_with_output().expect("perf did not finish");
    exception_count(&String::from_utf8_lossy(&output.stderr))
}

/// The count perf printed, refused rather than defaulted when it is absent or not a
/// number: a guard that reads nothing and compares it against zero passes for the wrong
/// reason. Read the same way in `xdp_exception.rs`, and duplicated rather than shared
/// because `support` is edited by several tasks at once.
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
    raw.replace([',', '.', '\u{202f}', '\u{a0}'], "")
        .parse()
        .unwrap_or_else(|_| {
            panic!("perf did not count the tracepoint, it printed {raw:?} in:\n{report}")
        })
}

/// Off the hook before anything is asserted. A program left attached is the 58 % of
/// receive throughput the next campaign would pay, and an assertion unwinds.
fn detach_now(ebpf: &mut Ebpf, link: XdpLinkId, iface: &str) {
    let program: &mut Xdp = ebpf
        .program_mut(support::PROGRAM)
        .expect("the program disappeared")
        .try_into()
        .expect("the program is not an XDP program");
    detach(program, link, iface).expect("detaching from the interface failed");
}

/// One window on one interface: load, attach natively, sample, hold, detach, report.
fn measure(
    iface: &str,
    phase: &str,
    settings: u32,
    window: Duration,
    during: impl FnOnce(),
) -> Record {
    let mut ebpf = load_raw(&object_path(), settings);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let link = attach_native(program, iface).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(
        ip_link_mode(iface),
        "xdp",
        "generic mode does not exercise the driver path the criterion is about"
    );

    let before = Sample::take(&ebpf, iface);
    let exceptions = open_window(iface, phase, window, during);
    let after = Sample::take(&ebpf, iface);
    detach_now(&mut ebpf, link, iface);

    report(iface, phase, settings, window, &before, &after, exceptions)
}

/// The campaign. Holds the interface for the window while the generator replays the
/// capture, and reports what the program decided about it.
///
/// Skipped where there is no such interface, which is every machine but the measurement
/// one: the traffic comes from outside the host, so there is nothing this test could build
/// for itself. What it *cannot* be is silently green on the wrong device — an interface
/// that exists and is addressed outside the lab subnet is a refusal, not a skip.
#[test]
fn the_legitimate_replay_loses_no_packet_on_the_wire() {
    let iface = env::var("LORICA_IFACE").unwrap_or_else(|_| DEFAULT_IFACE.to_owned());
    if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
        eprintln!(
            "SKIP wire: this host has no {iface}. LORICA_IFACE names the interface the \
             replay arrives on, and the traffic comes from another machine"
        );
        return;
    }
    let addr = in_test_subnet(&iface).unwrap_or_else(|err| panic!("{err}"));
    println!("LORICA_WIRE_IFACE iface={iface} addr={addr}");

    measure(&iface, "replay", POLICY, window(), || {}).assert_clean("replay");
}

/// The same instrument against traffic this host can produce, so that everything but the
/// pcap is exercised where no campaign machine is available: the guard, the native attach,
/// the arrival count, the sampling and the detach.
///
/// Two windows, and the second is the negative control. Without it a file like this one
/// only ever passes, which proves that it runs and not that it can fail: the control arms
/// `DROP_ICMP_ECHO`, so every echo request of the burst is dropped on purpose, and the
/// drop total has to move and name `icmp_echo_dropped`. Two windows in one test rather
/// than two tests, because both need `10.90.1.1` and libtest would run them at the same
/// time on one routing table.
#[test]
fn real_frames_are_measured_and_a_deliberate_drop_fails_the_verdict() {
    let (link, near) = Link::wired("lori-wire", SELF_CHECK_OCTET);
    if let Err(err) = in_test_subnet(&link.name) {
        eprintln!("SKIP wire self-check: {err}");
        return;
    }
    // 100 frames at 20 ms is two seconds, which fits inside the window with room to
    // spare. `ping` needs root below 200 ms and the kernel tests run under sudo.
    let burst = || {
        link.in_netns(&["ping", "-q", "-c", "100", "-i", "0.02", "-W", "1", &near])
            .ok();
    };

    let clean = measure(&link.name, "veth-clean", POLICY, SELF_CHECK_WINDOW, burst);
    clean.assert_clean("veth-clean");

    let control = measure(
        &link.name,
        "veth-control",
        POLICY | setting::DROP_ICMP_ECHO,
        SELF_CHECK_WINDOW,
        burst,
    );
    assert_eq!(
        control.verdict, "fail",
        "the control window dropped {} packets on purpose and the verdict still reads \
         pass, so the verdict line cannot fail",
        control.drops
    );
    assert!(
        control
            .named
            .contains(&("icmp_echo_dropped", control.drops)),
        "the control window reported {} drops named {:?}, and the echo requests it drops \
         on purpose are not among them",
        control.drops,
        control.named
    );
    assert_eq!(
        control.exceptions, 0,
        "the driver raised {} exceptions while {} packets were dropped on purpose",
        control.exceptions, control.drops
    );
}
