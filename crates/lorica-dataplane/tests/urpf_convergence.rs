//! The second half of the phase criterion: under legitimate traffic, removing then
//! restoring a route costs zero legitimate drops.
//!
//! That sentence has two readings and they are not the same test, so both are here.
//!
//! **Reading A.** The interface carries a default route, so the criterion says the stage
//! decides nothing and `URPF_ENFORCE` stays clear. The default route goes away and comes
//! back inside a window shorter than `DEFAULT_HOLD`. The watcher must report no flip, so
//! nothing reloads, so the attached program keeps the setting it was loaded with and not
//! one packet is dropped. This is what the hysteresis is for, and it is the reading the
//! criterion is written against.
//!
//! **Reading B.** The stage is already armed, because the loader found no default route.
//! A specific route to a legitimate peer goes away and comes back. `URPF_ENFORCE` is a
//! `.rodata` global fixed at load, so the attached program cannot soften; the FIB answers
//! "no path back" for that peer for as long as the route is gone and the stage drops. The
//! hysteresis does not help here — it delays *reload decisions*, not the FIB's own answer.
//! So reading B is not asserted to be zero. It is measured, and the number is the
//! exposure the design accepts.
//!
//! **Why a namespace of its own.** The criterion is a predicate over a routing table, and
//! the build-and-test VM has policy routing: an overlay agent parks routes in table 7120,
//! which makes `discriminates()` answer `PolicyRouting` for every interface, forever,
//! whatever this file adds. There is no arming transition to observe on that table. So the
//! test thread unshares its network namespace and builds the whole table itself — the
//! veth, the addresses, the default route, and nothing else. `unshare(CLONE_NEWNET)` is
//! per-thread, so one test's namespace is not another's, and the routes, the netlink
//! subscription and the attach all land in the same one.
//!
//! **Why a real attach and real frames.** A reverse-path lookup needs a real
//! `ingress_ifindex`, which is why `urpf_stage.rs` had to hand-build a `struct xdp_md`:
//! `BPF_PROG_TEST_RUN` reports the loopback. Here the frames come off a wire, through a
//! native attach, so the interface the stage asks about is the interface the packet
//! arrived on. Nothing in this file is a fixture except the addresses.
//!
//! **What is counted, and why not only the drops.** "Zero legitimate drops" is worth
//! nothing next to a phase where the traffic never arrived: both read as zero. So every
//! packet of every phase is accounted for on the program's own side of the wire — either
//! it is answered, which the sender counts as a reply, or a counter of the stage names it.
//! A phase where the two do not add up to what was sent is a failed measurement and says
//! so.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{
    ffi::CString,
    fs, io,
    process::Command,
    time::{Duration, Instant},
};

use aya::Ebpf;
use lorica_common::{CounterId, DEFAULT_SETTINGS, setting};
use lorica_dataplane::{
    fib::{DEFAULT_HOLD, Discrimination, RouteWatcher},
    loader::attach_native,
};
use support::{
    net::{ip, ip_link_mode},
    run::{COUNTER_SLOTS, load_raw, object_path, xdp_program},
};

/// The near side, on the interface the program is attached to, and the destination of
/// every burst.
const NEAR: &str = "10.90.78.1";
/// The peer. Addressing the two sides installs the connected route, which is the route
/// back that makes traffic from here legitimate.
const FAR: &str = "10.90.78.2";
/// A second address on the same peer, reachable only through a route this file adds by
/// hand. Reading B flaps that route rather than the connected one, so the peer keeps its
/// resolved neighbour entry across the window and a lost frame cannot be an unresolved
/// ARP wearing the costume of a drop.
const FAR_ALT: &str = "10.91.78.2";
const ALT_NET: &str = "10.91.78.0/24";

/// One frame every 20 ms, which is the interval `xdp_exception.rs` already sends at on
/// this hardware. `ping` needs root for anything below 200 ms and the kernel tests run
/// under sudo.
const INTERVAL_MS: u64 = 20;

/// How long each phase lasts. A parameter and not a measurement: the exposure of reading
/// B is a rate, so the campaign that reads these lines chooses the window it wants to
/// price and this default only has to be long enough to be more than a handful of frames
/// and short enough to fit several times inside the 30 s hysteresis.
fn window() -> Duration {
    let ms = std::env::var("LORICA_CONV_WINDOW_MS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(2000);
    Duration::from_millis(ms)
}

/// The kernel index of an interface, asked of the kernel rather than read out of sysfs.
///
/// `/sys/class/net` belongs to the namespace `/sys` was mounted in, and this thread left
/// that namespace without remounting anything, so `support::net::ifindex` would report
/// "no such file" for an interface that is right there. `if_nametoindex` goes through a
/// socket, which follows the calling thread.
fn ifindex(iface: &str) -> u32 {
    let name = CString::new(iface).expect("an interface name with a NUL in it");
    // SAFETY: a NUL-terminated name, and the call only reads it.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    assert_ne!(index, 0, "the kernel does not know an interface {iface}");
    index
}

/// The three counters of the stage, read together because the interesting assertions are
/// about which of them moved.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Urpf {
    no_route: u64,
    wrong_interface: u64,
    unsupported: u64,
}

impl Urpf {
    fn read(ebpf: &Ebpf) -> Self {
        Self {
            no_route: counter(ebpf, "urpf_no_route"),
            wrong_interface: counter(ebpf, "urpf_wrong_interface"),
            unsupported: counter(ebpf, "urpf_lookup_unsupported"),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            no_route: self.no_route - before.no_route,
            wrong_interface: self.wrong_interface - before.wrong_interface,
            unsupported: self.unsupported - before.unsupported,
        }
    }

    /// The two arms that end in `XDP_DROP`. `unsupported` is a pass and is reported
    /// separately, because on a host that does not forward it is every frame.
    const fn drops(self) -> u64 {
        self.no_route + self.wrong_interface
    }
}

fn counter(ebpf: &Ebpf, name: &str) -> u64 {
    let id = CounterId::from_name(name).unwrap_or_else(|| panic!("no counter named {name}"));
    lorica_dataplane::maps::counter_at(ebpf, COUNTER_SLOTS, id.index())
        .expect("reading a counter failed")
}

/// A wire, in a network namespace this thread owns, with the peer in one of its own.
struct Lab {
    iface: String,
    peer: String,
    peer_ns: String,
    ifindex: u32,
}

impl Lab {
    /// `None`, loudly, on a host that refuses a step. A test that cannot build its
    /// preconditions and passes anyway is the false pass this whole file is exposed to:
    /// zero drops is also what a run with no traffic reports.
    fn build(tag: &str, forwarding: bool) -> Option<Self> {
        let iface = format!("lori-{tag}");
        let peer_ns = format!("{iface}-ns");
        // Named namespaces live in a mount this thread is about to stop sharing a network
        // namespace with, so the peer's namespace is created first, from here.
        let _ = ip(&["netns", "del", &peer_ns]);
        if let Err(err) = ip(&["netns", "add", &peer_ns]) {
            eprintln!("SKIP {tag}: cannot create the peer namespace: {err}");
            return None;
        }
        let mut lab = Self {
            peer: format!("{iface}p"),
            iface,
            peer_ns,
            ifindex: 0,
        };
        match lab.wire(forwarding) {
            Ok(()) => Some(lab),
            Err(err) => {
                eprintln!("SKIP {tag}: {err}");
                None
            }
        }
    }

    fn wire(&mut self, forwarding: bool) -> Result<(), String> {
        // SAFETY: unshare with CLONE_NEWNET touches nothing outside this thread's network
        // namespace, and libtest gives each test its own thread.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(format!(
                "cannot unshare the network namespace: {}",
                io::Error::last_os_error()
            ));
        }
        ip(&[
            "link",
            "add",
            &self.iface,
            "type",
            "veth",
            "peer",
            "name",
            &self.peer,
        ])?;
        ip(&["link", "set", &self.peer, "netns", &self.peer_ns])?;

        // Off on both ends, before either is up. IPv6 on a fresh veth means neighbour
        // discovery and MLD for several seconds, and every one of those is an IP frame the
        // stage has an opinion about: with the stage armed, two of them were counted as
        // `urpf_no_route` inside the first measured phase, which is a drop this file did
        // not cause and cannot account for. It also settles the criterion on one family,
        // since a disabled interface has no link-local route for IPv6 to be judged on.
        let path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", self.iface);
        fs::write(&path, "1").map_err(|err| format!("cannot write {path}: {err}"))?;
        self.in_peer(&[
            "sysctl",
            "-qw",
            &format!("net.ipv6.conf.{}.disable_ipv6=1", self.peer),
        ])?;

        ip(&["addr", "add", &format!("{NEAR}/24"), "dev", &self.iface])?;
        ip(&["link", "set", &self.iface, "up"])?;
        self.in_peer(&["ip", "addr", "add", &format!("{FAR}/24"), "dev", &self.peer])?;
        self.in_peer(&[
            "ip",
            "addr",
            "add",
            &format!("{FAR_ALT}/24"),
            "dev",
            &self.peer,
        ])?;
        self.in_peer(&["ip", "link", "set", &self.peer, "up"])?;

        // `bpf_ipv4_fib_lookup` reads the ingress device's forwarding flag before it
        // consults the table at all, so without this the answer for every frame is
        // `FWD_DISABLED` and the stage decides nothing. That is not a detail of the
        // fixture: it is the state the tier-1 target of this product is actually in, which
        // is why one of the tests below leaves it off on purpose.
        let path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", self.iface);
        fs::write(&path, if forwarding { "1" } else { "0" })
            .map_err(|err| format!("cannot write {path}: {err}"))?;
        self.ifindex = ifindex(&self.iface);
        Ok(())
    }

    fn in_peer(&self, argv: &[&str]) -> Result<(), String> {
        let out = self.peer_output(argv);
        if out.status {
            Ok(())
        } else {
            Err(format!("{argv:?} in the peer namespace: {}", out.text))
        }
    }

    fn peer_output(&self, argv: &[&str]) -> PeerOutput {
        let out = Command::new("ip")
            .args(["netns", "exec", &self.peer_ns])
            .args(argv)
            .output()
            .expect("cannot run ip netns exec");
        PeerOutput {
            status: out.status.success(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    /// A burst of real frames from the peer, and what the peer saw of them.
    ///
    /// `ping` and not a sender of our own: it is on this machine, `xdp_exception.rs`
    /// already depends on it, and its reply count is the one arrival number no counter of
    /// ours can produce — a frame that reached the stack and was answered. Echo requests
    /// pass every earlier stage with the default policy word, so what a drop here means is
    /// stage five.
    fn burst(&self, source: Option<&str>, count: u64) -> (u64, u64) {
        let count = count.to_string();
        let interval = format!("0.{INTERVAL_MS:03}");
        let mut argv = vec!["ping", "-q", "-c", &count, "-i", &interval, "-W", "1"];
        if let Some(source) = source {
            argv.extend(["-I", source]);
        }
        argv.push(NEAR);
        // A phase where every frame is dropped is a phase where ping exits non-zero, and
        // that is the phase reading B exists to measure, so the status carries nothing.
        tally(&self.peer_output(&argv).text)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        // The veth and its routes go with the thread's namespace. The peer's namespace is
        // named, so it does not.
        let _ = ip(&["netns", "del", &self.peer_ns]);
    }
}

struct PeerOutput {
    status: bool,
    text: String,
}

/// Transmitted and received, off ping's own statistics line.
///
/// Refused rather than defaulted when the line is absent: a zero read out of nothing
/// compares equal to a clean run, which is the way a guard fails worst.
fn tally(report: &str) -> (u64, u64) {
    let line = report
        .lines()
        .find(|line| line.contains("packets transmitted"))
        .unwrap_or_else(|| panic!("ping printed no statistics line:\n{report}"));
    let mut numbers = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|word| !word.is_empty())
        .map(|word| word.parse().expect("a digit run that does not parse"));
    let sent = numbers.next().expect("no transmitted count");
    let received = numbers.next().expect("no received count");
    (sent, received)
}

/// One phase of a flap.
#[derive(Clone, Copy)]
struct Phase {
    sent: u64,
    received: u64,
    urpf: Urpf,
}

impl Phase {
    /// Every frame the sender sent, named by something on this side of the wire.
    ///
    /// Two readings, and the account is the larger. A frame is either answered or dropped
    /// by the stage, which is the first; or it is one the stage counted as a lookup it
    /// could not answer, which is the second and is *not* exclusive with the first — such
    /// a frame passed and was answered too. The second reading is the only witness left in
    /// a phase where the reply has no route home, and a phase where neither reaches what
    /// was sent lost frames for a reason this test does not know.
    fn accounted(&self) -> u64 {
        (self.received + self.urpf.drops()).max(self.urpf.unsupported)
    }
}

/// Waits for the wire to stop carrying frames this file did not send.
///
/// An interface that has just come up sends its IGMP membership reports twice, about a
/// second apart, and the second one lands after the attach: it showed up as one extra
/// `urpf_lookup_unsupported` in the first measured phase, which is one frame the
/// per-phase accounting could not name. Three quiet readings a quarter of a second apart
/// is the shortest thing that outlasts it, and on a quiet wire it costs three quarters of
/// a second per test.
fn settle(ebpf: &Ebpf) {
    let mut last = Urpf::read(ebpf);
    let mut quiet = 0;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(250));
        let now = Urpf::read(ebpf);
        quiet = if now == last { quiet + 1 } else { 0 };
        if quiet == 3 {
            return;
        }
        last = now;
    }
    eprintln!(
        "the wire never went quiet: the stage is still counting frames nobody sent, and \
         the phases below will not add up"
    );
}

/// The scenario under way: the wire, the loaded program, and the watcher whose silence is
/// the claim of reading A.
struct Run<'a> {
    lab: &'a Lab,
    ebpf: &'a Ebpf,
    reading: &'static str,
    forwarding: u8,
    source: Option<&'static str>,
    watcher: RouteWatcher,
    /// Every flip the watcher reported over the whole run. A reported flip is a program
    /// reload, so for reading A this has to stay empty.
    reloads: Vec<Discrimination>,
}

impl<'a> Run<'a> {
    fn new(
        lab: &'a Lab,
        ebpf: &'a Ebpf,
        reading: &'static str,
        forwarding: u8,
        source: Option<&'static str>,
    ) -> Self {
        let watcher = RouteWatcher::new(lab.ifindex, DEFAULT_HOLD)
            .expect("the route dump failed in the test namespace");
        settle(ebpf);
        Self {
            lab,
            ebpf,
            reading,
            forwarding,
            source,
            watcher,
            reloads: Vec::new(),
        }
    }

    /// Drains the subscription and records whatever it decided. Called on both sides of
    /// every route change, so a flip that only shows up after the traffic has stopped is
    /// still seen.
    fn poll(&mut self) -> Option<Discrimination> {
        let reported = self
            .watcher
            .poll()
            .expect("draining the subscription failed");
        if let Some(decision) = reported {
            self.reloads.push(decision);
        }
        reported
    }

    /// The criterion's answer to the table as it stands, with no hysteresis in the way.
    ///
    /// A second watcher with a zero window rather than a peek at the first one's state:
    /// this is the negative control of reading A. Without it, a watcher that stays silent
    /// because the criterion never moved is indistinguishable from a watcher held quiet by
    /// its hold time, and only the second proves anything.
    fn live(&self) -> Discrimination {
        RouteWatcher::new(self.lab.ifindex, Duration::ZERO)
            .expect("the route dump failed")
            .decision()
    }

    /// One phase: drain, send, drain, and print the line the campaign parses.
    fn phase(&mut self, name: &str) -> Phase {
        self.poll();
        let before = Urpf::read(self.ebpf);
        let started = Instant::now();
        let (sent, received) = self
            .lab
            .burst(self.source, window().as_millis() as u64 / INTERVAL_MS);
        let elapsed = started.elapsed();
        let urpf = Urpf::read(self.ebpf).since(before);
        let reload = self.poll();
        let phase = Phase {
            sent,
            received,
            urpf,
        };
        println!(
            "LORICA_CONV reading={} phase={name} elapsed_ms={} forwarding={} sent={sent} \
             received={received} drops={} no_route={} wrong_if={} unsupported={} live={:?} \
             reported={:?} reload={}",
            self.reading,
            elapsed.as_millis(),
            self.forwarding,
            urpf.drops(),
            urpf.no_route,
            urpf.wrong_interface,
            urpf.unsupported,
            self.live(),
            self.watcher.decision(),
            match reload {
                Some(decision) => format!("{decision:?}"),
                None => "none".to_owned(),
            },
        );
        assert!(
            sent > 0,
            "the {name} phase sent nothing, so it measured nothing"
        );
        assert_eq!(
            phase.accounted(),
            sent,
            "the {name} phase sent {sent} frames and this side of the wire accounts for \
             {}: {received} answered, {} dropped, {} unanswerable. The difference vanished \
             for a reason this test does not know, so its drop count means nothing",
            phase.accounted(),
            urpf.drops(),
            urpf.unsupported
        );
        phase
    }
}

/// Reading A. The interface carries a default route, so the criterion says the stage
/// decides nothing and the loader leaves `URPF_ENFORCE` clear. The route goes away and
/// comes back well inside the 30 s hold, and the whole claim is that this costs nothing:
/// no reported flip, so no reload, so no packet dropped.
///
/// The zero here is not the interesting half — with the stage unarmed it could hardly be
/// anything else. What is asserted is that the watcher stayed silent *while the criterion
/// had already flipped*, which `live()` establishes before the window opens.
#[test]
fn a_flap_inside_the_hold_reports_nothing_and_drops_nothing() {
    let Some(lab) = Lab::build("convA", true) else {
        return;
    };
    if let Err(err) = ip(&["route", "add", "default", "via", FAR, "dev", &lab.iface]) {
        eprintln!("SKIP convA: cannot install the default route: {err}");
        return;
    }

    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let _link = attach_native(program, &lab.iface).expect("attaching to the test veth failed");
    assert_eq!(
        ip_link_mode(&lab.iface),
        "xdp",
        "generic mode does not exercise the driver path these frames arrive on"
    );

    let mut run = Run::new(&lab, &ebpf, "A", 1, None);
    assert!(
        !run.watcher.decision().enforce(),
        "the interface carrying the default route arms the stage: {}",
        run.watcher.decision()
    );
    let settled = run.watcher.decision();
    let before = run.phase("before");

    ip(&["route", "del", "default"]).expect("removing the default route failed");
    let opened = Instant::now();
    // The negative control. Without a criterion that has actually flipped, the silence
    // asserted below is a table that never moved and proves nothing about the hold time.
    let live = run.live();
    if !live.enforce() {
        ip(&["route", "add", "default", "via", FAR, "dev", &lab.iface]).ok();
        eprintln!(
            "SKIP convA: the table without its default route answers {live:?}, so there is \
             no arming transition to hold back"
        );
        return;
    }
    let during = run.phase("during");
    ip(&["route", "add", "default", "via", FAR, "dev", &lab.iface])
        .expect("restoring the default route failed");
    let flap = opened.elapsed();
    let after = run.phase("after");

    println!(
        "LORICA_CONV_FLAP reading=A forwarding=1 flap_ms={} hold_ms={} sent={} dropped={} \
         reloads={}",
        flap.as_millis(),
        DEFAULT_HOLD.as_millis(),
        during.sent,
        during.urpf.drops(),
        run.reloads.len()
    );

    assert!(
        flap < DEFAULT_HOLD,
        "the route was gone for {flap:?}, which is not inside the {DEFAULT_HOLD:?} hold, \
         so this run says nothing about the hysteresis"
    );
    assert!(
        run.reloads.is_empty(),
        "a flap inside the hold reported {:?}, and every report is a program reload",
        run.reloads
    );
    assert_eq!(
        run.watcher.decision(),
        settled,
        "the watcher moved off the decision the program was loaded with"
    );
    for (name, phase) in [("before", before), ("during", during), ("after", after)] {
        assert_eq!(
            phase.urpf,
            Urpf::default(),
            "the {name} phase moved a stage-five counter with URPF_ENFORCE clear"
        );
        assert_eq!(
            phase.received,
            phase.sent,
            "the {name} phase lost {} of {} legitimate frames",
            phase.sent - phase.received,
            phase.sent
        );
    }
}

/// Reading B, and the uncomfortable one. The loader found no default route, so the stage
/// is armed, and `URPF_ENFORCE` is a `.rodata` global: the attached program cannot soften
/// while a route is missing. So this test does not assert zero. It measures how many
/// legitimate frames the window costs and prints it, because the number is the exposure
/// the design accepts and a criterion nobody has priced is a criterion nobody has met.
///
/// The reply path goes with the route — an answer to `FAR_ALT` needs the same entry the
/// reverse lookup does — so `received` is zero during the window whatever the stage does.
/// That is why the assertion is on `no_route` matching the frames sent: it is the only
/// reading that says every frame arrived *and* names what happened to it.
///
/// The run also shows the second cost of this flap, which is not a drop. `reported` comes
/// out of this test as `NoPathOnIngress` and the watcher reports one flip, because the
/// incremental table model identifies a route by family, prefix length, table and output
/// interface, and `10.90.78.0/24` and `10.91.78.0/24` on one interface agree on all four:
/// the model holds one entry for both, so deleting either empties it. `store` names that
/// ceiling for two defaults differing in metric; here it is two /24s. The direction is the
/// safe one — the model claims no path, the criterion disarms, and disarming does not wait
/// — so the flap costs the window's drops *and* an immediate reload, followed by the full
/// 30 s hold before the stage comes back.
#[test]
fn an_armed_stage_drops_the_peer_for_as_long_as_its_route_is_gone() {
    let Some(lab) = Lab::build("convB", true) else {
        return;
    };
    if let Err(err) = ip(&["route", "add", ALT_NET, "dev", &lab.iface]) {
        eprintln!("SKIP convB: cannot install the peer's route: {err}");
        return;
    }

    let mut ebpf = load_raw(&object_path(), setting::URPF_ENFORCE);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let _link = attach_native(program, &lab.iface).expect("attaching to the test veth failed");
    assert_eq!(ip_link_mode(&lab.iface), "xdp");

    let mut run = Run::new(&lab, &ebpf, "B", 1, Some(FAR_ALT));
    let decision = run.watcher.decision();
    if !decision.enforce() {
        eprintln!(
            "SKIP convB: the table this test built answers {decision:?}, so the loader \
             would not have armed the stage and there is nothing to measure"
        );
        return;
    }
    let before = run.phase("before");

    ip(&["route", "del", ALT_NET]).expect("removing the peer's route failed");
    let opened = Instant::now();
    let during = run.phase("during");
    ip(&["route", "add", ALT_NET, "dev", &lab.iface]).expect("restoring the peer's route failed");
    let flap = opened.elapsed();
    let after = run.phase("after");

    println!(
        "LORICA_CONV_FLAP reading=B forwarding=1 flap_ms={} hold_ms={} sent={} dropped={} \
         reloads={}",
        flap.as_millis(),
        DEFAULT_HOLD.as_millis(),
        during.sent,
        during.urpf.drops(),
        run.reloads.len()
    );

    for (name, phase) in [("before", before), ("after", after)] {
        assert_eq!(
            phase.urpf,
            Urpf::default(),
            "the {name} phase dropped a legitimate frame with the route in place"
        );
        assert_eq!(
            phase.received,
            phase.sent,
            "the {name} phase lost {} of {} legitimate frames",
            phase.sent - phase.received,
            phase.sent
        );
    }
    assert_eq!(
        during.urpf.no_route, during.sent,
        "the window cost {} of {} frames and the rest is unexplained, so the exposure \
         this test reports is not the whole of it",
        during.urpf.no_route, during.sent
    );
}

/// The same armed stage on a host that does not forward, which is the tier-1 target of
/// this product and not an edge case.
///
/// `bpf_ipv4_fib_lookup` reads the ingress device's forwarding flag before the table, so
/// the answer is `FWD_DISABLED` for every frame, the stage counts a lookup it could not
/// answer and passes. The exposure of reading B is therefore zero there — which is a
/// finding about where the stage works, not a reason to relax about it.
#[test]
fn an_armed_stage_on_a_host_that_does_not_forward_costs_nothing() {
    let Some(lab) = Lab::build("convC", false) else {
        return;
    };
    if let Err(err) = ip(&["route", "add", ALT_NET, "dev", &lab.iface]) {
        eprintln!("SKIP convC: cannot install the peer's route: {err}");
        return;
    }

    let mut ebpf = load_raw(&object_path(), setting::URPF_ENFORCE);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let _link = attach_native(program, &lab.iface).expect("attaching to the test veth failed");
    assert_eq!(ip_link_mode(&lab.iface), "xdp");

    let mut run = Run::new(&lab, &ebpf, "C", 0, Some(FAR_ALT));
    let before = run.phase("before");
    ip(&["route", "del", ALT_NET]).expect("removing the peer's route failed");
    let opened = Instant::now();
    let during = run.phase("during");
    ip(&["route", "add", ALT_NET, "dev", &lab.iface]).expect("restoring the peer's route failed");
    let flap = opened.elapsed();
    let after = run.phase("after");

    println!(
        "LORICA_CONV_FLAP reading=C forwarding=0 flap_ms={} hold_ms={} sent={} dropped={} \
         reloads={}",
        flap.as_millis(),
        DEFAULT_HOLD.as_millis(),
        during.sent,
        during.urpf.drops(),
        run.reloads.len()
    );

    for (name, phase) in [("before", before), ("during", during), ("after", after)] {
        assert_eq!(
            phase.urpf.drops(),
            0,
            "the {name} phase dropped a frame on a host where the lookup cannot answer"
        );
        assert_eq!(
            phase.urpf.unsupported, phase.sent,
            "the {name} phase sent {} frames and the stage reported {} it could not \
             answer, so something else decided them",
            phase.sent, phase.urpf.unsupported
        );
    }
}
