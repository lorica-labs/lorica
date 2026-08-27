//! The agent seen from outside while it is on an interface: whether it attaches, in which
//! mode, what it says when it cannot, and what it leaves behind when it stops.
//!
//! Every case here runs the real binary rather than the loop in `main`, because the two
//! things worth establishing are both outside the process: what `ip -d link` says about the
//! interface, and what is still on it after the agent is gone. A harness that called `serve`
//! in-process could assert neither.
//!
//! **One assertion here cannot fail on its own, and it is named rather than left to look
//! solid.** `stopping_the_agent_detaches` checks that the hook is free after the agent
//! exits — and on a kernel with `bpf_link`, which is every kernel this project supports,
//! closing the last descriptor of the link frees the hook whether or not anybody asked. So
//! that check passes against an agent that detaches and against an agent that does not, and
//! the assertion that separates them is the one on what the agent *reported*: an agent that
//! lets the kernel tidy up never learns whether the tidying worked. The interface check
//! still earns its place on the other path — aya falls back to a netlink attach when
//! `bpf_link_create` is refused, and nothing releases a netlink attach when the process
//! dies — but it is not what makes this case falsifiable today, and a reader deserves to
//! know which half is doing the work.
//!
//! Interfaces are `veth`s created and deleted per case, and their names carry the process
//! id: cargo runs these cases as threads of one process, so a fixed name is the failure that
//! happens once in ten runs and never when the case is run alone.

#![cfg(all(target_os = "linux", feature = "kernel-tests"))]

// The dataplane's fixtures, by path rather than copied. `Link` creates the interface, brings
// it up and deletes it on drop, and `ip_link_mode` reads the one field that attests a native
// attach. A second copy of them here would be a second thing to keep true.
#[path = "../../lorica-dataplane/tests/support/net.rs"]
#[allow(dead_code)]
mod net;

use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use net::{Link, ip_link_mode};

/// How long the agent is given to bind its socket. Generous because the clock calibration
/// sleeps a few hundred milliseconds at startup by design, and because these cases share a
/// lab VM with whatever else the suite is doing.
const STARTUP: Duration = Duration::from_secs(30);

/// How long a startup that is expected to fail is given to fail. An agent that is still
/// running after this has not refused, which is the defect the case is about.
const REFUSAL: Duration = Duration::from_secs(30);

fn object_path() -> PathBuf {
    if let Ok(path) = std::env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

/// An interface name no other case and no concurrent run is using.
///
/// `veth` appends a `p` to build the peer and the kernel stops at 15 bytes, so the tag is
/// one character and the pid is folded into five digits.
fn iface(case: &str) -> String {
    format!("la{case}{}", std::process::id() % 100_000)
}

fn socket_path(case: &str) -> PathBuf {
    PathBuf::from("/tmp")
        .join(format!("lorica-attach-{case}-{}", std::process::id()))
        .join("control.sock")
}

/// The agent as a process: spawned, asked, stopped.
struct Agent {
    child: Option<Child>,
    socket: PathBuf,
}

impl Agent {
    /// Spawns the agent and returns without waiting for anything.
    fn spawn(case: &str, extra: &[&str]) -> Self {
        let socket = socket_path(case);
        let _ = std::fs::remove_dir_all(socket.parent().expect("the socket path has a parent"));
        let object = object_path();
        let child = Command::new(env!("CARGO_BIN_EXE_loricad"))
            .args([
                "--object",
                object.to_str().expect("the object path is UTF-8"),
            ])
            .args([
                "--socket",
                socket.to_str().expect("the socket path is UTF-8"),
            ])
            // Off, because these cases run in parallel and one loopback port cannot be bound
            // twice: a port conflict here would read as an attach failure.
            .args(["--metrics", "off"])
            // Above the named counters, so the agent has somewhere to count a refusal and
            // `arm` is refused for a reason this file is not about.
            .args(["--counters", "1024"])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start the agent");
        Self {
            child: Some(child),
            socket,
        }
    }

    /// Spawns the agent and waits until it answers a `status`.
    ///
    /// Readiness is a whole exchange and not a socket that accepts a connection, and the
    /// difference is the case that attaches: the socket is bound before the attach and the
    /// loop that answers runs after it, so a case that started as soon as `connect`
    /// succeeded would look at an interface the agent had not reached yet.
    fn started(case: &str, extra: &[&str]) -> Self {
        let mut agent = Self::spawn(case, extra);
        let deadline = Instant::now() + STARTUP;
        while Instant::now() < deadline {
            if let Some(status) = agent.exited() {
                let output = agent.collect();
                panic!(
                    "the agent exited with {status} before it was ready:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if agent
                .try_ask("status")
                .is_some_and(|answer| answer.contains("\"attached\""))
            {
                return agent;
            }
            sleep(Duration::from_millis(20));
        }
        panic!(
            "the agent did not answer on {} within {STARTUP:?}",
            agent.socket.display()
        );
    }

    /// One exchange, or nothing, for the readiness poll above: an agent that has not bound
    /// its socket yet is not a failure to report.
    fn try_ask(&self, command: &str) -> Option<String> {
        let mut socket = UnixStream::connect(&self.socket).ok()?;
        socket.write_all(format!("{command}\n").as_bytes()).ok()?;
        socket.shutdown(Shutdown::Write).ok()?;
        let mut answer = String::new();
        socket.read_to_string(&mut answer).ok()?;
        Some(answer)
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .expect("the agent is gone")
            .try_wait()
            .expect("cannot ask whether the agent exited")
    }

    /// One command, one answer, the exchange `lorica-ctl` makes.
    fn ask(&self, command: &str) -> String {
        let mut socket = UnixStream::connect(&self.socket)
            .unwrap_or_else(|err| panic!("cannot connect to {}: {err}", self.socket.display()));
        socket
            .write_all(format!("{command}\n").as_bytes())
            .expect("cannot write the command");
        socket
            .shutdown(Shutdown::Write)
            .expect("cannot half-close the socket");
        let mut answer = String::new();
        socket
            .read_to_string(&mut answer)
            .expect("cannot read the answer");
        answer
    }

    /// SIGTERM, then everything the agent said on its way out.
    fn terminate(&mut self) -> Output {
        let child = self.child.as_ref().expect("the agent is gone");
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("cannot run kill");
        assert!(status.success(), "kill -TERM did not reach the agent");
        self.collect()
    }

    /// Waits for the agent to exit and takes its output. Bounded, because a case that hangs
    /// here reports nothing at all.
    fn collect(&mut self) -> Output {
        let mut child = self.child.take().expect("the agent is gone");
        let deadline = Instant::now() + REFUSAL;
        loop {
            match child.try_wait().expect("cannot wait for the agent") {
                Some(_) => break,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let output = child.wait_with_output().expect("cannot reap the agent");
                    panic!(
                        "the agent was still running after {REFUSAL:?}:\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                None => sleep(Duration::from_millis(20)),
            }
        }
        child.wait_with_output().expect("cannot reap the agent")
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(dir) = self.socket.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The behaviour that was there before `--iface` existed, and it is still the default.
#[test]
fn without_an_interface_the_agent_runs_detached() {
    let agent = Agent::started("none", &[]);
    let status = agent.ask("status");

    assert!(
        status.contains("\"attached\": false"),
        "an agent given no interface reports itself attached: {status}"
    );
    assert!(
        status.contains("\"interface\": null"),
        "an agent given no interface names one: {status}"
    );
}

/// The whole point of the flag: it attaches, and it says to what.
#[test]
fn with_an_interface_the_agent_attaches_and_names_it() {
    let name = iface("a");
    let veth = Link::veth(&name);
    let agent = Agent::started("attached", &["--iface", &veth.name]);
    let status = agent.ask("status");

    assert!(
        status.contains("\"attached\": true"),
        "the agent was given an interface and reports itself detached: {status}"
    );
    assert!(
        status.contains(&format!("\"interface\": \"{}\"", veth.name)),
        "the agent does not name the interface it is on: {status}"
    );
}

/// Native or nothing. Generic XDP runs after the stack has built an skb, so an agent that
/// silently landed there would be measuring something else while reporting this.
#[test]
fn the_attach_the_agent_makes_is_native() {
    let name = iface("b");
    let veth = Link::veth(&name);
    let _agent = Agent::started("native", &["--iface", &veth.name]);

    assert_eq!(
        ip_link_mode(&veth.name),
        "xdp",
        "ip -d link has to render xdp and never xdpgeneric"
    );
}

/// An agent that starts believing it protects an interface and does not is the defect this
/// whole file exists to close, so a startup that cannot attach is a startup that fails.
#[test]
fn an_interface_that_does_not_exist_stops_the_startup() {
    let missing = format!("{}-no", iface("c"));
    let mut agent = Agent::spawn("missing", &["--iface", &missing]);
    let output = agent.collect();

    assert!(
        !output.status.success(),
        "the agent started with an interface that does not exist: {}",
        stderr_of(&output)
    );
    let said = stderr_of(&output);
    assert!(
        said.contains(&missing),
        "the failure does not name the interface it was asked for: {said}"
    );
}

/// The collision that happens in the field. Cilium, a hosting provider's protection or
/// another eBPF tool holds the hook, and a refusal that says only "attach failed" leaves the
/// operator with nothing to act on. The occupant here is another Lorica because that is the
/// one XDP program this crate is certain to have; what is asserted is that the occupant is
/// named, not which one it is.
#[test]
fn an_interface_that_already_carries_a_program_names_the_occupant() {
    let name = iface("d");
    let veth = Link::veth(&name);
    let _holder = Agent::started("holder", &["--iface", &veth.name]);
    assert_eq!(
        ip_link_mode(&veth.name),
        "xdp",
        "the fixture agent did not take the hook, so this case cannot state its point"
    );

    let mut second = Agent::spawn("second", &["--iface", &veth.name]);
    let output = second.collect();
    let said = stderr_of(&output);

    assert!(
        !output.status.success(),
        "a second agent attached over a hook that was already taken: {said}"
    );
    // Printed, not only asserted on. This is the text an operator reads at the moment the
    // agent refuses to start, and a diagnostic nobody has read is a diagnostic nobody has
    // judged. `--nocapture` shows it.
    println!("refusal as the operator sees it:\n{said}");
    for expected in [veth.name.as_str(), "program id", "lorica_xdp"] {
        assert!(
            said.contains(expected),
            "the refusal does not name {expected:?}; it says: {said}"
        );
    }
}

/// The agent gives the interface back when it is told to stop.
///
/// See the module comment for which half of this is falsifiable: the report is, the bare
/// interface is not, on a kernel where closing the link descriptor already frees the hook.
#[test]
fn stopping_the_agent_detaches() {
    let name = iface("e");
    let veth = Link::veth(&name);
    let mut agent = Agent::started("stop", &["--iface", &veth.name]);
    assert_eq!(
        ip_link_mode(&veth.name),
        "xdp",
        "the agent is not attached, so this case would pass without detaching anything"
    );

    let output = agent.terminate();
    let said = stderr_of(&output);

    assert!(
        output.status.success(),
        "the agent did not exit cleanly on SIGTERM: {said}"
    );
    assert!(
        said.contains(&format!("detached from {}", veth.name)),
        "the agent stopped without reporting a detach, so nothing in it knows whether the \
         interface was given back: {said}"
    );
    assert_eq!(
        ip_link_mode(&veth.name),
        "none",
        "the interface still carries a program after the agent is gone"
    );
}

/// The socket does the same round trip the flag does, and `status` follows both ways.
#[test]
fn attach_and_detach_over_the_socket_make_the_round_trip() {
    let name = iface("f");
    let veth = Link::veth(&name);
    let agent = Agent::started("roundtrip", &[]);

    assert!(
        agent.ask("status").contains("\"attached\": false"),
        "the agent was given no interface and starts attached"
    );

    let attached = agent.ask(&format!("attach {}", veth.name));
    assert!(
        attached.contains("\"attached\": true"),
        "attaching over the socket was refused: {attached}"
    );
    assert_eq!(
        ip_link_mode(&veth.name),
        "xdp",
        "the socket reported an attach that is not on the interface, or is not native"
    );
    let status = agent.ask("status");
    assert!(
        status.contains("\"attached\": true")
            && status.contains(&format!("\"interface\": \"{}\"", veth.name)),
        "status does not follow what attach did: {status}"
    );

    let detached = agent.ask("detach");
    assert!(
        detached.contains("\"attached\": false") && detached.contains(&veth.name),
        "detaching over the socket has to say what it took off: {detached}"
    );
    assert_eq!(
        ip_link_mode(&veth.name),
        "none",
        "the socket reported a detach the interface did not see"
    );
    let status = agent.ask("status");
    assert!(
        status.contains("\"attached\": false") && status.contains("\"interface\": null"),
        "status does not follow what detach did: {status}"
    );
}

/// Attaching is not arming, and this is the assertion that makes an attached default
/// publishable: an agent in the packet path in `observe` mode watches and writes nothing.
#[test]
fn attaching_does_not_arm() {
    let name = iface("g");
    let veth = Link::veth(&name);
    let agent = Agent::started("observe", &["--iface", &veth.name]);

    // Long enough for the ticks to have run and the ladder to have decided something, so an
    // empty list is an empty list and not a list nothing has reached yet.
    sleep(Duration::from_millis(500));

    let status = agent.ask("status");
    assert!(
        status.contains("\"mode\": \"observe\""),
        "attaching moved the mode: {status}"
    );
    assert!(
        status.contains("\"attached\": true"),
        "the agent is not attached, so this case is asserting nothing: {status}"
    );
    assert!(
        status.contains("\"written\": 0"),
        "an agent in observe mode wrote an entry: {status}"
    );

    let rules = agent.ask("rules");
    assert!(
        rules.contains("\"count\": 0"),
        "the unified list is not empty on an attached agent in observe mode: {rules}"
    );
}
