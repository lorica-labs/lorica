//! The control socket seen from outside: what an operator can read, what they can change,
//! and what no answer is allowed to contain.
//!
//! **The load-bearing case is `rules_never_reports_an_active_entry_without_a_deadline`.**
//! Every other guard on the accidental permanent blackhole lives on the write path —
//! `apply` refuses a `Deadline::never()`, the ladder never builds one — and a guard on the
//! write path only covers the writer it is compiled into. This one looks at the map through
//! the same command an operator runs, so it also covers whatever else ever writes into that
//! map. It is falsifiable: put a never-expiring entry in the trie behind `apply`'s back and
//! this case fails, which is the check that the assertion is an assertion and not a
//! rendering.
//!
//! The modules are included by path rather than imported, for the reason
//! `tests/enforce.rs` gives: `loricad` is a binary and an integration test cannot reach
//! into one. What is compiled here is the file the agent compiles.

#![cfg(all(target_os = "linux", feature = "kernel-tests"))]

#[path = "../src/attach.rs"]
mod attach;
#[path = "../src/control/mod.rs"]
mod control;
#[path = "../src/enforce/mod.rs"]
mod enforce;

use std::{
    fs,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    time::Instant,
};

use aya::{Ebpf, EbpfLoader};
use lorica_common::{Clock, CounterId, Deadline, LpmKey, LpmValue};
use lorica_dataplane::{clock, maps};
use lorica_detect::{Confirmation, Decision, Reason, Tier, snapshot::NAMED_SLOTS};
use lorica_policy::Mode;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use control::{Control, Snapshot, Tiers};

/// Small, and not the object's own default, for the reason `tests/enforce.rs` gives: the
/// list has to be one this file sized or a change in `lorica-ebpf` changes what is tested.
const LIST_ENTRIES: u32 = 64;
const COUNTER_ENTRIES: u32 = CounterId::COUNT + LIST_ENTRIES;

/// The first slot above the named counters, read from `lorica-common` rather than written
/// down: a number recopied here would go stale the day a counter is added.
const SLOT: u32 = CounterId::COUNT;

/// Seconds of life the decisions below are written with. A parameter of this file only.
const TTL_SECS: u64 = 600;

fn object_path() -> PathBuf {
    if let Ok(path) = std::env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

/// The maps, and the clock the deadlines in them are compared against. The clock is
/// measured through the object's own probe, because a deadline is a count of jiffies and
/// the whole question is whether the number reported is on the axis the data path reads.
fn lab() -> (Ebpf, Clock) {
    let path = object_path();
    let bytes = fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    // The counter map's entry count and the stripe width the program indexes it with are
    // one decision, and `maps::size_counters` is the only thing allowed to make it.
    let layout = lorica_dataplane::maps::counter_layout(COUNTER_ENTRIES)
        .expect("no counter layout for this machine");
    let mut loader = EbpfLoader::new();
    let mut ebpf = lorica_dataplane::maps::size_counters(&mut loader, &layout)
        .map_max_entries("UNIFIED_LIST", LIST_ENTRIES)
        .load(&bytes)
        .unwrap_or_else(|err| panic!("creating the maps of {} failed: {err}", path.display()));
    let clock = clock::calibrate(&mut ebpf).expect("cannot measure the kernel clock rate");
    (ebpf, clock)
}

/// A directory of this test's own, named after the case.
///
/// Not a shared path: cargo runs these cases as threads of one process, so a socket path
/// built from the pid alone would be the same path in all of them, and the failure that
/// produces is one case in ten under parallelism and none when run alone. The case name is
/// the part that makes it unique; the pid is there for two runs at once.
fn socket_path(case: &str) -> PathBuf {
    let dir = PathBuf::from("/tmp").join(format!("lorica-control-{case}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir.join("control.sock")
}

/// What the agent would be holding across a tick, owned here so a case can hand out the
/// borrows [`Control`] is made of and then look at what a command changed.
///
/// `written` and `withheld` are rendered and never read by a command, so they are the
/// constructor's zero rather than fields of this.
struct Agent {
    mode: Mode,
    standing: Option<LpmKey>,
    pulled: u64,
    tiers: Tiers,
    stages: [u64; NAMED_SLOTS],
    /// Never anything but `None` here: an [`Attachment`](attach::Attachment) exists only
    /// where a real interface was attached, and that is `tests/attach_iface.rs`. What this
    /// file asserts about it is that `status` says so.
    attached: Option<attach::Attachment>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            standing: None,
            pulled: 0,
            tiers: Tiers::default(),
            stages: [0; NAMED_SLOTS],
            attached: None,
        }
    }
}

impl Agent {
    fn control<'a>(&'a mut self, ebpf: &'a mut Ebpf) -> Control<'a> {
        Control {
            mode: &mut self.mode,
            standing: &mut self.standing,
            pulled: &mut self.pulled,
            written: 0,
            withheld: 0,
            stages: &self.stages,
            tiers: &self.tiers,
            attached: &mut self.attached,
            ebpf,
        }
    }
}

/// The list descriptor, duplicated rather than borrowed out of the program.
///
/// `Control` takes the program mutably — that is what makes `attach` a command — so a
/// borrow of one of its maps held across a command would not compile. `main` duplicates the
/// same two descriptors for the same reason.
fn duplicate(ebpf: &Ebpf, name: &str) -> OwnedFd {
    maps::fd(ebpf, name)
        .unwrap_or_else(|| panic!("no {name} map in the object"))
        .try_clone_to_owned()
        .unwrap_or_else(|err| panic!("cannot duplicate the descriptor of {name}: {err}"))
}

/// The snapshot a query would be answered from. `slots` is the one field a case varies: it
/// is what decides whether this agent has anywhere to count a refusal, and therefore
/// whether it may be armed at all.
fn snapshot(slots: usize, clock: Clock) -> Snapshot {
    Snapshot {
        counter_slots: slots,
        ticks: 0,
        full_sweeps: 0,
        sweep_every: 1,
        slot_reads_per_second: 0,
        counted: 0,
        named_counted: 0,
        period_ms: 100,
        attached: false,
        clock,
    }
}

/// One exchange: a client connects, sends `line`, half-closes, and reads the answer.
///
/// The client is a task and the server is this function, because that is the shape `main`
/// has — the accept and the answer happen on the thread the tick is on — and a test that
/// drove both halves in sequence could not catch a handler that waits for something the
/// client already stopped sending.
async fn ask(
    listener: &UnixListener,
    path: PathBuf,
    line: &'static str,
    snapshot: Snapshot,
    control: &mut Control<'_>,
) -> String {
    let client = tokio::spawn(async move {
        let mut socket = UnixStream::connect(&path)
            .await
            .unwrap_or_else(|err| panic!("cannot connect to {}: {err}", path.display()));
        socket.write_all(line.as_bytes()).await.expect("write");
        socket.shutdown().await.expect("half-close");
        let mut answer = String::new();
        socket.read_to_string(&mut answer).await.expect("read");
        answer
    });
    let (stream, _) = listener.accept().await.expect("accept");
    control::serve(stream, snapshot, control)
        .await
        .expect("answering a well-behaved client cannot fail");
    client.await.expect("the client task panicked")
}

/// The lines of a `rules` answer that describe an entry which never expires.
///
/// Matched on the rendered line rather than parsed, because the agent owes no serialiser
/// and `lorica-ctl` owes no dependency: one entry per line is the contract this reads.
fn everlasting(answer: &str) -> Vec<&str> {
    answer
        .lines()
        .filter(|line| line.contains("\"expires\": false"))
        .collect()
}

fn entry_lines(answer: &str) -> Vec<&str> {
    answer
        .lines()
        .filter(|line| line.contains("\"prefix\":"))
        .collect()
}

/// A decision at a refusing rung, named on `key`.
fn refusal(key: LpmKey, deadline: Deadline) -> Decision {
    Decision::new(
        Tier::DropSurgical,
        Reason::Confirmed {
            key,
            by: Confirmation::ExactKey,
            per_sec: 1,
        },
        deadline,
    )
    .expect("a rung naming its own exact key has to be constructible")
}

/// The default is what makes this repository publishable, so it is read back through the
/// same command an operator runs and not asserted on a field.
///
/// The second half is the anti-drift half: the word this answer carries has to be a word
/// `Mode` itself accepts. `lorica-ctl` prints it and a configuration file spells the same
/// two, so a rename that reached only one of them would leave `status` reporting a mode
/// nothing can be set to.
#[tokio::test]
async fn status_reports_the_observing_mode_by_default() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("status-default");
    let listener = control::listen(&path).expect("cannot listen");

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);
    let answer = ask(
        &listener,
        path.clone(),
        "status\n",
        snapshot(COUNTER_ENTRIES as usize, clock),
        &mut control,
    )
    .await;

    assert!(
        answer.contains("\"mode\": \"observe\""),
        "an agent nobody armed has to report the observing mode: {answer}"
    );
    assert!(
        !answer.contains("\"mode\": \"armed\""),
        "the answer reports both modes at once: {answer}"
    );
    assert_eq!(
        "observe".parse::<Mode>(),
        Ok(Mode::Observe),
        "the word status reports is not a word Mode accepts, so the two have drifted"
    );
    assert_eq!("armed".parse::<Mode>(), Ok(Mode::Armed));
    assert!(
        answer.contains("\"capabilities\""),
        "status has to carry the capability table: {answer}"
    );
}

/// The guard on the accidental permanent blackhole, from outside, after a real write.
///
/// The write goes through `apply` in armed mode, so what is in the trie when `rules` walks
/// it is what the agent itself puts there. The two assertions are ordered on purpose: an
/// empty list satisfies "no entry without a deadline" for free, so the count is asserted
/// first and the invariant second.
#[tokio::test]
async fn rules_never_reports_an_active_entry_without_a_deadline() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("rules-deadline");
    let listener = control::listen(&path).expect("cannot listen");
    let list_fd = duplicate(&ebpf, "UNIFIED_LIST");
    let list = list_fd.as_fd();

    let key = LpmKey::host_v4([198, 51, 100, 21]);
    assert_eq!(
        enforce::apply(
            list,
            Mode::Armed,
            &refusal(key, clock.deadline(TTL_SECS)),
            SLOT
        )
        .expect("the write failed"),
        enforce::Applied::Written(key)
    );

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);
    let answer = ask(
        &listener,
        path.clone(),
        "rules\n",
        snapshot(COUNTER_ENTRIES as usize, clock),
        &mut control,
    )
    .await;

    let entries = entry_lines(&answer);
    assert_eq!(
        entries.len(),
        1,
        "the entry that was just written has to be the one rules reports: {answer}"
    );
    assert!(
        entries[0].contains("198.51.100.21/32"),
        "rules has to name the prefix the refusal was written on: {answer}"
    );

    let forever = everlasting(&answer);
    assert!(
        forever.is_empty(),
        "an active entry with no deadline is a permanent blackhole nobody asked for: {forever:?}"
    );
}

/// Arming is refused when there is no slot to count refusals in, and the refusal says so.
///
/// Without a slot above the named counters, an armed agent charges its own drops to a stage
/// counter and reads them back as evidence for the next rung. That is the same condition
/// `parse_options` applies to `--mode armed`, which is why it is asked here and not
/// restated.
#[tokio::test]
async fn arming_without_a_slot_above_the_named_counters_is_refused() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("arm-no-slot");
    let listener = control::listen(&path).expect("cannot listen");

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);
    // Exactly the named counters and nothing above them.
    let answer = ask(
        &listener,
        path.clone(),
        "arm\n",
        snapshot(CounterId::COUNT as usize, clock),
        &mut control,
    )
    .await;

    assert!(
        answer.contains("\"error\""),
        "arming without a slot has to be refused: {answer}"
    );
    assert!(
        answer.contains("named counters"),
        "the refusal has to name the reason, not just fail: {answer}"
    );
    assert!(
        answer.contains(&CounterId::COUNT.to_string()),
        "the refusal has to say how many slots are taken, so an operator can size the map: \
         {answer}"
    );
    drop(control);
    assert_eq!(
        agent.mode,
        Mode::Observe,
        "a refused arm left the agent armed"
    );
}

/// A word the agent does not know is refused, and the next client is still answered.
///
/// The second half is the trust boundary. The command is a third party's string and it is
/// echoed back inside JSON that `jq` reads, so the case sends the two bytes that break a
/// hand-written serialiser: a quote, and a carriage return that used to append a second
/// request elsewhere in this project.
#[tokio::test]
async fn an_unknown_command_is_refused_and_the_agent_keeps_answering() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("unknown-command");
    let listener = control::listen(&path).expect("cannot listen");
    let snap = snapshot(COUNTER_ENTRIES as usize, clock);

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);

    let answer = ask(&listener, path.clone(), "wat\n", snap, &mut control).await;
    assert!(
        answer.contains("\"error\"") && answer.contains("unknown command"),
        "an unknown word has to be refused by name: {answer}"
    );

    let injected = ask(
        &listener,
        path.clone(),
        "sta\"tus\r\n\"role\":\"admin\"\n",
        snap,
        &mut control,
    )
    .await;
    assert!(
        injected.contains("\\\""),
        "the quote the client sent has to come back escaped: {injected}"
    );
    assert!(
        !injected.contains('\r'),
        "a carriage return reached the answer, which is how one request becomes two: \
         {injected:?}"
    );
    assert_eq!(
        injected.matches('{').count(),
        1,
        "the answer has to be one JSON document whatever the client sent: {injected}"
    );
    assert!(
        !injected.contains("\"role\""),
        "the bytes after the newline were answered as a second command: {injected}"
    );

    // The point of the case: none of the above took the listener with it.
    let after = ask(&listener, path.clone(), "status\n", snap, &mut control).await;
    assert!(
        after.contains("\"mode\":"),
        "the agent stopped answering after a refusal: {after}"
    );
}

/// Neither a line that never ends nor a client that walks away mid-exchange stops the
/// agent, and neither can hold the tick behind it.
///
/// `main` awaits the handler on the tick's own thread, so a client that connects and says
/// nothing is not a slow client — it is a stopped agent. The third block is that client,
/// and the assertion is on the clock: the exchange has to come back on its own.
#[tokio::test]
async fn a_truncated_line_or_a_client_that_leaves_does_not_stop_the_agent() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("truncated");
    let listener = control::listen(&path).expect("cannot listen");
    let snap = snapshot(COUNTER_ENTRIES as usize, clock);

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);

    // A line with no newline at all, longer than any command word. The read is bounded, so
    // this is a refusal and not a buffer that grows until the allocator gives up.
    let flood = "s".repeat(4096);
    let sending = {
        let path = path.clone();
        tokio::spawn(async move {
            let mut socket = UnixStream::connect(&path).await.expect("connect");
            let _ = socket.write_all(flood.as_bytes()).await;
            let _ = socket.shutdown().await;
            let mut answer = String::new();
            let _ = socket.read_to_string(&mut answer).await;
        })
    };
    let (stream, _) = listener.accept().await.expect("accept");
    let _ = control::serve(stream, snap, &mut control).await;
    let _ = sending.await;

    // A client that writes half a word and drops the socket without reading. The write of
    // the answer fails, which is the client's problem and not the agent's.
    let leaving = {
        let path = path.clone();
        tokio::spawn(async move {
            let socket = UnixStream::connect(&path).await.expect("connect");
            let mut socket = socket;
            let _ = socket.write_all(b"sta").await;
        })
    };
    let (stream, _) = listener.accept().await.expect("accept");
    let _ = control::serve(stream, snap, &mut control).await;
    let _ = leaving.await;

    // A client that connects and never speaks. Nothing here can make it speak, so the only
    // thing that ends this exchange is the bound the handler puts on it.
    let silent = {
        let path = path.clone();
        tokio::spawn(async move {
            let socket = UnixStream::connect(&path).await.expect("connect");
            tokio::time::sleep(control::EXCHANGE * 4).await;
            drop(socket);
        })
    };
    let (stream, _) = listener.accept().await.expect("accept");
    let started = Instant::now();
    let _ = control::serve(stream, snap, &mut control).await;
    let waited = started.elapsed();
    assert!(
        waited < control::EXCHANGE * 3,
        "a client that says nothing held the handler for {waited:?}, and the handler is on \
         the thread the tick is on"
    );
    silent.abort();

    // The agent is still there, which is the whole case.
    let after = ask(&listener, path.clone(), "status\n", snap, &mut control).await;
    assert!(
        after.contains("\"mode\":"),
        "the agent stopped answering: {after}"
    );
}

/// Disarming puts the mode back and takes the entry out, rather than putting the mode back
/// and leaving the refusal standing until its deadline.
///
/// The deadline would eventually remove it, and that is exactly the objection: an operator
/// who disarms and then watches traffic still being dropped for the rest of a ten-minute
/// TTL has been told the agent is off while it is not. Only the key the agent wrote is
/// withdrawn — anything else in the list belongs to whoever put it there.
#[tokio::test]
async fn disarm_returns_to_observing_and_withdraws_what_arming_wrote() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("disarm");
    let listener = control::listen(&path).expect("cannot listen");
    let list_fd = duplicate(&ebpf, "UNIFIED_LIST");
    let list = list_fd.as_fd();
    let snap = snapshot(COUNTER_ENTRIES as usize, clock);

    let mut agent = Agent::default();
    let key = LpmKey::host_v4([198, 51, 100, 22]);
    {
        let mut control = agent.control(&mut ebpf);
        let armed = ask(&listener, path.clone(), "arm\n", snap, &mut control).await;
        assert!(
            armed.contains("\"mode\": \"armed\""),
            "arming with a slot available has to be granted: {armed}"
        );
    }
    assert_eq!(agent.mode, Mode::Armed, "arm did not reach the agent");

    // The tick, as far as this case is concerned: the mode the socket set is the mode the
    // write is made in, and the key it wrote is what the agent now stands on.
    assert_eq!(
        enforce::apply(
            list,
            agent.mode,
            &refusal(key, clock.deadline(TTL_SECS)),
            SLOT
        )
        .expect("the write failed"),
        enforce::Applied::Written(key)
    );
    agent.standing = Some(key);

    {
        let mut control = agent.control(&mut ebpf);
        let disarmed = ask(&listener, path.clone(), "disarm\n", snap, &mut control).await;
        assert!(
            disarmed.contains("\"mode\": \"observe\""),
            "disarming has to report the mode it left the agent in: {disarmed}"
        );
        assert!(
            disarmed.contains("198.51.100.22/32"),
            "disarming has to say what it withdrew, or nobody can tell it did: {disarmed}"
        );
    }
    assert_eq!(agent.mode, Mode::Observe, "disarm did not reach the agent");
    assert_eq!(agent.standing, None, "the withdrawn key is still standing");
    assert_eq!(agent.pulled, 1, "the withdrawal was not counted");

    let mut control = agent.control(&mut ebpf);
    let rules = ask(&listener, path.clone(), "rules\n", snap, &mut control).await;
    assert!(
        entry_lines(&rules).is_empty(),
        "the entry arming wrote is still in the list after a disarm: {rules}"
    );
}

/// Who can arm, as a mode and not as an assumption.
///
/// The socket is where arming is decided, so its permissions are the whole access control
/// of this feature. They were the umask's: `bind` creates the socket with `0777 & !umask`,
/// which is `0755` under the usual `0022` — owner-only by luck, because connecting to a
/// Unix socket needs write permission — and `0777` under a unit file with `UMask=0000`, at
/// which point any local account can arm and disarm the mitigation. The directory is
/// tightened before the bind rather than after, because between the bind and a chmod the
/// socket exists at whatever the umask said.
///
/// A runtime case even though nothing here is awaited: `listen` answers a tokio listener,
/// and registering one with the reactor is part of what `bind` does.
#[tokio::test]
async fn the_socket_and_its_directory_are_not_left_to_the_umask() {
    let path = socket_path("permissions");
    let _listener = control::listen(&path).expect("cannot listen");

    let socket = fs::metadata(&path).expect("no socket at the path listen returned");
    assert_eq!(
        socket.permissions().mode() & 0o777,
        0o600,
        "the control socket is reachable by more than the user the agent runs as"
    );

    let parent = path.parent().expect("the socket path has no directory");
    let directory = fs::metadata(parent).expect("no directory");
    assert_eq!(
        directory.permissions().mode() & 0o777,
        0o700,
        "the directory the socket sits in can be traversed by other users, so the mode of \
         the socket itself is not the whole answer"
    );
    assert!(
        Path::new(&path).exists(),
        "listen answered without leaving a socket behind"
    );
}

/// A directory the agent did not create keeps the mode it had.
///
/// The regression this pins down was shipped and did real damage. `listen` used to chmod the
/// socket's parent to `0700` unconditionally, which is right for the default
/// `/run/lorica/control.sock` and catastrophic for `--socket /run/agent.sock`: the parent is
/// then `/run`, and one measurement run left `/run` at `0700 root:root` on the lab's
/// measurement machine. Every service needing a runtime directory as a non-root user broke,
/// the overlay dropped its interface, and the host went unreachable — from a flag whose only
/// job was to name a socket.
///
/// So the property is not "the directory ends up at 0700". It is **the agent hardens what it
/// creates and leaves what it finds**, and only the second half can be broken silently.
#[tokio::test]
async fn a_directory_the_agent_did_not_create_keeps_its_mode() {
    let dir = PathBuf::from("/tmp").join(format!("lorica-preexisting-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("cannot create the directory");
    // 0755 rather than 0700, so a version that tightens what it finds changes it and a
    // version that leaves it alone does not. Setting it explicitly because create_dir_all
    // goes through the umask and the test must not depend on the caller's.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("cannot set the mode");

    let path = dir.join("control.sock");
    let _listener = control::listen(&path).expect("cannot listen");

    let after = fs::metadata(&dir)
        .expect("no directory")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        after, 0o755,
        "listen changed the mode of a directory it did not create, from 0755 to {after:o}. \
         Pointed at a socket directly in /run that is /run itself, and it takes the machine \
         down with it."
    );

    let socket = fs::metadata(&path).expect("no socket").permissions().mode() & 0o777;
    assert_eq!(
        socket, 0o600,
        "the socket in a pre-existing directory is the only thing guarding the agent there, \
         and it is not owner-only"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// `reload` is answered rather than silently accepted.
///
/// There is no configuration file on this path — `main` loads the object, the default
/// settings and the whole signature catalogue, and reads no policy — so a `reload` that
/// answered success would be reporting a re-read that did not happen. It says what is
/// missing instead.
#[tokio::test]
async fn reload_names_what_it_has_no_source_for_instead_of_reporting_success() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("reload");
    let listener = control::listen(&path).expect("cannot listen");

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);
    let answer = ask(
        &listener,
        path.clone(),
        "reload\n",
        snapshot(COUNTER_ENTRIES as usize, clock),
        &mut control,
    )
    .await;

    assert!(
        answer.contains("\"error\""),
        "reload has to refuse rather than report a re-read it did not do: {answer}"
    );
    assert!(
        answer.contains("configuration"),
        "the refusal has to name what is missing: {answer}"
    );
}

/// The write path refuses a never-expiring entry, so the only way one reaches the map is
/// behind it — and that is the entry `rules` has to be able to show.
///
/// This is the falsification of the load-bearing case above, kept as a case of its own: it
/// puts the entry `apply` would refuse into the trie directly, and asserts that `rules`
/// reports it as never expiring. Delete the deadline rendering from `rules` and this fails;
/// weaken the invariant in the load-bearing case and this one is what says the invariant
/// was reachable.
#[tokio::test]
async fn a_never_expiring_entry_written_behind_apply_is_reported_as_such() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("never");
    let listener = control::listen(&path).expect("cannot listen");
    let list_fd = duplicate(&ebpf, "UNIFIED_LIST");
    let list = list_fd.as_fd();

    let key = LpmKey::host_v4([198, 51, 100, 23]);
    assert!(
        enforce::apply(list, Mode::Armed, &refusal(key, Deadline::never()), SLOT).is_err(),
        "apply has to refuse a never-expiring refusal, or this case is testing nothing"
    );

    let mut value = LpmValue::zeroed();
    value.action = lorica_common::Action::Drop;
    value.deadline = Deadline::never();
    value.counter_idx = SLOT;
    lorica_dataplane::maps::lpm::load(list, &[(key, value)], 1)
        .expect("writing straight into the trie failed");

    let mut agent = Agent::default();
    let mut control = agent.control(&mut ebpf);
    let answer = ask(
        &listener,
        path.clone(),
        "rules\n",
        snapshot(COUNTER_ENTRIES as usize, clock),
        &mut control,
    )
    .await;

    let forever = everlasting(&answer);
    assert_eq!(
        forever.len(),
        1,
        "rules has to report an entry that never expires as one, or the invariant above \
         cannot fail: {answer}"
    );
    assert!(
        forever[0].contains("198.51.100.23/32"),
        "the entry reported as never expiring is not the one that was written: {answer}"
    );
}

/// The history is what the ladder went through, and it is bounded.
#[tokio::test]
async fn tiers_reports_the_transitions_and_says_how_many_it_keeps() {
    let (mut ebpf, clock) = lab();
    let path = socket_path("tiers");
    let listener = control::listen(&path).expect("cannot listen");

    let mut agent = Agent::default();
    agent.tiers.note(7, Tier::Mark.rung());
    agent.tiers.note(8, Tier::Mark.rung());
    agent.tiers.note(9, Tier::Limit.rung());

    let mut control = agent.control(&mut ebpf);
    let answer = ask(
        &listener,
        path.clone(),
        "tiers\n",
        snapshot(COUNTER_ENTRIES as usize, clock),
        &mut control,
    )
    .await;

    assert!(
        answer.contains("\"transitions\": 2"),
        "a rung noted twice in a row is one transition, not two: {answer}"
    );
    assert!(
        answer.contains("\"rung\": 2"),
        "tiers has to report the rung standing now: {answer}"
    );
    assert!(
        answer.contains("\"tick\": 9"),
        "a transition has to carry the tick it happened on: {answer}"
    );
    assert!(
        answer.contains("\"kept\":"),
        "the history is bounded, and a reader cannot tell it was truncated unless the \
         bound is in the answer: {answer}"
    );
}
