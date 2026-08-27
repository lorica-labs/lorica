//! The claim is O(states) and not O(packets), so the assertion is a line count.
//!
//! **Why the count is taken from the real formatter and not from a mock.** The property under
//! test is a number of bytes handed to a sink, and the sink is journald with a measured
//! ceiling of 37 500 messages per 30 s on `lab-dev`. A test that counted calls into a fake
//! logger would pass with a formatter that emits one line per counter entry, because the call
//! count is the same. So the subscriber here is the agent's own, from `log::subscriber`, with
//! only its writer replaced.
//!
//! **Why the counting allocator is declared again.** It lives in the binary and an
//! integration test cannot reach into one. Thread-local, because cargo runs these tests in
//! parallel threads and a global count would be whatever another test happened to be doing —
//! the pattern `tick_budget.rs` set. `tick_budget.rs` includes `state.rs` and `tick/mod.rs`
//! and so cannot see this subscriber at all: the zero-allocation claim for the emission is
//! asserted here or nowhere.

#[path = "../src/log/mod.rs"]
#[allow(dead_code)]
mod log;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, Write},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use lorica_common::{CounterId, Deadline};
use lorica_detect::{
    BucketView, CounterView, Decision, Reason, Snapshot, Tier, snapshot::NAMED_SLOTS,
};
use tracing_subscriber::fmt::MakeWriter;

use log::{AGGREGATE_NS, Journal};

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every method forwards to System with the layout it was given, so the contract is
// System's.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The tick period at the default ten hertz, in nanoseconds.
const TICK_NS: u64 = 100_000_000;

/// What a tick is told it cost, for the diagnostic the aggregate line carries. 1.7 ms is the
/// mean `tick_budget.rs` measures on the lab guest over 4 096 slots; nothing here asserts on
/// it, and a fixed value is the point — the emission has to be a function of the state and
/// not of how long a tick happened to take.
const TICK_COST: Duration = Duration::from_micros(1_700);

/// Ticks per run: sixty seconds at ten hertz, so a per-second aggregate line gives the
/// comparison a denominator of sixty rather than of one.
const TICKS: u64 = 600;

/// A writer that counts and discards. Its counters are borrowed rather than global so each
/// test owns a pair and parallel tests cannot pollute each other.
#[derive(Clone, Copy)]
struct Tally {
    lines: &'static AtomicU64,
    bytes: &'static AtomicU64,
}

impl Write for Tally {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let newlines = buf.iter().filter(|byte| **byte == b'\n').count() as u64;
        self.lines.fetch_add(newlines, Ordering::Relaxed);
        self.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Tally {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        *self
    }
}

/// A writer that keeps the text, for the tests that read what a line says.
#[derive(Clone, Copy)]
struct Capture(&'static Mutex<String>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the capture buffer is not shared across a panic")
            .push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        *self
    }
}

/// One snapshot, rewritten in place every tick.
///
/// In place because a fresh `Snapshot` per tick is a `Vec::new()` and a 34-slot array on the
/// stack, and while neither allocates today, the assertion below would then be resting on
/// that rather than on the emission.
fn snapshot() -> Snapshot {
    Snapshot {
        seq: 0,
        at_ns: 0,
        counters: CounterView::new([0; NAMED_SLOTS], Vec::new()),
        buckets: BucketView::new(Vec::new()),
    }
}

/// A rung above `Observe` that refuses nothing, so no exact key is needed and the decision
/// exists. What is under test is the transition, not what the ladder rests on.
fn alarm() -> Decision {
    Decision::new(
        Tier::Mark,
        Reason::Pressure {
            counter: CounterId::ALL[0],
            per_sec: 400_000,
            loaded_share: 30_000,
        },
        Deadline::never(),
    )
    .expect("Mark refuses no packets, so it needs no exact key")
}

/// Drives `TICKS` ticks. Under load every named counter moves every tick and one incident
/// runs across the middle of the window; at rest nothing moves and the rung stays at zero.
fn drive(journal: &mut Journal, load: bool) {
    let mut snapshot = snapshot();
    let quiet = Decision::quiet();
    let alarm = alarm();
    let mut acted = 0u64;

    for tick in 1..=TICKS {
        snapshot.seq = tick;
        snapshot.at_ns = tick * TICK_NS;
        if load {
            for slot in snapshot.counters.named_mut() {
                *slot += 400_000;
            }
        }
        // One incident, not one per rung change: a sustained attack is one state, and the
        // line count has to be a function of the states and not of how long the attack lasts.
        let attacking = load && (100..500).contains(&tick);
        if attacking && tick >= 110 {
            acted += 1;
        }
        journal.tick(
            &snapshot,
            if attacking { &alarm } else { &quiet },
            acted,
            TICK_COST,
        );
    }
}

static REST_LINES: AtomicU64 = AtomicU64::new(0);
static REST_BYTES: AtomicU64 = AtomicU64::new(0);
static LOAD_LINES: AtomicU64 = AtomicU64::new(0);
static LOAD_BYTES: AtomicU64 = AtomicU64::new(0);

#[test]
fn emitted_lines_under_load_are_the_same_order_as_at_rest() {
    let rest = Tally {
        lines: &REST_LINES,
        bytes: &REST_BYTES,
    };
    tracing::subscriber::with_default(log::subscriber(rest), || {
        drive(&mut Journal::default(), false);
    });
    let load = Tally {
        lines: &LOAD_LINES,
        bytes: &LOAD_BYTES,
    };
    tracing::subscriber::with_default(log::subscriber(load), || {
        drive(&mut Journal::default(), true);
    });

    let at_rest = REST_LINES.load(Ordering::Relaxed);
    let under_load = LOAD_LINES.load(Ordering::Relaxed);
    let bytes = LOAD_BYTES.load(Ordering::Relaxed);
    println!(
        "{TICKS} ticks at {} ms: {at_rest} lines at rest, {under_load} under load, ratio {:.2}",
        TICK_NS / 1_000_000,
        under_load as f64 / at_rest.max(1) as f64,
    );
    println!(
        "under load: {bytes} bytes, {} bytes a line, {:.0} lines per 30 s rate-limit interval",
        bytes / under_load.max(1),
        under_load as f64 * 30.0 / (TICKS * TICK_NS / 1_000_000_000) as f64,
    );

    // The ratio alone is not the guard, and running a broken emitter proved it: a version that
    // wrote one line per counter slot per aggregate emitted 2 100 lines at rest and 2 103 under
    // load, ratio 1.00, and passed. Thirty-five times the volume, still O(states) by the
    // ratio. So the rest count is pinned to the design constant as well: one line per
    // `AGGREGATE_NS` and no other line while nothing is happening. Derived from
    // `AGGREGATE_NS`, never from a byte budget read off a machine — a rate-limit ceiling
    // copied into this file would go stale on the next host.
    let heartbeats = TICKS * TICK_NS / AGGREGATE_NS;
    assert!(
        at_rest >= heartbeats - 1 && at_rest <= heartbeats,
        "{at_rest} lines at rest over {TICKS} ticks where {heartbeats} were expected: at rest \
         the agent emits one aggregate line per second and nothing else. Zero would mean \
         nothing was measured; more means the aggregate is not an aggregate."
    );
    // Three, and the three are named: detected, mitigating, cleared. Anything the packet rate
    // adds lands past this.
    assert!(
        under_load <= at_rest + 3,
        "{under_load} lines under load against {at_rest} at rest. The emission is a function \
         of the traffic, not of the state: one incident is allowed three lines and nothing \
         else is allowed any."
    );
}

static ALLOC_LINES: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

/// The assertion `tick_budget.rs` would make if it could see this module.
///
/// Ten thousand ticks, incidents opening and closing throughout, so every one of the four
/// line shapes is formatted many times. The warm-up runs one whole incident first: the `fmt`
/// layer formats into a thread-local `String` it reuses, and the tick the agent spends its
/// life in is the one after that buffer has reached its width.
#[test]
fn sustained_emission_allocates_nothing_after_the_first_lines() {
    let tally = Tally {
        lines: &ALLOC_LINES,
        bytes: &ALLOC_BYTES,
    };
    let subscriber = log::subscriber(tally);
    tracing::subscriber::with_default(subscriber, || {
        let mut journal = Journal::default();
        drive(&mut journal, true);

        let mut snapshot = snapshot();
        let quiet = Decision::quiet();
        let alarm = alarm();
        let mut acted = 0u64;
        let warm = ALLOC_LINES.load(Ordering::Relaxed);
        let before = ALLOCATIONS.with(Cell::get);
        let started = Instant::now();

        for tick in 1..=10_000u64 {
            snapshot.seq = tick;
            snapshot.at_ns = tick * TICK_NS;
            for slot in snapshot.counters.named_mut() {
                *slot += 400_000;
            }
            // An incident every hundred ticks, held for fifty: both transitions and the
            // aggregate are formatted repeatedly inside the counted region.
            let attacking = tick % 100 >= 50;
            if attacking && tick % 100 >= 60 {
                acted += 1;
            }
            journal.tick(
                &snapshot,
                if attacking { &alarm } else { &quiet },
                acted,
                TICK_COST,
            );
        }

        let elapsed = started.elapsed();
        let after = ALLOCATIONS.with(Cell::get);
        let lines = ALLOC_LINES.load(Ordering::Relaxed) - warm;
        println!(
            "10000 ticks, {lines} lines emitted, {} allocations, {elapsed:?} total",
            after - before
        );
        // Per second of agent life, not per tick: the claim being checked is a cost that does
        // not move with the packet rate, and the unit it is stated in is the second. Ten
        // thousand ticks at ten hertz is a thousand seconds of an agent. The write into the
        // journald socket is *not* in this number — the sink here counts and discards — so
        // this is the formatting and the emission and nothing else.
        println!(
            "{} ns per emitted line, {} ns per second of agent time (formatting only, no syscall)",
            elapsed.as_nanos() / u128::from(lines.max(1)),
            elapsed.as_nanos() / 1_000,
        );
        assert_eq!(
            after,
            before,
            "the emission allocated {} times. `panic = \"abort\"` makes a surprise allocation \
             in the tick an abort in production, which is what the span was rejected for.",
            after - before
        );
    });
}

static INCIDENT: Mutex<String> = Mutex::new(String::new());

#[test]
fn one_incident_emits_three_lines_and_the_last_carries_duration_and_volume() {
    let mut journal = Journal::default();
    let mut snapshot = snapshot();
    let quiet = Decision::quiet();
    let alarm = alarm();

    tracing::subscriber::with_default(log::subscriber(Capture(&INCIDENT)), || {
        // Every tick moves the counters by a known amount, so the volume on the third line is
        // a number this test can predict rather than read back.
        let mut tick = |seq: u64, decision: &Decision, acted: u64| {
            snapshot.seq = seq;
            // Below `AGGREGATE_NS` for the whole run, so no heartbeat shares the capture and
            // the three lines are the only lines.
            snapshot.at_ns = seq * 1_000_000;
            for slot in snapshot.counters.named_mut() {
                *slot += 1_000;
            }
            journal.tick(&snapshot, decision, acted, TICK_COST);
        };
        tick(1, &quiet, 0);
        tick(2, &alarm, 0);
        tick(3, &alarm, 1);
        tick(4, &alarm, 1);
        tick(5, &quiet, 1);
    });

    let captured = INCIDENT.lock().expect("capture buffer").clone();
    print!("{captured}");
    let lines: Vec<&str> = captured.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "an incident emitted {} lines instead of three:\n{captured}",
        lines.len()
    );
    assert!(lines[0].contains("detected"), "first line: {}", lines[0]);
    assert!(lines[1].contains("mitigating"), "second line: {}", lines[1]);
    assert!(lines[2].contains("cleared"), "third line: {}", lines[2]);

    // One id across the three, or the incident cannot be reassembled from the journal.
    let id = field(lines[0], "attack_id");
    assert_ne!(id, "0", "the attack_id is zero, so nothing was drawn");
    for line in &lines {
        assert_eq!(
            field(line, "attack_id"),
            id,
            "line carries a different id: {line}"
        );
    }

    // Detected on tick 2 at 2 ms, cleared on tick 5 at 5 ms.
    assert_eq!(
        field(lines[2], "duration_ms"),
        "3",
        "the third line must carry the duration: {}",
        lines[2]
    );
    // Ticks 3, 4 and 5 each moved every named slot by 1 000.
    assert_eq!(
        field(lines[2], "events"),
        (3 * 1_000 * NAMED_SLOTS).to_string(),
        "the third line must carry the volume: {}",
        lines[2]
    );
}

static WITHHELD: Mutex<String> = Mutex::new(String::new());

/// The honest complement, and the one place this file departs from three.
///
/// `--mode observe` is the default and it writes nothing into the list, so `acted` never
/// rises and there is no second transition to report. Two lines is the correct answer there,
/// and a module that emitted a "mitigating" line anyway would be reporting a rule that does
/// not exist.
#[test]
fn an_incident_nothing_acted_on_emits_two_lines() {
    let mut journal = Journal::default();
    let mut snapshot = snapshot();
    let quiet = Decision::quiet();
    let alarm = alarm();

    tracing::subscriber::with_default(log::subscriber(Capture(&WITHHELD)), || {
        for (seq, decision) in [(1, &quiet), (2, &alarm), (3, &alarm), (4, &quiet)] {
            snapshot.seq = seq;
            snapshot.at_ns = seq * 1_000_000;
            journal.tick(&snapshot, decision, 0, TICK_COST);
        }
    });

    let captured = WITHHELD.lock().expect("capture buffer").clone();
    print!("{captured}");
    assert_eq!(
        captured.lines().count(),
        2,
        "an incident nothing was applied for must report detection and end and nothing \
         between:\n{captured}"
    );
}

static OK_LOST: AtomicU64 = AtomicU64::new(0);
static BROKEN_LOST: AtomicU64 = AtomicU64::new(0);

/// A sink that refuses everything, which is what a journald socket looks like after journald
/// has gone away.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Failing;

impl<'a> MakeWriter<'a> for Failing {
    type Writer = log::Counted<Broken>;

    fn make_writer(&'a self) -> Self::Writer {
        log::Counted::new(Broken, &BROKEN_LOST)
    }
}

#[derive(Clone, Copy)]
struct Working;

/// Counted over a tally, so the number of lines the broken sink is judged against is the one
/// the working sink actually accepted from the same drive rather than a constant written here.
impl<'a> MakeWriter<'a> for Working {
    type Writer = log::Counted<Tally>;

    fn make_writer(&'a self) -> Self::Writer {
        log::Counted::new(
            Tally {
                lines: &WORKING_LINES,
                bytes: &WORKING_BYTES,
            },
            &OK_LOST,
        )
    }
}

static WORKING_LINES: AtomicU64 = AtomicU64::new(0);
static WORKING_BYTES: AtomicU64 = AtomicU64::new(0);

#[test]
fn the_lost_counter_is_non_zero_exactly_when_a_write_fails() {
    let mut journal = Journal::default();
    tracing::subscriber::with_default(log::subscriber(Working), || {
        drive(&mut journal, true);
    });
    let lines = WORKING_LINES.load(Ordering::Relaxed);
    assert!(lines > 0, "nothing was emitted, so nothing was measured");
    assert_eq!(
        OK_LOST.load(Ordering::Relaxed),
        0,
        "a sink that accepted every write was reported as losing lines"
    );

    tracing::subscriber::with_default(log::subscriber(Failing), || {
        drive(&mut Journal::default(), true);
    });
    let lost = BROKEN_LOST.load(Ordering::Relaxed);
    println!("{lines} lines into a broken sink: lost = {lost}");
    assert!(
        lost >= lines,
        "{lines} lines went into a sink that refused all of them and only {lost} were counted \
         lost. A daemon that loses logs without saying so is worse than a silent one."
    );
}

/// Reads a `key=value` field out of a formatted line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let mut needle = String::from(" ");
    needle.push_str(key);
    needle.push('=');
    let after = line
        .split_once(&needle)
        .unwrap_or_else(|| panic!("no {key} on {line}"))
        .1;
    after.split_whitespace().next().unwrap_or("")
}

/// journald is the sink, so the last question is one only journald can answer.
///
/// Gated behind `kernel-tests` for the reason every privileged test in this tree is: it needs
/// to read the system journal, which an unprivileged `cargo test --workspace` cannot, and a
/// test that returns zero because it could not look is the failure mode this repository has
/// been burnt by twice. Under `kernel-tests.sh` it runs as root.
///
/// It writes the volume the agent would write in two minutes and then checks that all of it
/// came back. The count is the real assertion and the `Suppressed` grep is the weaker one:
/// measured on `lab-dev`, journald wrote that notice only when the next message of the unit
/// arrived after the interval, so a unit that stops logging at the end of its burst loses its
/// lines in silence.
#[cfg(feature = "kernel-tests")]
#[test]
fn journald_kept_every_line_two_minutes_of_the_agent_would_write() {
    use std::process::{Command, Stdio};

    let identifier = format!("lorica-log-volume-{}", std::process::id());
    let expected = 120 * 1_000_000_000 / AGGREGATE_NS + 3;

    let mut cat = Command::new("systemd-cat")
        .arg("-t")
        .arg(&identifier)
        .stdin(Stdio::piped())
        .spawn()
        .expect("systemd-cat is not on PATH, so journald cannot be measured from here");
    {
        let stdin = cat.stdin.as_mut().expect("systemd-cat stdin");
        for line in 0..expected {
            writeln!(
                stdin,
                "INFO digest tick_seq={line} ticks=10 slots_moved=34 events=13600000 \
                 read_failures=0 rung=0 lines={line} lost=0"
            )
            .expect("writing to systemd-cat");
        }
    }
    assert!(cat.wait().expect("systemd-cat").success());

    let mut journal = String::new();
    for _ in 0..40 {
        let out = Command::new("journalctl")
            .args([
                "-t",
                &identifier,
                "--since",
                "-2min",
                "--no-pager",
                "-o",
                "cat",
            ])
            .output()
            .expect("journalctl is not on PATH, so journald cannot be measured from here");
        journal = String::from_utf8_lossy(&out.stdout).into_owned();
        if journal.lines().count() as u64 >= expected {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    let stored = journal.lines().count() as u64;
    let suppressed = journal.matches("Suppressed").count();
    println!(
        "{expected} lines written through systemd-cat, {stored} read back, {suppressed} suppression notices"
    );
    assert!(
        stored > 0,
        "journalctl returned nothing for {identifier}. Nothing was measured, so there is no \
         verdict to give."
    );
    assert_eq!(
        stored, expected,
        "journald kept {stored} of {expected} lines. The rate limit is per service and its \
         effective burst is the configured one scaled by free disk space."
    );
    assert_eq!(
        suppressed, 0,
        "journald reported suppressing messages from this identifier"
    );
}
