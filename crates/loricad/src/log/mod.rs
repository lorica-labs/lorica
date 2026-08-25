//! One aggregate line per second, whatever the packet rate, because the sink throws the
//! rest away.
//!
//! **The number that sets the shape, read off the machine rather than off a document.**
//! journald rate-limits per service. On `lab-dev` `/etc/systemd/journald.conf` sets nothing,
//! so the compiled defaults apply — `RateLimitIntervalSec=30s`, `RateLimitBurst=10000`, both
//! confirmed by `systemd-analyze cat-config systemd/journald.conf` and by `man 5
//! journald.conf` — and journald then scales that burst by the free space of the journal
//! filesystem. So the configured number is not the ceiling: 60 000 lines pushed through one
//! transient unit there stored 37 502 and dropped 22 500, which puts the effective ceiling at
//! 37 500 per 30 s, or 1 250 lines a second for one service. A line per source under a flood
//! is past that by two orders of magnitude, and the lines it destroys are the incident lines,
//! because those fall in the same interval as the flood that caused them.
//!
//! **The drop is not always announced.** `Suppressed 22500 messages from …` is written when
//! the *next* message of that unit arrives after the interval, not when the drop happens: in
//! the run above where the unit exited at the end of its burst, 22 500 messages were lost and
//! no notice was written at all. A grep for `Suppressed` therefore proves nothing by itself,
//! which is why [`lost`] counts what this process knows it failed to hand over.
//!
//! **What was rejected, with its cost.** `tracing-appender`'s `non_blocking` buffers
//! `DEFAULT_BUFFERED_LINES_LIMIT` = 128 000 lines; at the ~140 bytes an aggregate line
//! measures in `tests/log_volume.rs` that is about 18 MB of anonymous heap, and it fills
//! precisely during an attack. The buffer that absorbs a burst has to be the kernel's socket
//! buffer, not this process's RSS. A span per tick was rejected for a different reason: a span
//! allocates under `Registry` where an event does not, and this binary is `panic = "abort"`
//! with a counting allocator asserted at zero over the tick, so correlation is a `u64` field
//! instead — see [`incident`].
//!
//! **What the text layer on stderr gives up.** journald assigns one syslog priority to a
//! stream, so `WARN` and `INFO` arrive at the same level and `journalctl -p` cannot separate
//! them; the level is in the text and greppable, and nothing else. The alternative is the
//! native protocol, which buys structured fields and one more dependency, and it is not here
//! because the fields this agent needs to correlate on are two integers.

pub mod incident;

use std::{
    io::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use lorica_detect::{Decision, Snapshot, snapshot::NAMED_SLOTS};
use tracing::{Level, info};
use tracing_subscriber::{fmt::MakeWriter, util::SubscriberInitExt};

pub use incident::Incident;

/// Nanoseconds between two aggregate lines.
///
/// One second, which is 30 lines per rate-limit interval against the 37 500 measured above:
/// 0.08 % of the budget, so the incident lines that share the interval cannot be crowded out
/// by the heartbeat. It is a heartbeat and not "emit only when something changed" on purpose —
/// a line count that falls to zero at rest gives the volume test no denominator, and an agent
/// that stops writing is indistinguishable from an agent that died.
pub const AGGREGATE_NS: u64 = 1_000_000_000;

/// Writes that did not reach the sink.
static LOST: AtomicU64 = AtomicU64::new(0);

/// Counter movements an aggregate line stands for instead of naming.
static FOLDED: AtomicU64 = AtomicU64::new(0);

/// Writes this process failed to hand to the sink.
///
/// Writes and not lines: a line whose first `write` succeeded and whose second failed is one
/// failure against a partial line, and reporting it as a whole line lost would be the
/// generous direction. What this cannot see is the sink dropping a line it accepted, which is
/// journald's rate limit, and which is why `tests/log_volume.rs` also goes and asks journald.
pub fn lost() -> u64 {
    LOST.load(Ordering::Relaxed)
}

/// Counter slots that moved between two aggregate lines, summed.
///
/// This is the counter that stands where a ring-buffer overflow counter would: **no crate in
/// this tree declares a ring buffer**, so a `ringbuf_overflow` series would render zero
/// forever, and a metric that is always zero is worse than an absent one — this repository
/// has already shipped 34 stage counters of which 18 were named. What is observable today is
/// the other half of the same hole: how many distinct counter movements the aggregate line
/// represents rather than names. Zero at rest, up to `NAMED_SLOTS` per aggregate line under
/// load.
///
/// Both this and [`lost`] are on the aggregate line as well as here. That is not duplication
/// for its own sake: `metrics/registry.rs` does not read them yet, and a counter whose only
/// reader is a Prometheus series nobody has wired up is a counter nobody can check.
pub fn folded() -> u64 {
    FOLDED.load(Ordering::Relaxed)
}

/// Installs the one subscriber: text, no colour, no timestamp, stderr.
///
/// No timestamp because journald stamps every entry it accepts, and an RFC3339 stamp is 27
/// bytes on a 140-byte line — 19 % of everything this agent will ever write, duplicated. No
/// ANSI because escape codes in a journal are bytes an operator has to filter. No
/// `EnvFilter`: the level is fixed here and `release_max_level_info` removes `trace!` and
/// `debug!` from the binary, so there is no runtime knob to be surprised by and no dependency
/// on the directive parser.
pub fn init() -> Result<()> {
    subscriber(Stderr).try_init()?;
    Ok(())
}

/// The one format, parameterised only by where it writes.
///
/// Exposed so `tests/log_volume.rs` counts the lines this agent actually emits. A test that
/// built its own `fmt()` would measure a format that drifts from this one, which is the
/// failure mode this repository already has a name for.
pub fn subscriber<W>(writer: W) -> impl tracing::Subscriber + Send + Sync + 'static
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_max_level(Level::INFO)
        .finish()
}

/// stderr, with the writes that did not land counted.
pub struct Stderr;

impl<'a> MakeWriter<'a> for Stderr {
    type Writer = Counted<io::Stderr>;

    fn make_writer(&'a self) -> Self::Writer {
        Counted::new(io::stderr(), &LOST)
    }
}

/// A writer that counts its own failures, because what the layer above it does with them is
/// not usable here.
///
/// `tracing_subscriber`'s `fmt` layer does react to a failed write: it prints `[tracing-
/// subscriber] Unable to write an event to the Writer for this Subscriber! Error: …` — to
/// `io::stderr()`, which under this daemon is the socket that just refused the write.
/// Verified in `tests/log_volume.rs`, where 63 refused lines produce 63 of those notices and
/// nowhere for them to go. So the number an operator can actually reach has to be a counter,
/// and it is a field rather than a global so a test can own one while other tests run in
/// parallel threads.
pub struct Counted<W> {
    inner: W,
    lost: &'static AtomicU64,
}

impl<W> Counted<W> {
    pub const fn new(inner: W, lost: &'static AtomicU64) -> Self {
        Self { inner, lost }
    }
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            // `Ok(0)` on a non-empty buffer is a sink that accepted nothing, which
            // `write_all` turns into `WriteZero` above us and the layer then discards. It is
            // a loss and it is counted as one.
            Ok(0) if !buf.is_empty() => {
                self.lost.fetch_add(1, Ordering::Relaxed);
                Ok(0)
            }
            Ok(written) => Ok(written),
            Err(error) => {
                self.lost.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What the tick emits, and the state that keeps it to one line a second.
///
/// The named totals of the last aggregate line are kept here rather than recomputed per tick:
/// the delta is only needed when a line is written, so nine ticks out of ten at 10 Hz do
/// nothing but compare two `u64`s and ask the incident whether anything changed.
pub struct Journal {
    incident: Incident,
    /// `Snapshot::at_ns` of the last aggregate line.
    emitted_at_ns: u64,
    /// `Snapshot::seq` of the last aggregate line, so the next one carries the jump.
    emitted_seq: u64,
    /// The named totals as the last aggregate line saw them.
    seen: [u64; NAMED_SLOTS],
    lines: u64,
}

/// Written out because there is no derive to have: `Default` is implemented for arrays up to
/// 32 elements and `NAMED_SLOTS` is 34.
impl Default for Journal {
    fn default() -> Self {
        Self {
            incident: Incident::default(),
            emitted_at_ns: 0,
            emitted_seq: 0,
            seen: [0; NAMED_SLOTS],
            lines: 0,
        }
    }
}

impl Journal {
    /// One tick. Emits at most one aggregate line and at most one incident line.
    ///
    /// `acted` is the running count of rungs the tick has written into the list or withheld
    /// from it. It is passed as one number rather than read from the enforcement result
    /// because a rise in it is the only thing this module needs to know: that the rung stopped
    /// being a decision and became a rule.
    pub fn tick(&mut self, snapshot: &Snapshot, decision: &Decision, acted: u64) {
        self.lines += self.incident.observe(snapshot, decision, acted);

        if snapshot.at_ns.saturating_sub(self.emitted_at_ns) < AGGREGATE_NS {
            return;
        }

        let named = snapshot.counters.named();
        let mut moved = 0u64;
        let mut events = 0u64;
        for (index, total) in named.iter().enumerate() {
            let delta = total.saturating_sub(self.seen[index]);
            if delta > 0 {
                moved += 1;
                events = events.wrapping_add(delta);
            }
        }
        FOLDED.fetch_add(moved, Ordering::Relaxed);
        self.seen = *named;
        self.lines += 1;

        info!(
            tick_seq = snapshot.seq,
            // The jump, not the count. A tick the agent did not get to run leaves a hole
            // here, and that hole is the earliest evidence of saturation available — earlier
            // than any share of a core, because it is the agent's own missed work.
            ticks = snapshot.seq.saturating_sub(self.emitted_seq),
            // The delta over this interval. The two cumulative counters below are the ones
            // exported, and they are on the line so an agent whose `/metrics` is off still
            // reports them.
            events,
            read_failures = snapshot.counters.failures(),
            rung = decision.tier().rung(),
            lines = self.lines,
            folded = folded(),
            lost = lost(),
            "digest"
        );

        self.emitted_at_ns = snapshot.at_ns;
        self.emitted_seq = snapshot.seq;
    }
}
