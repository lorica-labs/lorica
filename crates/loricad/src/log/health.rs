//! Which of three suspects the tail of a tick belongs to, read off the kernel once per
//! tick and reported once per second.
//!
//! **The question this exists to close.** The worst tick over a thousand measures 3.4× the
//! mean on the lab guest, and it is unstable between runs. Three causes fit and they do not
//! have the same answer:
//!
//! - **CFS preemption.** `generic_map_lookup_batch` calls `cond_resched()` per element, so a
//!   sweep of fifty thousand slots offers the scheduler fifty thousand chances to take the
//!   thread away. `ru_nivcsw` counts exactly that, and a tail correlated with it is a tail
//!   `SCHED_FIFO` on this thread would remove.
//! - **Hypervisor steal.** An 8 vCPU guest whose processors are not pinned loses time to the
//!   host, and that loss is **invisible in `ru_nivcsw`**: nothing preempted the thread, the
//!   processor under it stopped existing. It shows up in the `steal` field of `/proc/stat`
//!   and in the runqueue-wait of `schedstat`. No optimisation inside the guest removes it,
//!   and the number to publish then is the median rather than the worst.
//! - **A buffer being faulted in.** A read buffer reallocated between ticks faults in during
//!   `copy_to_user`, which is a page fault inside the syscall and therefore inside the tick.
//!   `ru_minflt` counts it. The reader allocates nothing after its constructor by design, so
//!   this one must read **zero after the first tick** — it is the assertion, not the
//!   suspect.
//!
//! It lives next to [`incident`](super::incident) and is driven the same way: sampled by
//! `Journal::tick` on every tick, rendered by it when a line is due. The tick's own duration
//! is measured by the agent's loop and passed in, because the loop is the only place that
//! knows where a tick begins and ends.
//!
//! **Why it rides on the one-per-second digest instead of a `debug!` per tick.** `debug!` is
//! compiled out of this binary: `release_max_level_info` is on in `Cargo.toml`, so a
//! diagnostic behind it would be absent from exactly the build the lab measures. And a line
//! per tick is ten a second against the one line per second the whole logging design is
//! asserted at. So the sampling is per tick — that is where the correlation lives — and the
//! report is per second, on the line that already exists.
//!
//! **Why not three more metric series.** `tests/series_cap.rs` allows sixty-four and sixty
//! are rendered. Six fields do not fit, and the ceiling is a decision rather than a budget
//! to spend.
//!
//! **What the kernel may refuse to answer.** `schedstat` reports a runqueue-wait of zero
//! unless `kernel.sched_schedstats` is on, which it is not by default on most distributions.
//! A zero there is therefore "not measured" and not "did not wait"; `sysctl -w
//! kernel.sched_schedstats=1` is part of the measurement protocol, not of the agent's
//! requirements. `steal` needs nothing turned on.

use std::{fs::File, os::unix::fs::FileExt, time::Duration};

/// Enough for the aggregate `cpu` line of `/proc/stat`, which is ten numbers and a label.
/// The file continues with one line per processor and this reads none of it: the aggregate
/// is first, so a short read is the whole answer.
const STAT_BYTES: usize = 256;

/// `schedstat` is three numbers on one line.
const SCHEDSTAT_BYTES: usize = 96;

/// What one second of ticks looked like. Deltas over the interval, except the two durations.
#[derive(Clone, Copy, Default)]
pub struct Report {
    /// The worst single tick of the interval.
    pub worst: Duration,
    /// Total time in ticks over the interval, so the caller can render a mean without this
    /// module deciding what to divide by.
    pub spent: Duration,
    pub ticks: u32,
    /// Involuntary context switches. Correlated with [`Self::worst`] over several intervals
    /// ⇒ CFS preemption.
    pub nivcsw: u64,
    /// Minor faults. Expected to be zero: the readers allocate nothing after construction.
    pub minflt: u64,
    /// Steal over the interval. Correlated with [`Self::worst`] ⇒ the hypervisor, and no
    /// change inside the guest will move it.
    pub steal_us: u64,
    /// Time the ticking thread spent runnable and not running, from `schedstat`. Zero when
    /// the kernel is not keeping schedstats.
    pub runq_wait_us: u64,
}

impl Report {
    pub fn mean(&self) -> Duration {
        self.spent.checked_div(self.ticks).unwrap_or_default()
    }
}

/// The three sources, opened once.
///
/// Opened and not reopened per read, and read with `read_at` rather than with a seek: two
/// syscalls a tick, no allocation, and `/proc` regenerates the file on every `pread` from
/// offset zero, so the answer is fresh without the handle being churned.
///
/// The `schedstat` handle is bound to the thread that constructed this, because `/proc`
/// resolves `thread-self` at `open` and not at `read`. That is the property that makes it the
/// right instrument: the agent runs one `current_thread` runtime, so the thread that builds
/// the journal is the thread that ticks, and a handle that followed the reader instead would
/// answer about whoever happened to scrape.
pub struct Diagnostic {
    stat: Option<File>,
    schedstat: Option<File>,
    /// Absolute readings of the previous tick, so what is reported is a delta.
    last: Absolute,
    /// The interval being accumulated.
    window: Report,
    started: bool,
}

/// The cumulative numbers, as the kernel reports them.
#[derive(Clone, Copy, Default)]
struct Absolute {
    nivcsw: u64,
    minflt: u64,
    steal_ticks: u64,
    runq_wait_ns: u64,
}

impl Default for Diagnostic {
    fn default() -> Self {
        Self {
            // Silent on failure, in both directions. A container with a masked `/proc` is
            // not a reason for the agent to refuse to start, and a diagnostic that reports
            // zero is distinguishable from one that reports a number.
            stat: File::open("/proc/stat").ok(),
            schedstat: File::open("/proc/thread-self/schedstat").ok(),
            last: Absolute::default(),
            window: Report::default(),
            started: false,
        }
    }
}

impl Diagnostic {
    /// Samples the kernel and folds one tick into the interval being accumulated.
    ///
    /// `elapsed` is the tick's own duration, measured by the caller: the correlation this
    /// module is for is between that number and the three below it, so a duration measured
    /// anywhere else would be correlating the wrong thing.
    pub fn observe(&mut self, elapsed: Duration) {
        let now = self.sample();

        // The first tick has no previous reading, so it contributes a duration and no
        // deltas. It is also the tick entitled to fault its buffers in, which is why
        // `minflt` is only meaningful from the second one.
        if self.started {
            self.window.nivcsw += now.nivcsw.saturating_sub(self.last.nivcsw);
            self.window.minflt += now.minflt.saturating_sub(self.last.minflt);
            self.window.steal_us +=
                ticks_to_us(now.steal_ticks.saturating_sub(self.last.steal_ticks));
            self.window.runq_wait_us +=
                now.runq_wait_ns.saturating_sub(self.last.runq_wait_ns) / 1_000;
        }
        self.last = now;
        self.started = true;

        self.window.worst = self.window.worst.max(elapsed);
        self.window.spent += elapsed;
        self.window.ticks += 1;
    }

    /// Hands back the interval and starts the next one.
    pub fn take(&mut self) -> Report {
        std::mem::take(&mut self.window)
    }

    fn sample(&self) -> Absolute {
        // SAFETY: `rusage` is a plain struct of integers and timevals, so an all-zero
        // bit pattern is a valid value of it. It is written by the call below and read
        // only if that call succeeded.
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        // SAFETY: the destination is a fully owned `rusage` of the kernel's own size, and
        // RUSAGE_THREAD is one of the three constants this call accepts. A negative return
        // leaves the struct as it was, which is zeroed.
        let rusage_ok = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut usage) } == 0;

        // On the stack, so the two reads below allocate nothing.
        let mut stat = [0u8; STAT_BYTES];
        let mut schedstat = [0u8; SCHEDSTAT_BYTES];
        let steal = self
            .stat
            .as_ref()
            .and_then(|file| first_line(file, &mut stat))
            .and_then(steal_ticks)
            .unwrap_or(0);
        let wait = self
            .schedstat
            .as_ref()
            .and_then(|file| first_line(file, &mut schedstat))
            .and_then(runq_wait_ns)
            .unwrap_or(0);

        Absolute {
            nivcsw: if rusage_ok { usage.ru_nivcsw as u64 } else { 0 },
            minflt: if rusage_ok { usage.ru_minflt as u64 } else { 0 },
            steal_ticks: steal,
            runq_wait_ns: wait,
        }
    }
}

/// `USER_HZ` and not `CONFIG_HZ`: `/proc/stat` counts in the former, which is 100 on every
/// architecture Linux supports and is what `sysconf(_SC_CLK_TCK)` returns.
fn ticks_to_us(ticks: u64) -> u64 {
    // SAFETY: no argument is a pointer and the name is a constant of the C library.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    ticks.saturating_mul(1_000_000) / hz
}

/// The first line of a `/proc` file, read into a caller-owned buffer.
///
/// The buffer is the caller's array and not a `String`, because this runs inside the tick and
/// the tick is asserted to allocate nothing. A short read is the whole answer for both files
/// here: what is wanted is on the first line of each.
fn first_line<'a>(file: &File, buffer: &'a mut [u8]) -> Option<&'a str> {
    let read = file.read_at(buffer, 0).ok()?;
    std::str::from_utf8(&buffer[..read]).ok()?.lines().next()
}

/// The eighth number of the aggregate `cpu` line, which is `steal`.
///
/// Counted by index rather than found by name, because the line has no names: the kernel
/// appends fields to it as it gains accounting — `guest` in 2.6.24, `guest_nice` in 2.6.33 —
/// and every one of them lands *after* `steal`. So an index from the left is stable where an
/// index from the right is not, which is what [`steal_from_the_left_and_not_the_right`]
/// pins.
fn steal_ticks(line: &str) -> Option<u64> {
    let mut fields = line.split_ascii_whitespace();
    // The label, then user nice system idle iowait irq softirq, then steal.
    if fields.next()? != "cpu" {
        return None;
    }
    fields.nth(6)?;
    fields.next()?.parse().ok()
}

/// The second number of `schedstat`, which is `wait_sum`: nanoseconds the task spent on a
/// runqueue without the processor.
fn runq_wait_ns(line: &str) -> Option<u64> {
    line.split_ascii_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel has appended fields to this line twice in its history and will again, so
    /// the same reading has to come out of a line with extra numbers on the end. Both of
    /// these are real `/proc/stat` lines: one from a 2.6.23 kernel, one from a current one.
    #[test]
    fn steal_from_the_left_and_not_the_right() {
        let old = "cpu  100 20 300 4000 50 6 7 888";
        let new = "cpu  100 20 300 4000 50 6 7 888 9999 11111";
        assert_eq!(steal_ticks(old), Some(888));
        assert_eq!(steal_ticks(new), Some(888));
        // A per-processor line is not the aggregate, and reading one as the aggregate would
        // report the steal of processor zero as the steal of the machine.
        assert_eq!(steal_ticks("cpu0 100 20 300 4000 50 6 7 888"), None);
        // A kernel too old to account for steal at all has seven numbers.
        assert_eq!(steal_ticks("cpu  100 20 300 4000 50 6 7"), None);
    }

    #[test]
    fn the_runqueue_wait_is_the_second_number() {
        // run_time, wait_sum, timeslices, as /proc/<tid>/schedstat prints them.
        assert_eq!(runq_wait_ns("123456789 987654 4242"), Some(987_654));
        // Schedstats off: the kernel prints the line and the middle number stays zero, which
        // is "not measured" and not "did not wait".
        assert_eq!(runq_wait_ns("123456789 0 4242"), Some(0));
        assert_eq!(runq_wait_ns(""), None);
    }

    /// The interval empties when it is taken, so two reports never carry the same tick
    /// twice. A `worst` that survived a `take` would report a spike forever.
    #[test]
    fn taking_the_report_starts_the_next_interval() {
        let mut diagnostic = Diagnostic::default();
        diagnostic.observe(Duration::from_micros(400));
        diagnostic.observe(Duration::from_micros(1_900));
        let first = diagnostic.take();
        assert_eq!(first.ticks, 2);
        assert_eq!(first.worst, Duration::from_micros(1_900));
        assert_eq!(first.mean(), Duration::from_micros(1_150));

        let second = diagnostic.take();
        assert_eq!(second.ticks, 0);
        assert_eq!(second.worst, Duration::ZERO);
        assert_eq!(second.mean(), Duration::ZERO);
    }
}
