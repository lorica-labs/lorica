//! One timer, two cadences, nothing else.
//!
//! The tick is the only periodic thing in the agent, and every later phase adds work to
//! this one sweep rather than a timer of its own. A timer per flow, or per bucket, is how
//! an agent that promised to be invisible ends up waking a core sixty times a second.
//!
//! **Why two cadences.** Reading a per-CPU counter slot costs about 264 ns on the target,
//! measured, and the cost is exactly linear in slots read per second: the kernel copies
//! `8 × possible_cpus` bytes per element across the syscall boundary with two
//! `copy_to_user` calls, so batching saves the syscall entry and nothing else. Fifty
//! thousand slots at ten hertz is half a million slot-reads a second, which is 13 % of a
//! core — no batch size changes that.
//!
//! The way out is not a faster read, it is reading what is actually needed. The named
//! counters are the control signal and there are eighteen of them; the slots above them
//! belong one to an entry of the unified list and are forensic — they answer "which
//! allow-listed source is leaving the pipeline", which nobody asks ten times a second.
//! So the named counters are read every tick and the whole map on a declared slower
//! sweep, and the agent says which cadence it is running.
//!
//! The sweep allocates nothing. That is assertion 6: the single-element form of this read
//! allocates once per slot, which under this load would be half a million allocations a
//! second in the one process that promised not to be a source of jitter.

use carapace_dataplane::maps::batch::PerCpuU64Reader;

pub struct Sweep {
    /// The named counters, read every tick.
    named: PerCpuU64Reader<'static>,
    /// Every slot, read every `every` ticks.
    full: PerCpuU64Reader<'static>,
    every: u64,
    slots: usize,
    named_slots: usize,
    ticks: u64,
    full_sweeps: u64,
    failures: u64,
    counted: u64,
    named_counted: u64,
}

impl Sweep {
    pub fn new(
        named: PerCpuU64Reader<'static>,
        full: PerCpuU64Reader<'static>,
        named_slots: usize,
        slots: usize,
        every: u64,
    ) -> Self {
        Self {
            named,
            full,
            every: every.max(1),
            slots,
            named_slots,
            ticks: 0,
            full_sweeps: 0,
            failures: 0,
            counted: 0,
            named_counted: 0,
        }
    }

    /// Reads the named counters, and every slot when this tick is one of the slower ones.
    ///
    /// A failed read leaves the previous total standing rather than zeroing it. Zeroing
    /// would publish a drop to nothing, which reads as an attack ending rather than as a
    /// read that did not happen, and the failure count is what says which it was.
    pub fn run(&mut self) {
        self.ticks += 1;

        match self.named.read() {
            Ok(totals) => self.named_counted = totals.iter().sum(),
            Err(_) => self.failures += 1,
        }

        if self.ticks % self.every == 0 {
            self.full_sweeps += 1;
            match self.full.read() {
                Ok(totals) => self.counted = totals.iter().sum(),
                Err(_) => self.failures += 1,
            }
        }
    }

    /// Slots read per second at this cadence, which is the number the cost is linear in
    /// and therefore the only one worth comparing between configurations.
    pub fn slot_reads_per_second(&self, hz: u32) -> u64 {
        let hz = u64::from(hz);
        self.named_slots as u64 * hz + (self.slots as u64 * hz) / self.every
    }

    pub fn slots(&self) -> usize {
        self.slots
    }

    pub fn every(&self) -> u64 {
        self.every
    }

    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    pub fn full_sweeps(&self) -> u64 {
        self.full_sweeps
    }

    pub fn failures(&self) -> u64 {
        self.failures
    }

    pub fn counted(&self) -> u64 {
        self.counted
    }

    pub fn named_counted(&self) -> u64 {
        self.named_counted
    }
}
