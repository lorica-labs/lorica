//! One timer, two cadences, nothing else.
//!
//! The tick is the only periodic thing in the agent, and every later phase adds work to
//! this one sweep rather than a timer of its own. A timer per flow, or per bucket, is how
//! an agent that promised to be invisible ends up waking a core sixty times a second.
//!
//! **Why two cadences, and what stopped being true.** Reading a counter slot through
//! `BPF_MAP_LOOKUP_BATCH` cost 215 ns on the target (`measure_batch` on carapace-target,
//! 6.8.0-138, four possible processors, 50 000 slots), and the cost was exactly linear in
//! slots read per second: the kernel copies `8 × possible_cpus` bytes per element across the
//! syscall boundary with two `copy_to_user` calls, so batching saved the syscall entry and
//! nothing else. Fifty thousand slots at ten hertz was **10.8 % of a core** and no batch size
//! changed it.
//!
//! Since the counter array became mappable, the same read is **4.16 ns a slot and 0.21 % of a
//! core** — a factor of 52, measured before and after on the same machine in the same run.
//! The whole tick over 4 096 slots went from a mean of 864 µs to **14.5 µs**
//! (`tick_budget.rs`, optimised, same machine). The two cadences below therefore no longer
//! buy what they were built to buy, and they stay for what they still buy: `every` bounds
//! the freshness an operator asks for, and the stride bounds the worst read of the fallback
//! path, which is the one that got *more* expensive — see [`Counters`].
//!
//! The way out was not a faster read, it was reading what is actually needed. The named
//! counters are the control signal and [`CounterId::ALL`](lorica_common::CounterId::ALL)
//! says how many — thirty-four today, and read from there rather than written down here for
//! the reason the next paragraph is about; the slots above them
//! belong one to an entry of the unified list and are forensic — they answer "which
//! allow-listed source is leaving the pipeline", which nobody asks ten times a second.
//! So the named counters are read every tick and the whole map on a declared slower
//! sweep, and the agent says which cadence it is running.
//!
//! **Why the per-counter totals are kept and not summed.** This sweep used to read the
//! named counters in one batch, reduce them with `totals.iter().sum()` and drop the slice.
//! The sum is a real signal and it is not the one the exposition needs: with the vector
//! gone, all thirty-four `lorica_stage_events_total` series rendered zero in the running
//! agent, permanently, and a metric that is always zero is worse than an absent one
//! because it looks like it works. What is kept instead is one total per
//! [`CounterId`](lorica_common::CounterId) — 272 bytes, written by a copy inside the tick —
//! and its length comes from `CounterId::ALL`. Not from a literal: this tree has already
//! shipped eighteen named counters against thirty-four real ones, and a number copied from
//! one crate into another expires without saying so.
//!
//! The sweep allocates nothing. That is assertion 6: the single-element form of this read
//! allocates once per slot, which under this load would be half a million allocations a
//! second in the one process that promised not to be a source of jitter.

use lorica_dataplane::maps::{Counters, bank::BankReader};
use lorica_detect::snapshot::NAMED_SLOTS;

pub struct Sweep {
    /// The named counters, read every tick.
    named: Counters<'static>,
    /// Every slot, read every `every` ticks.
    full: Counters<'static>,
    every: u64,
    slots: usize,
    named_slots: usize,
    ticks: u64,
    full_sweeps: u64,
    failures: u64,
    counted: u64,
    named_counted: u64,
    /// One total per named counter, at its own `CounterId::index()`, as the last successful
    /// read left it. This is what the exposition renders; `named_counted` is its sum and
    /// keeping only the sum is what left thirty-four series at zero.
    named_totals: [u64; NAMED_SLOTS],
    /// The bank, read every `bank_every` ticks, or absent when the agent could not open it.
    ///
    /// **A slower cadence than the counters, and the reason is what the bank is.** A level is a
    /// pressure reading and never a proof: 1 024 buckets against any realistic source count
    /// means two sources share one, so nothing built on it can name whom to refuse. Freshness
    /// buys a confirmed key nothing, and this read costs a syscall and 64 KiB of copy where the
    /// counter sweep costs neither. Absent rather than fatal: an agent that cannot open the
    /// bank is an agent with no pressure signal, which is a smaller thing than an agent that
    /// refused to start.
    bank: Option<BankReader<'static>>,
    bank_every: u64,
    bank_sweeps: u64,
    /// When the last complete pass of each slice landed, on the tick's own clock. Zero means
    /// never, and a stamp that does not move is how the detector learns that a slice was not
    /// looked at rather than that it did not change.
    full_at_ns: u64,
    bank_at_ns: u64,
}

impl Sweep {
    pub fn new(
        named: Counters<'static>,
        full: Counters<'static>,
        named_slots: usize,
        slots: usize,
        every: u64,
        bank: Option<BankReader<'static>>,
        bank_every: u64,
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
            named_totals: [0; NAMED_SLOTS],
            bank,
            bank_every: bank_every.max(1),
            bank_sweeps: 0,
            full_at_ns: 0,
            bank_at_ns: 0,
        }
    }

    /// Reads the named counters, and every slot when this tick is one of the slower ones.
    ///
    /// A failed read leaves the previous total standing rather than zeroing it. Zeroing
    /// would publish a drop to nothing, which reads as an attack ending rather than as a
    /// read that did not happen, and the failure count is what says which it was.
    pub fn run(&mut self, at_ns: u64) {
        self.ticks += 1;

        match self.named.read() {
            Ok(totals) => {
                // Zipped and not copied wholesale: the reader is built for `named_slots`,
                // which is a runtime number, and a slice shorter than the array must leave
                // the slots it does not cover standing rather than panic the tick.
                for (slot, total) in self.named_totals.iter_mut().zip(totals) {
                    *slot = *total;
                }
                self.named_counted = self.named_totals.iter().sum();
            }
            Err(_) => self.failures += 1,
        }

        if self.ticks.is_multiple_of(self.every) {
            self.full_sweeps += 1;
            match self.full.read() {
                Ok(totals) => {
                    self.counted = totals.iter().sum();
                    // Stamped only here. A tick that did not sweep, and a sweep that failed,
                    // both leave the previous stamp standing -- which is what tells the
                    // detector that the per-entry slots were not looked at, rather than that
                    // they did not move.
                    self.full_at_ns = at_ns;
                }
                Err(_) => self.failures += 1,
            }
        }

        if self.ticks.is_multiple_of(self.bank_every)
            && let Some(bank) = self.bank.as_mut()
        {
            self.bank_sweeps += 1;
            match bank.read() {
                Ok(_) => self.bank_at_ns = at_ns,
                Err(_) => self.failures += 1,
            }
        }
    }

    /// Every slot as the last completed sweep left it, named counters included.
    ///
    /// The caller takes the slice above [`CounterId::COUNT`](lorica_common::CounterId::COUNT):
    /// those belong one to an entry of the unified list. It is handed out whole rather than
    /// pre-sliced because the split is the caller's business and this type does not know how
    /// many named counters the map was sized for beyond the number it was told.
    pub fn full_totals(&self) -> &[u64] {
        self.full.last()
    }

    /// When [`Self::full_totals`] last completed. Zero means never.
    pub const fn full_at_ns(&self) -> u64 {
        self.full_at_ns
    }

    /// The bucket levels as the last completed pass left them. Empty when there is no bank.
    pub fn bank_levels(&self) -> &[u64] {
        self.bank.as_ref().map_or(&[], BankReader::last)
    }

    /// When [`Self::bank_levels`] last completed. Zero means never, which is also what an
    /// agent with no bank reports for as long as it runs.
    pub const fn bank_at_ns(&self) -> u64 {
        self.bank_at_ns
    }

    /// Passes over the bank, for the startup line and the digest.
    pub const fn bank_sweeps(&self) -> u64 {
        self.bank_sweeps
    }

    /// Slots read per second at this cadence, which is the number the cost is linear in
    /// and therefore the only one worth comparing between configurations.
    ///
    /// The stride divides it for the same reason `every` does — a pass over the map now
    /// takes `every × stride` ticks — and the two are not the same knob: `every` leaves the
    /// worst tick where it was and skips whole ticks, the stride cuts the worst tick and
    /// skips nothing.
    pub fn slot_reads_per_second(&self, hz: u32) -> u64 {
        let hz = u64::from(hz);
        let stride = u64::from(self.full.stride());
        self.named_slots as u64 * hz + (self.slots as u64 * hz) / (self.every * stride)
    }

    /// Reads it takes the full sweep to cover the map once, which is what the freshness of
    /// a per-entry counter costs at this configuration.
    pub fn stride(&self) -> u32 {
        self.full.stride()
    }

    /// Whether the sweep is reading the counter array as memory rather than through
    /// `BPF_MAP_LOOKUP_BATCH`. Measured on the target, it is a factor of 52 at 50 000 slots and
    /// 78 at 4 096, so it is on the startup line: an agent whose CPU figure surprises somebody
    /// starts here.
    pub const fn is_mapped(&self) -> bool {
        self.full.is_mapped()
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

    /// One running total per named counter, indexed by `CounterId::index()`.
    pub const fn named_totals(&self) -> &[u64; NAMED_SLOTS] {
        &self.named_totals
    }
}
