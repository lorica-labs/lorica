//! The attack journal: fixed-size records, rotated files, and no query engine.
//!
//! **The format is the interface, not the engine.** What an operator needs from a journal is
//! to answer questions about an attack after it is over, and the way to give them that is a
//! file a real query engine can open — not a query engine inside the agent.
//!
//! **DuckDB embedded was measured and refused.** 36.8 MB of binary after fat LTO and strip,
//! 69 dependencies, 25.8 MB of RSS and 24 threads to insert one row. None of that is a
//! quality complaint: DuckDB is excellent and the numbers are what an analytical engine
//! costs. It is a size problem. The agent's whole budget is a few megabytes of RSS on a host
//! whose CPU belongs to the application it protects, and 24 threads on a `current_thread`
//! runtime is not a tuning knob, it is a different program. Polars is refused on the same
//! grounds and the same measurement. What is here instead is [`record`], a 48-byte
//! `#[repr(C)]` struct, and [`rotate`], one `write_all` per buffer — and `lorica-export`
//! turns the result into Parquet on demand, in a process whose peak nobody watches, which is
//! where DuckDB is then welcome to read it.
//!
//! **The roll-up is a second and not a tick, and that is a decision about volume.** A 10 Hz
//! agent writing per tick is 864 000 records a day; per second it is 86 400, and the ticks it
//! drops are ticks in which nothing changed. [`Rollup`] keeps the *worst* rung of each second
//! rather than the last, so what is lost is duration inside a second and never an event —
//! see [`record::Record::worse`].
//!
//! **If direct Parquet writing from the agent ever became a requirement, the granularity is
//! one row group per second, not one per tick.** This is written down rather than built,
//! because the measurement says the tick-granular version is the wrong shape twice over:
//! batches of 20 000 rows put the p99 of the writing call at 3.2 ms — a third of a 10 Hz
//! period, on the thread that owns the timer — and produce a file twice the size, because a
//! row group carries its own statistics and dictionary per column and a per-tick row group
//! pays that overhead ten times a second for ten rows. A row group per second amortises the
//! footer over a second's worth of rows and matches the granularity the records already have.
//!
//! Nothing in the agent writes to this yet: wiring it into the tick is another task's, and
//! `main.rs` carries one line for this module and no call. Hence the crate-level allowance
//! below — a module that is complete and not yet called is dead code by the compiler's
//! definition, and the alternative is a caller written to satisfy a warning.

#![allow(dead_code)]

pub mod record;
pub mod rotate;

use lorica_detect::Decision;

use record::Record;

/// One second's worth of decisions, collapsed to the record that describes it.
///
/// Deliberately not joined to [`rotate::Writer`] behind a single `observe`. The two costs
/// are different in kind — this one is arithmetic on the timer thread, that one is a
/// `write_all` — and a wrapper over both would make the CPU figure in `tests/journal.rs`
/// a figure about the disk. The caller's version of the join is two lines.
#[derive(Default)]
pub struct Rollup(Option<Record>);

impl Rollup {
    /// Folds one decision in, and answers with the record of the second that just closed.
    ///
    /// `Some` exactly on the tick whose second differs from the previous one's, so a caller
    /// appending whatever comes back writes one record per second with no timer of its own.
    pub fn observe(&mut self, at_ns: u64, decision: &Decision) -> Option<Record> {
        let record = Record::of(at_ns, decision);
        match &mut self.0 {
            Some(open) if open.at_ns == record.at_ns => {
                *open = open.worse(record);
                None
            }
            // Includes the first call, where the slot is empty and there is no closed second
            // to report. `replace` returning `None` is that case and needs no branch.
            slot => slot.replace(record),
        }
    }

    /// The second still being accumulated, taken out. What a shutdown owes the journal.
    pub fn close(&mut self) -> Option<Record> {
        self.0.take()
    }
}
