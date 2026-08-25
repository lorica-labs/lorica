//! The one snapshot the rest of the agent reads, republished whole once per tick.
//!
//! **Why an atomic pointer swap and not a lock.** The tick writes, and every scrape and
//! every control query reads. A reader takes its own `Arc` and the tick never waits for
//! one, so a scraper that stops reading half way through a response cannot hold the timer
//! behind it — which on a current-thread runtime is the actual failure mode, not a
//! theoretical one.
//!
//! **[`ArcSwap::load_full`], never `load`.** `load` returns a `Guard` that occupies one of
//! arc-swap's per-thread debt slots. A handler that holds one across an `.await` keeps the
//! slot for as long as its client takes, and the publication in the tick then has to pay
//! the slow path to reclaim it. `load_full` is one atomic increment and owes nothing, which
//! is the only property that survives a handler being made async later.
//!
//! **What was rejected, and why the reasons are structural rather than numeric.**
//! *left-right* needs no lock on the read path, but the readers still share the `Arc`
//! control block the writer is touching: it removes the lock and keeps the cache line, so
//! it buys nothing over this and costs two copies of every snapshot. *dashmap* is not slow
//! here, it is wrong: a `Ref` held across an `.await` deadlocks its shard, and holding a
//! read across an await is exactly the shape of both handlers in `main`. *thread_local*
//! would be free and there is nothing for it to do — the runtime is built
//! `new_current_thread`, so there is one thread and nothing to shard. [`CachePadded`] is
//! the one piece kept from that family; the runtime is single-threaded today, so it is
//! insurance against the first reader that is not on the tick's thread and not a measured
//! win.
//!
//! **The allocation this file exists not to make.** Republishing an `Arc<Snapshot>` every
//! tick allocates one control block every tick, by construction — the honest number is one,
//! not zero, and the two ways out are a pool of preallocated buffers or an allocation per
//! tick declared and excluded from the budget. This is the pool, and it is two buffers
//! because two is what the invariant needs: the published one, and the one being written.
//! [`Arc::get_mut`] hands out `&mut` exactly when nobody else holds the buffer, so the
//! reuse is not an assumption about the readers — it is checked, every tick, and the tick
//! that finds a reader still holding its spare allocates a fresh buffer and counts it. A
//! pool that overwrote what a reader was reading would be a data race with a comment on it.
//! Measured in `tests/tick_budget.rs`: a thousand ticks over a 4096-slot map allocate zero
//! times and reuse the spare a thousand times out of a thousand.

use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam_utils::CachePadded;
use lorica_detect::{BucketView, CounterView, Snapshot, snapshot::NAMED_SLOTS};

use crate::tick::Sweep;

pub struct Published {
    current: CachePadded<ArcSwap<Snapshot>>,
    /// The buffer that is not published: written in place, then swapped in.
    spare: Arc<Snapshot>,
    reallocations: u64,
}

impl Default for Published {
    fn default() -> Self {
        Self {
            current: CachePadded::new(ArcSwap::from_pointee(empty())),
            spare: Arc::new(empty()),
            reallocations: 0,
        }
    }
}

impl Published {
    /// Writes this tick into the spare buffer and publishes it.
    pub fn publish(&mut self, sweep: &Sweep, at_ns: u64) {
        match Arc::get_mut(&mut self.spare) {
            Some(buffer) => write(buffer, sweep, at_ns),
            None => {
                self.reallocations += 1;
                let mut fresh = empty();
                write(&mut fresh, sweep, at_ns);
                self.spare = Arc::new(fresh);
            }
        }
        // The buffer that was published becomes the spare, so the two alternate and the
        // one being written is never the one being read.
        let previous = self.current.swap(Arc::clone(&self.spare));
        self.spare = previous;
    }

    /// The last published snapshot.
    pub fn read(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Ticks that had to allocate a buffer because a reader still held the spare.
    ///
    /// Published rather than asserted away: it is zero in a steady agent, and a number that
    /// climbs says a reader is outliving the tick that gave it its snapshot, which is a
    /// fact about the handlers and not about this file.
    pub const fn reallocations(&self) -> u64 {
        self.reallocations
    }
}

fn write(into: &mut Snapshot, sweep: &Sweep, at_ns: u64) {
    // Monotone, and the jump rather than the value is the signal: a tick the agent did not
    // get to run leaves a gap here, which shows saturation earlier than any CPU counter
    // because it is the agent's own missed work rather than a share of a core.
    into.seq = sweep.ticks();
    into.at_ns = at_ns;
    into.counters
        .named_mut()
        .copy_from_slice(sweep.named_totals());
    into.counters.set_failures(sweep.failures());
}

/// A snapshot with the named totals sized and both vectors empty.
///
/// Empty, and not to save the allocation: nothing in the tick reads the bucket bank or the
/// unified list yet, so there is no length to size these for. When either read lands, the
/// reuse path above keeps whatever capacity the vectors grew to and the fresh-buffer path
/// is the one that has to ask for it.
fn empty() -> Snapshot {
    Snapshot {
        seq: 0,
        at_ns: 0,
        counters: CounterView::new([0; NAMED_SLOTS], Vec::new()),
        buckets: BucketView::new(Vec::new()),
    }
}
