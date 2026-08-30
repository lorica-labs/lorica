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
use lorica_detect::{
    BucketView, CounterView, Snapshot,
    snapshot::{EntryCounter, NAMED_SLOTS},
};

use crate::{roster::Roster, tick::Sweep};

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
    pub fn publish(&mut self, sweep: &Sweep, at_ns: u64, roster: &Roster) {
        match Arc::get_mut(&mut self.spare) {
            Some(buffer) => write(buffer, sweep, at_ns, roster),
            None => {
                self.reallocations += 1;
                let mut fresh = empty();
                write(&mut fresh, sweep, at_ns, roster);
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

fn write(into: &mut Snapshot, sweep: &Sweep, at_ns: u64, roster: &Roster) {
    // Monotone, and the jump rather than the value is the signal: a tick the agent did not
    // get to run leaves a gap here, which shows saturation earlier than any CPU counter
    // because it is the agent's own missed work rather than a share of a core.
    into.seq = sweep.ticks();
    into.at_ns = at_ns;
    into.counters
        .named_mut()
        .copy_from_slice(sweep.named_totals());
    into.counters.set_failures(sweep.failures());

    // **The per-entry slice, and the stamp that says whether to believe a delta across it.**
    // `clear` then `extend` rather than a fresh `Vec`: the buffer keeps its capacity across
    // ticks, which is what `tests/tick_budget.rs` asserts by counting allocations.
    //
    // The stamp comes from the sweep and not from this tick. A tick that did not sweep, and a
    // sweep that failed, both leave it where it was, and the detector reads an unmoved stamp as
    // "not looked at" rather than as "unchanged". That distinction is the difference between an
    // attack that stopped and an agent that stopped watching, and only one of the two should
    // withdraw a mitigation.
    let totals = sweep.full_totals();
    let entries = into.counters.entries_mut();
    entries.clear();
    // `reserve` before the loop and not `extend` over a `filter_map`: a filtered iterator
    // reports a lower bound of zero, so `extend` grows the buffer by doubling and a first fill
    // of four thousand seats costs a dozen allocations instead of one. On every tick after the
    // first this reserves nothing, because the capacity is already there -- which is the whole
    // point of reusing the buffer.
    entries.reserve(roster.len());
    for seat in roster.seats() {
        // A seat whose slot is past the end of the sweep is a roster built against a larger
        // counter map than the one the agent opened. Skipped rather than zero-filled: a zero
        // would read as an entry taking no traffic, which is a claim about the traffic.
        if let Some(hits) = totals.get(seat.slot as usize) {
            entries.push(EntryCounter {
                key: seat.key,
                hits: *hits,
            });
        }
    }
    into.counters.set_entries_at_ns(sweep.full_at_ns());

    // The bank, on its own cadence and with its own stamp, for the same reasons.
    let levels = into.buckets.levels_mut();
    levels.clear();
    levels.extend_from_slice(sweep.bank_levels());
    into.buckets.set_at_ns(sweep.bank_at_ns());
}

/// A snapshot with the named totals sized and both vectors empty.
///
/// **Empty, and it no longer means what it used to.** It once said that nothing in the tick
/// read the bucket bank or the unified list, which was true and was why the whole detection
/// ladder ran on nothing. Both are read now; these start empty because their lengths are
/// properties of the compiled policy and the bank the agent found, neither of which this
/// function knows. `write` fills them on the first tick and the reuse path above keeps
/// whatever capacity they grew to, so the allocation happens once and not once a tick.
fn empty() -> Snapshot {
    Snapshot {
        seq: 0,
        at_ns: 0,
        counters: CounterView::new([0; NAMED_SLOTS], Vec::new()),
        buckets: BucketView::new(Vec::new()),
    }
}
