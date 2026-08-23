//! Stage 7. One leaky bucket per hashed source, in a shared lock-free bank.
//!
//! `now` is in jiffies, so two packets inside the same jiffy see zero elapsed time: a
//! leaky bucket accumulates without leaking and then leaks a whole jiffy's worth at the
//! boundary. Correct behaviour, marginally more tolerant of micro-bursts, and it needs
//! no workaround.
//!
//! Over budget and enforcing, the stage answers `Drop`, or `Mark` when the operator asked
//! for the excess to reach the stack tagged instead. `Mark` does not write the metadata it
//! is named after: the write is `bpf_xdp_adjust_meta`, which needs the `XdpContext` this
//! stage is deliberately not handed, and the capability that lets the stack read multi-byte
//! metadata answers no on the 6.8 floor of the project anyway, so the bit that reaches this
//! branch is clear there and `Drop` is the only path on the floor. What both paths share is
//! the counter: `BucketOverBudget` is bumped before the policy word is read, so the number
//! an operator's dashboard shows says the same thing about the same traffic on either
//! kernel, and the response tier reached is the same — the excess is never served normally.

use lorica_common::{BankLayout, Charge, CounterId, PacketView};

use crate::{
    helpers,
    maps::BANK_BUCKETS,
    settings,
    stage::{Budget, Outcome},
};

/// `shards` is 1 because the retained bank is shared rather than split per CPU: per-CPU
/// shards diluted the enforcement to exactly 1/N, which handed a flood spread across
/// source ports 4.00x the configured budget on four cores.
const LAYOUT: BankLayout = BankLayout {
    buckets: BANK_BUCKETS,
    shards: 1,
};

#[inline(never)]
pub fn run(view: &PacketView, now: u64, budget: Budget) -> Outcome {
    // The source address alone, and deliberately **not** `(source, port)`. What this stage
    // exists to refuse is a flood spread across source ports from one source; folding the
    // port into the index would give every port a bucket of its own and refuse none of it.
    // Keyed, because the index is chosen by whoever sends the packet: an unkeyed hash has
    // the same collisions on every host at every boot, so an attacker computes a set of
    // addresses that share one bucket once and reuses it everywhere.
    let index = LAYOUT.index(settings::bucket_hasher().hash(&view.src));

    let rate = match budget {
        Budget::Normal => settings::bucket_normal_rate(),
        Budget::Suspect => settings::bucket_suspect_rate(),
    };

    if helpers::bank_charge(index, rate, now, u32::from(view.packet_len)) == Charge::Within {
        return Outcome::Continue;
    }

    helpers::bump(CounterId::BucketOverBudget);

    // Default mode of the product is observation, so with the bit clear the excess is
    // counted and passed.
    if !settings::enforce_buckets() {
        return Outcome::Continue;
    }
    if settings::mark_over_budget() {
        helpers::bump(CounterId::BucketMarked);
        return Outcome::Mark;
    }
    Outcome::Drop
}
