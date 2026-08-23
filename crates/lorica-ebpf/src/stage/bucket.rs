//! Stage 7. One leaky bucket per hashed source, in a shared lock-free bank.
//!
//! `now` is in jiffies, so two packets inside the same jiffy see zero elapsed time: a
//! leaky bucket accumulates without leaking and then leaks a whole jiffy's worth at the
//! boundary. Correct behaviour, marginally more tolerant of micro-bursts, and it needs
//! no workaround.
//!
//! **What it costs, measured, because it is not the figure the layout study assumed.** 100
//! to 112 ns on the 901 against a whole-pipeline baseline of 81 ns, so this stage cost more
//! than everything before it put together. Attributed by measuring the same path with the
//! index replaced by one byte of the address: 61 to 73 ns was the keyed SipHash-2-4 and
//! 39 ns the lookup and the charge. A third of the program for one hash is not a trade this
//! phase can make, so the index is keyed multiply-shift instead: 2-universal, which is the
//! only property the threat model asks for, and two multiplies and an add against ten
//! siprounds of a rotate this ISA does not have. What that bought deterministically, on
//! 7.0.0-30: 8668 JITed bytes down to 7378 — which is the checked-in ceiling exactly, so the
//! headroom is zero and not comfortable. `hash/multiply_shift.rs` states what was given up.
//!
//! The 39 ns is dominated by one 64-bit division: the drain divides by 10^9 / 512, LLVM
//! cannot strength-reduce it because the reciprocal multiply would need a high multiply BPF
//! does not have, and a `div` is tens of cycles. Worth revisiting. Not revisited here.
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
    // addresses that share one bucket once and reuses it everywhere. Two-universal and
    // nothing more, which is what that threat needs and all this path can afford.
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
