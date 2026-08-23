//! Stage 7. Arrives with the deterministic defenses. Writing the bucket arithmetic
//! before the contention measurement decides the layout of the bank would mean
//! writing it twice.
//!
//! `now` is in jiffies, so two packets inside the same jiffy see zero elapsed time: a
//! leaky bucket accumulates without leaking and then leaks a whole jiffy's worth at the
//! boundary. Correct behaviour, marginally more tolerant of micro-bursts, and it needs
//! no workaround.

use lorica_common::PacketView;

use crate::stage::{Budget, Outcome};

#[inline(never)]
pub fn run(_view: &PacketView, _now: u64, _budget: Budget) -> Outcome {
    Outcome::Continue
}
