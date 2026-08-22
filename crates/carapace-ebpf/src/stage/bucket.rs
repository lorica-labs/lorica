//! Stage 7. Arrives with the deterministic defenses. Writing the bucket arithmetic
//! before the contention measurement decides the layout of the bank would mean
//! writing it twice.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView, _now_ns: u64) -> Outcome {
    Outcome::Continue
}
