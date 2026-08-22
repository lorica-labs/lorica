//! Stage 6. Arrives with the deterministic defenses, behind a backend abstraction:
//! a branch cascade on the current floor, a jump table when the kernel that allows
//! one is in the field.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView) -> Outcome {
    Outcome::Continue
}
