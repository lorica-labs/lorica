//! Stage 1. Before the list, because there is no reason to hand a malformed packet
//! to the stack just because its source is a friend.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView) -> Outcome {
    Outcome::Continue
}
