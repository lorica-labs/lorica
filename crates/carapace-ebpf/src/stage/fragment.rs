//! Stage 4. A later fragment has no L4 header, so no destination port, so it can
//! never match a scope. Hence a stage of its own rather than a silent death in
//! sanity.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView) -> Outcome {
    Outcome::Continue
}
