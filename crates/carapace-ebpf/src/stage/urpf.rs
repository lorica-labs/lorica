//! Stage 5, conditional on the role. Arrives with the deterministic defenses: it
//! needs the return codes of `bpf_fib_lookup` distinguished and its cost measured.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView) -> Outcome {
    Outcome::Continue
}
