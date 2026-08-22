//! Stage 2. Above the tiers on purpose: an ICMPv4 type 3 code 4 or an ICMPv6 Packet
//! Too Big has to get through whatever the configuration says, or the path MTU
//! blackholes and nobody connects the symptom to the MTU.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView) -> Outcome {
    Outcome::Continue
}
