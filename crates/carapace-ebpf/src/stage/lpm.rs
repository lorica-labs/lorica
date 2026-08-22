//! Stage 3. One list, one lookup: allow list and block list are the same trie, and
//! the value carries the verdict.

use carapace_common::PacketView;

use crate::stage::Outcome;

#[inline(never)]
pub fn run(_view: &PacketView, _now_ns: u64) -> Outcome {
    Outcome::Continue
}
