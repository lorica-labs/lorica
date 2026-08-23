//! The generated table into entries of the unified list.
//!
//! On a leaf host uRPF has nothing to check a source against: there is one default
//! route and every address in the world is reachable through it. What does work at that
//! position is the static list of prefixes that can never legitimately have sent the
//! packet, and it costs nothing to enforce, because these are entries of the list that
//! already exists. A stage of their own would buy a branch on every packet to answer a
//! question the trie answers on the way past.

use lorica_common::{Action, CounterId, Deadline, LpmKey, LpmValue};

use crate::compile::bogon_table::BOGONS;

/// A drop on everything from the prefix, all of them pointing at the one counter: the
/// operator wants to know that a bogon was refused, not which of twenty-eight reserved
/// prefixes it was. No deadline either — a reserved prefix does not stop being reserved.
pub fn entries() -> impl Iterator<Item = (LpmKey, LpmValue)> {
    BOGONS.iter().map(|key| {
        let mut value = LpmValue::zeroed();
        value.action = Action::Drop;
        value.counter_idx = CounterId::BogonRefused.index();
        value.deadline = Deadline::never();
        (*key, value)
    })
}
