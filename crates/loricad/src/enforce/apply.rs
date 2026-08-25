//! Writing the entry, with its deadline.
//!
//! **Why the checks come before the mode and not after.** The shorter version answers
//! `Withheld` first and validates only on the way to a write, which costs 1 branch less
//! and hides the one thing an operator runs `observe` to find out: whether the decisions
//! this agent is about to be armed on are applicable at all. Here a decision that could
//! not be written is refused in both modes, so arming changes exactly one thing — whether
//! the map moves — and nothing about what is judged.
//!
//! **What is not in the value.** No priority: ties between an operator's entry and a
//! mitigation entry on the same prefix are refused at compile time rather than settled
//! here. No scope either, so the refusal covers the whole prefix — a scoped refusal would
//! let the flood pick another port.

use std::{io, os::fd::BorrowedFd};

use lorica_common::{Action, CounterId, LpmKey, LpmValue};
use lorica_dataplane::maps::lpm;
use lorica_detect::Decision;
use lorica_policy::Mode;

/// What became of a decision.
///
/// `Withheld` is the countable event of the observing mode: the rung was reached, the key
/// was named, and the list was not touched. A caller that only counted writes would
/// report an agent under attack as an agent with nothing to say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Applied {
    /// The rung refuses nothing, so there is nothing for the list to carry.
    Nothing,
    /// `observe`: this is the key that would have been refused.
    Withheld(LpmKey),
    Written(LpmKey),
}

/// Applies `decision` to the unified list, counting its hits in `slot`.
///
/// `slot` is the caller's, because allocating a counter slot is the business of whoever
/// owns the list and not of one decision. It has to sit above the named counters:
/// entries pointed at a named counter would make the drops they cause look like evidence
/// to the engine that ordered them.
pub fn apply(
    list: BorrowedFd<'_>,
    mode: Mode,
    decision: &Decision,
    slot: u32,
) -> io::Result<Applied> {
    if !decision.tier().drops() {
        return Ok(Applied::Nothing);
    }

    // Read rather than unwrapped. `Decision::new` cannot build this combination, but the
    // fields of a decision are public, so one already built can be raised to a refusing
    // rung afterwards — and the whole invariant is that a refusal names its key.
    let key = decision.reason().exact_key().ok_or_else(|| {
        io::Error::other(format!(
            "rung {} refuses packets and its reason names no exact key: {:?}",
            decision.tier().rung(),
            decision.reason()
        ))
    })?;

    if decision.deadline().is_never() {
        return Err(io::Error::other(format!(
            "rung {} on {key:?} carries no deadline; an entry the detection writes has to \
             expire on its own, because the agent that would remove it is the thing that \
             can die",
            decision.tier().rung()
        )));
    }

    if slot < CounterId::COUNT {
        return Err(io::Error::other(format!(
            "counter slot {slot} is one of the {} named counters; a mitigation entry \
             counted there would feed the ladder its own drops as evidence",
            CounterId::COUNT
        )));
    }

    if mode == Mode::Observe {
        return Ok(Applied::Withheld(key));
    }

    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.deadline = decision.deadline();
    value.counter_idx = slot;
    lpm::load(list, &[(key, value)], 1)?;
    Ok(Applied::Written(key))
}
