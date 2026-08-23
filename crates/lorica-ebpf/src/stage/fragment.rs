//! Stage 4. A later fragment has no transport header, so no destination port, so it
//! can never match a scope that names one. That is why it gets a stage of its own
//! rather than dying silently in sanity: the operator has a decision to make and it
//! has to be visible.
//!
//! The degraded key the specification asks for costs no code here, and that is worth
//! saying out loud. A later fragment reaches the list on its source with a port of
//! zero, so a scope written as `udp:any` still covers it while `udp:30120` does not.
//! Judging a later fragment on source and protocol alone is therefore what the list
//! already does, and what the operator gives up by allowing them is exactly the
//! ability to filter them by port.
//!
//! What this stage decides is only what happens to a later fragment the list said
//! nothing about, which is a policy and defaults to refusing it.

use lorica_common::{CounterId, FragState, PacketView};

use crate::{helpers, settings, stage::Outcome};

#[inline(never)]
pub fn run(view: &PacketView) -> Outcome {
    match view.frag() {
        FragState::None => Outcome::Continue,
        // It carries its transport header, so it took the normal path through every
        // stage before this one. Counted because the volume of fragmentation is worth
        // seeing, and because it is the denominator of the drops below.
        FragState::First => {
            helpers::bump(CounterId::FragmentFirstPassed);
            Outcome::Continue
        }
        FragState::Later => {
            if settings::allow_later_fragments() {
                helpers::bump(CounterId::FragmentLaterAllowed);
                Outcome::Continue
            } else {
                helpers::bump(CounterId::FragmentLaterDropped);
                Outcome::Drop
            }
        }
    }
}
