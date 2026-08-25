//! Stage 6. The vector catalogue, matched by a backend chosen at compile time.
//!
//! Signatures and bogons are the only defenses in the pipeline allowed to drop without
//! the buckets having a say, and that licence is the reason this stage says nothing by
//! default. With `ENFORCE_SIGNATURES` clear a match bumps its counter and the packet
//! continues: observation is the mode the whole product ships in, and a catalogue
//! nobody has yet watched run against their own traffic is a list of false positives
//! waiting to be discovered by an outage.
//!
//! Armed, the verdict comes from the catalogue and not from this file, because the ten
//! vectors are not ten claims of the same strength. What each one answers, and why, is
//! in `catalog.rs`.

pub mod backend;
pub mod catalog;

use lorica_common::PacketView;

use crate::{
    helpers, settings,
    stage::{
        Outcome,
        signature::backend::{Selected, SignatureBackend},
    },
};

#[inline(never)]
pub fn run(view: &PacketView) -> Outcome {
    let Some(vector) = Selected::classify(view) else {
        return Outcome::Continue;
    };

    // Before the policy and not after it: the counter is what an operator reads to
    // decide whether arming the stage is safe, so it has to move in the mode where
    // nothing is armed. That is the only way the decision is informed.
    helpers::bump(vector.counter());

    if settings::enforce_signatures() {
        vector.policy()
    } else {
        Outcome::Continue
    }
}
