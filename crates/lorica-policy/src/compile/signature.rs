//! The signature catalogue as the operator side sees it: one row per vector, the
//! counter it bumps and the verdict arming stage 6 gives it.
//!
//! This is the same table the data path holds, written twice, and that is not a
//! duplication anyone can remove by refactoring. `lorica-ebpf` is a `no_std` crate
//! for another target in a workspace of its own, so nothing here can link against it,
//! and the only vocabulary the two sides share is what `lorica-common` freezes:
//! `CounterId` and `Action`. What keeps them honest is that the counters themselves are
//! the join, and `tests/signature_compile.rs` asserts this table covers every
//! `Signature*` counter that exists, exactly once, in the order they are declared in.
//! A vector added to one side without a verdict on the other fails that test rather
//! than shipping with no policy.
//!
//! The verdict is per vector because the catalogue holds two kinds of claim. A vector
//! that is a fact about the packet is dropped; a vector recognised by a service port
//! and a size threshold is a judgement about a packet that could be legitimate, so it
//! is rate-limited and the buckets decide how much of it gets through.

use lorica_common::{Action, CounterId};

/// One vector of the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vector {
    pub counter: CounterId,
    /// Only ever `Drop` or `RateLimit`. A row that let the packet through would be a
    /// vector that does not belong in the catalogue.
    pub action: Action,
}

const fn vector(counter: CounterId, action: Action) -> Vector {
    Vector { counter, action }
}

pub const CATALOG: [Vector; 10] = [
    vector(CounterId::SignatureAmpDns, Action::RateLimit),
    vector(CounterId::SignatureAmpNtp, Action::RateLimit),
    vector(CounterId::SignatureAmpSsdp, Action::RateLimit),
    vector(CounterId::SignatureAmpMemcached, Action::RateLimit),
    vector(CounterId::SignatureAmpA2s, Action::RateLimit),
    vector(CounterId::SignatureAmpRaknet, Action::RateLimit),
    vector(CounterId::SignatureLoopyPortPair, Action::Drop),
    vector(CounterId::SignatureFragAbuse, Action::Drop),
    vector(CounterId::SignatureImpossibleTcpFlags, Action::Drop),
    vector(CounterId::SignatureLengthMismatch, Action::Drop),
];

/// What an armed stage does when this counter moves. `None` for a counter that is not a
/// vector at all, so a caller cannot get an answer for a question it did not ask.
pub fn verdict(counter: CounterId) -> Option<Action> {
    CATALOG
        .iter()
        .find(|vector| vector.counter == counter)
        .map(|vector| vector.action)
}
