//! The ten vectors, each with the counter it bumps and the verdict arming the stage
//! gives it.
//!
//! One counter per vector because the question an operator asks after a drop is which
//! signature fired, not that one did. One verdict per vector because the catalogue
//! holds two different kinds of claim and they do not deserve the same answer.
//!
//! A vector that is a *fact* about the packet — a fragment whose length cannot exist,
//! a flag combination no stack emits, two headers that disagree — is dropped, because
//! there is nothing left to be wrong about. A vector recognised by what a reflector
//! answers is a *judgement*: the packet could be the reply to a query something behind
//! this pipeline really sent, so it answers `RateLimit` and the buckets decide how much
//! of it gets through. That is the whole reason stage 6 has three answers instead of two.
//!
//! Matching a MAGIC tightens a judgement without turning it into a fact, which is why
//! the two game vectors that now read the payload still answer `RateLimit`. An A2S
//! answer is an A2S answer whether or not anybody asked for it, and only the operator's
//! own outbound traffic knows which — and that is not something one datagram carries.

use lorica_common::CounterId;

use crate::stage::Outcome;

/// An explicit width because the discriminant is a catalogue ordinal, and the same
/// ordering is written a second time in the policy compiler for the operator-facing
/// side: a tag whose width followed the platform would make the two disagree.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VectorId {
    AmpDns,
    AmpNtp,
    AmpSsdp,
    AmpMemcached,
    AmpA2s,
    AmpRaknet,
    LoopyPortPair,
    FragAbuse,
    ImpossibleTcpFlags,
    LengthMismatch,
}

impl VectorId {
    pub const fn counter(self) -> CounterId {
        match self {
            Self::AmpDns => CounterId::SignatureAmpDns,
            Self::AmpNtp => CounterId::SignatureAmpNtp,
            Self::AmpSsdp => CounterId::SignatureAmpSsdp,
            Self::AmpMemcached => CounterId::SignatureAmpMemcached,
            Self::AmpA2s => CounterId::SignatureAmpA2s,
            Self::AmpRaknet => CounterId::SignatureAmpRaknet,
            Self::LoopyPortPair => CounterId::SignatureLoopyPortPair,
            Self::FragAbuse => CounterId::SignatureFragAbuse,
            Self::ImpossibleTcpFlags => CounterId::SignatureImpossibleTcpFlags,
            Self::LengthMismatch => CounterId::SignatureLengthMismatch,
        }
    }

    /// Only ever `Drop` or `RateLimit`, and never `Continue`: a row whose verdict was
    /// to let the packet through would be a vector that does not belong in the
    /// catalogue at all, and the counter alone already says what observation mode has
    /// to say.
    pub const fn policy(self) -> Outcome {
        match self {
            Self::AmpDns
            | Self::AmpNtp
            | Self::AmpSsdp
            | Self::AmpMemcached
            | Self::AmpA2s
            | Self::AmpRaknet => Outcome::RateLimit,
            Self::LoopyPortPair
            | Self::FragAbuse
            | Self::ImpossibleTcpFlags
            | Self::LengthMismatch => Outcome::Drop,
        }
    }
}
