//! The rungs, and the one thing a rung that refuses packets is allowed to rest on.
//!
//! **The invariant, expressed as types rather than as a comment.** Buckets and signatures
//! produce candidates: 1024 buckets and any realistic source count means two sources share
//! one by the pigeonhole principle, so a bucket's level is a state a second source can
//! move. A refusal that rests on it refuses whoever else was hashed there. So every rung
//! for which [`Tier::drops`] holds needs a [`Reason`] carrying an exact [`LpmKey`], and
//! [`Decision::new`] answers `None` when it does not. Note what is *not* in
//! [`Confirmation`]: there is no variant naming a bucket, an index, or a level, which is
//! why "drop the bucket 412" has no spelling in this module.
//!
//! **The alternative that was rejected, with its cost.** The cheaper design is a single
//! `Decision { tier, reason }` with a free-form reason string and the invariant written in
//! the module header — zero types, and the check is a code review. It is not here because
//! that check has to pass on every future caller, and there will be several: the tier
//! ladder is driven from the tick, from the escalation crate, and from whatever replays it.
//! One `Option` at the constructor costs the callers an `unwrap_or_else` each and cannot be
//! forgotten.

use lorica_common::{CounterId, Deadline, LpmKey};

/// The rungs, in the order they are climbed. `#[repr(u8)]` and ordered because the ladder
/// is walked one rung at a time in both directions and the comparison is the walk.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    Observe,
    Mark,
    Limit,
    DropSurgical,
    DropBroad,
    Escalate,
    Rtbh,
}

impl Tier {
    pub const fn rung(self) -> u8 {
        self as u8
    }

    /// Whether this rung refuses packets, and therefore whether it needs an exact key.
    ///
    /// `Escalate` is absent: it asks an upstream to do something and refuses nothing here.
    /// `Rtbh` is present, because a blackhole route is a refusal — of the announced prefix,
    /// which is why that prefix has to be named in the reason like any other key.
    pub const fn drops(self) -> bool {
        matches!(self, Self::DropSurgical | Self::DropBroad | Self::Rtbh)
    }

    pub const fn up(self) -> Self {
        match self {
            Self::Observe => Self::Mark,
            Self::Mark => Self::Limit,
            Self::Limit => Self::DropSurgical,
            Self::DropSurgical => Self::DropBroad,
            Self::DropBroad => Self::Escalate,
            Self::Escalate | Self::Rtbh => Self::Rtbh,
        }
    }

    pub const fn down(self) -> Self {
        match self {
            Self::Observe | Self::Mark => Self::Observe,
            Self::Limit => Self::Mark,
            Self::DropSurgical => Self::Limit,
            Self::DropBroad => Self::DropSurgical,
            Self::Escalate => Self::DropBroad,
            Self::Rtbh => Self::Escalate,
        }
    }
}

/// What turned a candidate into a key that may be refused.
///
/// Two variants and not three. The third ground a refusal is allowed to rest on is a bit of
/// the policy word, and it is absent because the policy word is not in the
/// [`Snapshot`](crate::Snapshot): this engine cannot observe it, so it cannot claim it.
/// Adding the variant now would be a shape nothing can construct.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confirmation {
    /// The key is an entry of the unified list and its own counter slot is rising. Per-entry
    /// and therefore unshareable: no other source can increment this key's slot.
    ExactKey,
    /// Objectively invalid packets are being counted while this key is the one taking hits.
    /// The ground is the invalidity — a truncated header, an impossible flag combination, a
    /// reverse path out of the wrong interface — and the key only says whom to apply it to.
    InvalidPacket(CounterId),
}

/// Why a rung is in force.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    Quiet,
    /// The bank is loaded. A candidate signal by construction, which is why no rung that
    /// refuses packets can carry it: see [`Decision::new`].
    Pressure {
        counter: CounterId,
        per_sec: u64,
        loaded_share: u32,
    },
    Confirmed {
        key: LpmKey,
        by: Confirmation,
        per_sec: u64,
    },
    /// Arrivals exceed what the bank's provisioned drain can pass, which is the link's
    /// capacity when the bank is provisioned at it. `announce` is the prefix a blackhole
    /// would be asked for, and is the exact key the `Rtbh` rung rests on.
    Saturation {
        excess_bps: u64,
        link_bps: u64,
        announce: Option<LpmKey>,
    },
}

impl Reason {
    /// The exact key this reason rests on, if it rests on one.
    pub fn exact_key(&self) -> Option<LpmKey> {
        match self {
            Self::Confirmed { key, .. } => Some(*key),
            Self::Saturation { announce, .. } => *announce,
            Self::Quiet | Self::Pressure { .. } => None,
        }
    }
}

/// A rung in force, why, and until when.
///
/// `#[non_exhaustive]`: the fields are public to read and the struct cannot be built by
/// literal from outside this crate, so [`Decision::new`] is the only way in and its refusal
/// cannot be routed around.
///
/// `deadline` is the net under the whole ladder. It is the same mechanism the data path's
/// map entries use, for the same reason: if the agent dies, if a bug stops the descent, the
/// rule stops being applied without anyone noticing it needed to.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decision {
    tier: Tier,
    reason: Reason,
    deadline: Deadline,
}

impl Decision {
    /// Answers `None` when the rung refuses packets and the reason names no exact key.
    pub fn new(tier: Tier, reason: Reason, deadline: Deadline) -> Option<Self> {
        if tier.drops() && reason.exact_key().is_none() {
            return None;
        }
        Some(Self {
            tier,
            reason,
            deadline,
        })
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Rung zero. `Deadline::never()` because nothing is being applied, so there is nothing
    /// for an expiry to withdraw.
    pub fn quiet() -> Self {
        Self {
            tier: Tier::Observe,
            reason: Reason::Quiet,
            deadline: Deadline::never(),
        }
    }
}
