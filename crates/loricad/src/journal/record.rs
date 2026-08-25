//! One journal record: forty-eight bytes, always forty-eight bytes.
//!
//! **Fixed size is what buys the reader, and the alternative is a length prefix.** A
//! self-describing record — varint length, then fields — is the obvious shape and it costs
//! the reader a decode per record and the writer a branch. A fixed stride costs neither:
//! record `n` is at `HEADER_BYTES + n * RECORD_BYTES`, a file's record count is its length
//! minus the header divided by the stride, and a truncated tail is arithmetic rather than a
//! parse that runs off the end. That is why [`Header`] carries [`RECORD_BYTES`] and not a
//! record count: the count would have to be rewritten when a file closes, and a file whose
//! writer died would then claim fewer records than it holds.
//!
//! **The padding is a named field, for the same reason the blocklist's is**: `IntoBytes`
//! refuses a type with implicit padding, and appending a record means turning it straight
//! into bytes. Naming it also makes it part of the round trip the tests assert — a padding
//! byte the writer leaves uninitialised is a byte that differs between two runs of the same
//! agent, which turns a journal diff into noise.
//!
//! Native byte order, and no endianness field, on the same reasoning as
//! `store/blocklist/binary.rs`: the file is written and read on one machine, and [`MAGIC`]
//! is what a file carried elsewhere trips over instead of being read as plausible garbage.

use core::mem::{align_of, size_of};

use lorica_detect::{Decision, Reason};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// First eight bytes of every journal file. Trailing digit is the format generation.
pub const MAGIC: [u8; 8] = *b"LORICAJ1";

pub const VERSION: u32 = 1;

/// What [`Record::at_ns`] is floored to.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// [`Record::prefix_len`] when the decision rests on no exact key.
///
/// A sentinel and not a zero: `::/0` is a prefix length of zero and a legitimate key, so a
/// zero would make "no key" and "the whole address space" the same record. 255 is chosen
/// because the longest real prefix is 128.
pub const NO_KEY: u8 = 0xff;

/// [`Record::reason`] codes, in the declaration order of [`Reason`].
///
/// Written out rather than taken from a `#[repr(u8)]` on `Reason` itself: that enum carries
/// data, its discriminants are the detector's business, and a journal that inherited them
/// would silently renumber every historical file the day a variant is inserted.
pub const REASON_QUIET: u8 = 0;
pub const REASON_PRESSURE: u8 = 1;
pub const REASON_CONFIRMED: u8 = 2;
pub const REASON_SATURATION: u8 = 3;

/// Sixteen bytes, a multiple of the eight [`Record`] needs, so records begin aligned at a
/// fixed offset.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Header {
    pub magic: [u8; 8],
    pub version: u32,
    /// The stride the rest of the file is written at. A reader divides by this instead of
    /// trusting its own `size_of`, so a file written by a build with a different record
    /// layout is refused rather than read at the wrong offsets.
    pub record_bytes: u32,
}

impl Header {
    pub const fn new() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            record_bytes: RECORD_BYTES as u32,
        }
    }
}

/// One second of the ladder's verdict.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Record {
    /// Start of the second this record summarises, in the agent's monotonic nanoseconds.
    /// Floored by [`Record::of`], which is what makes two records of the same second
    /// mergeable by comparing this field.
    pub at_ns: u64,
    /// The rate the reason rests on. **The unit is given by [`Record::reason`]** — packets
    /// per second under `REASON_PRESSURE` and `REASON_CONFIRMED`, excess bits per second
    /// under `REASON_SATURATION`, zero under `REASON_QUIET`. One column instead of three
    /// because a journal is read by filtering on the reason first; three columns would be
    /// two nulls per row on every row.
    pub rate: u64,
    /// The rung's expiry, in the kernel jiffies the data path's map entries carry.
    /// `u64::MAX` is `Deadline::never()` and is what rung zero writes.
    pub deadline: u64,
    /// The exact key the rung rests on, in the `LpmKey` form — v4-mapped for IPv4. All
    /// zeroes when [`Record::prefix_len`] is [`NO_KEY`].
    pub addr: [u8; 16],
    /// 0 to 128, or [`NO_KEY`].
    pub prefix_len: u8,
    /// A `Tier` rung, from `Tier::rung`.
    pub tier: u8,
    /// One of the `REASON_*` codes.
    pub reason: u8,
    pub pad: [u8; 5],
}

impl Record {
    /// The record a decision produces, stamped with the second `at_ns` falls in.
    ///
    /// Flooring here rather than in the roll-up is what keeps the merge rule honest: the
    /// roll-up decides which of two records of one second survives, and it can only do that
    /// if "same second" is a field comparison and not a division it might do differently.
    pub fn of(at_ns: u64, decision: &Decision) -> Self {
        let (reason, rate) = match decision.reason() {
            Reason::Quiet => (REASON_QUIET, 0),
            Reason::Pressure { per_sec, .. } => (REASON_PRESSURE, *per_sec),
            Reason::Confirmed { per_sec, .. } => (REASON_CONFIRMED, *per_sec),
            Reason::Saturation { excess_bps, .. } => (REASON_SATURATION, *excess_bps),
        };
        let (addr, prefix_len) = match decision.reason().exact_key() {
            // 128 fits a u8; the cast cannot lose a real prefix length.
            Some(key) => (key.addr, key.prefix_len as u8),
            None => ([0; 16], NO_KEY),
        };
        Self {
            at_ns: at_ns - at_ns % NANOS_PER_SEC,
            rate,
            deadline: decision.deadline().0,
            addr,
            prefix_len,
            tier: decision.tier().rung(),
            reason,
            pad: [0; 5],
        }
    }

    /// The one of two records of the same second that a journal should keep.
    ///
    /// Highest rung wins, and the rate breaks a tie. **The worst of the second and not the
    /// last of it**: an operator reading a journal after an attack is asking what the agent
    /// did at its most aggressive, and a last-writer-wins roll-up would drop a one-tick
    /// `DropBroad` between two `Observe` ticks — which is precisely the event worth keeping.
    ///
    /// `at_ns` is `self`'s. The caller has already established the two share a second, so
    /// the fields are interchangeable; taking `self`'s says the record is the second's and
    /// not any particular tick's.
    pub fn worse(self, other: Self) -> Self {
        if (other.tier, other.rate) > (self.tier, self.rate) {
            Self {
                at_ns: self.at_ns,
                ..other
            }
        } else {
            self
        }
    }
}

pub const HEADER_BYTES: usize = size_of::<Header>();
pub const RECORD_BYTES: usize = size_of::<Record>();

const _: () = assert!(HEADER_BYTES == 16);
const _: () = assert!(RECORD_BYTES == 48);
// The stride is only arithmetic if the header is a whole number of alignments, and the
// round trip is only bit for bit if there is no implicit padding to be uninitialised. Both
// halves are asserted so neither can drift when a field is added.
const _: () = assert!(HEADER_BYTES % align_of::<Record>() == 0);
const _: () = assert!(align_of::<Header>() >= align_of::<Record>());
