//! The counter map's bytes as slots, checked once and never copied.
//!
//! **Why this reads the bytes and not [`CounterView`](crate::snapshot::CounterView).** The
//! snapshot's counter side pairs every entry count with the key it belongs to, which is the
//! shape a decision about *one* key needs — and the wrong shape for a reduction over all of
//! them. `size_of::<EntryCounter>()` is 32 bytes against the 8 the count itself occupies, so
//! a scan over the parsed form touches four times the bytes and reads them at a stride no
//! vector load can use. This view interprets the same batch read as a contiguous `[u64]`,
//! which is the layout the kernel wrote in the first place: the parsing is what would have
//! been added, not what is being skipped.
//!
//! **The alternative that was rejected, with its cost.** `slice::from_raw_parts` on the
//! buffer's pointer is two lines and no dependency, and it is undefined behaviour the first
//! time a batch read hands back a buffer that is not eight-byte aligned — which is not
//! hypothetical, since the length and the alignment both come from a syscall that writes
//! into memory this crate did not size. `zerocopy` 0.8 turns that into a `Result` for
//! **zero transitive dependencies** with `default-features = false`: no `derive`, so no
//! proc-macro in the build graph. The whole of what is used here is one checked cast, and
//! what it buys is that the failure mode is an error value instead of a miscompilation.

use zerocopy::FromBytes;

use crate::snapshot::NAMED_SLOTS;

/// Why a batch read could not be interpreted as counter slots.
///
/// Three variants and not one, because the three say different things about what went
/// wrong upstream: a short buffer is a truncated read, a ragged one is a value size that no
/// longer matches the map, and a misaligned one is a buffer the caller allocated as bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotsError {
    /// Fewer slots than there are named counters.
    Short,
    /// Not a whole number of eight-byte slots.
    Ragged,
    /// Not aligned for `u64`.
    Misaligned,
}

/// One batch read of the counter map, split where the named counters end.
///
/// Borrowed and never owned: the buffer belongs to the reader that filled it, which
/// allocates once at construction and nothing per tick. Copying it here would put an
/// allocation back on the path that exists to have none.
pub struct CounterSlots<'a> {
    named: &'a [u64],
    entries: &'a [u64],
}

impl<'a> CounterSlots<'a> {
    /// Checks the buffer and splits it. The only place in this stage that can fail.
    ///
    /// The split point is [`NAMED_SLOTS`], which is `CounterId::ALL.len()` — read, not
    /// restated, because a counter added to `lorica-common` moves this boundary and a
    /// number copied here would move the whole entry region by one slot in silence.
    pub fn new(bytes: &'a [u8]) -> Result<Self, SlotsError> {
        if bytes.as_ptr().addr() % align_of::<u64>() != 0 {
            return Err(SlotsError::Misaligned);
        }
        if bytes.len() % size_of::<u64>() != 0 {
            return Err(SlotsError::Ragged);
        }
        let slots = <[u64]>::ref_from_bytes(bytes).map_err(|_| SlotsError::Misaligned)?;
        if slots.len() < NAMED_SLOTS {
            return Err(SlotsError::Short);
        }
        let (named, entries) = slots.split_at(NAMED_SLOTS);
        Ok(Self { named, entries })
    }

    /// The named counters, by [`CounterId::index`](lorica_common::CounterId::index).
    pub const fn named(&self) -> &'a [u64] {
        self.named
    }

    /// One slot per unified-list entry, in the order the policy compiler allocated them.
    ///
    /// How many there are is whatever the buffer holds. The kernel side declares the map's
    /// entry count and this crate cannot see that declaration, so a length asserted here
    /// would be a second copy of it drifting on its own.
    pub const fn entries(&self) -> &'a [u64] {
        self.entries
    }
}
