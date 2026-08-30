//! Reading the leaky-bucket bank, which nothing read before.
//!
//! The bank is an `ARRAY` of 1 024 sixty-four-byte slots, one cache line each. Only the first
//! eight bytes of a slot are wanted here — the level — and the rest is the timestamp the data
//! path compares against, plus the padding that keeps two buckets off one line. So the walk
//! reads whole slots and keeps one `u64` from each, which is all the detector can use: a level
//! is a number it can put a share and a total on, while the timestamp is on the kernel's jiffy
//! clock and means nothing beside a userspace reading.
//!
//! **Why a batch walk and not a mapping.** The counter array is created with `BPF_F_MMAPABLE`
//! and read as memory at about three nanoseconds a slot; this map is not, and could not be
//! without changing the program that declares it. At 1 024 slots the syscall is affordable
//! precisely because the bank is small and read rarely — see the cadence note below. Making it
//! mappable would add a second mapping to keep coherent for a read that happens once a second.
//!
//! **Why the caller reads it less often than the counters, and why that is not a compromise.**
//! The bank is the *candidate* side of the snapshot. Nothing in the detector can build a
//! refusal out of it, because 1 024 buckets against any realistic source count means two
//! sources share one — pigeonhole, not hashing quality — so a level names a number and never a
//! source. A signal that cannot confirm anything does not need the freshness of one that can,
//! and this read costs a syscall and 64 KiB of copy where the counter sweep costs neither.
//!
//! **A pass is published whole or not at all.** The walk fills a staging buffer and swaps it in
//! only when it completed. A caller that saw half a bank would compute a total that fell, and a
//! falling total is exactly what this system reads as an attack ending — the one misreading
//! that withdraws a mitigation. On failure the previous pass stands and the caller learns from
//! the `Err`, never from a number that moved for the wrong reason.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use lorica_common::BANK_SLOT_BYTES;

use super::batch::{Attr, BPF_MAP_LOOKUP_BATCH, command};

/// Where the level sits in a slot.
///
/// `Bucket` is `repr(C)` with `level` first. Read by offset rather than by transmuting the
/// slot, because the type is declared in the eBPF crate and this one does not depend on it and
/// must not: the dependency direction is the dataplane below the program, never above it.
const LEVEL_AT: usize = 0;

pub struct BankReader<'fd> {
    fd: BorrowedFd<'fd>,
    buckets: u32,
    batch: u32,
    /// The kernel writes the keys it returned here; for an array map they are the indices.
    keys: Vec<u32>,
    values: Vec<u8>,
    /// Where the walk in progress writes. Never handed out.
    pending: Vec<u64>,
    /// The last pass that completed. What every caller reads.
    levels: Vec<u64>,
    /// One key, for the kernel to record where it stopped.
    token: u32,
}

impl<'fd> BankReader<'fd> {
    /// # Safety
    ///
    /// `fd` must name an `ARRAY` with a four-byte key and a [`BANK_SLOT_BYTES`] value. The walk
    /// hands the kernel buffers sized from those two numbers and the kernel cannot check them
    /// against the map it was given.
    pub unsafe fn new(fd: BorrowedFd<'fd>, buckets: u32, batch: u32) -> Self {
        // At least one, so a caller that passes zero gets a slow walk rather than a division by
        // zero or a syscall that asks for nothing and never advances.
        let batch = batch.max(1).min(buckets.max(1));
        Self {
            fd,
            buckets,
            batch,
            keys: vec![0; batch as usize],
            values: vec![0; batch as usize * BANK_SLOT_BYTES as usize],
            pending: vec![0; buckets as usize],
            levels: vec![0; buckets as usize],
            token: 0,
        }
    }

    /// One whole pass over the bank, or the error that stopped it.
    pub fn read(&mut self) -> io::Result<&[u64]> {
        self.pending.fill(0);
        let mut walked = 0u32;
        let mut first = true;

        while walked < self.buckets {
            let remaining = self.buckets - walked;
            let mut attr = Attr {
                // Zero on the first call means "start at the beginning"; after that the kernel
                // resumes from the key it wrote into `token`, exclusive.
                in_batch: if first {
                    0
                } else {
                    (&raw mut self.token).addr() as u64
                },
                out_batch: (&raw mut self.token).addr() as u64,
                keys: self.keys.as_mut_ptr().addr() as u64,
                values: self.values.as_mut_ptr().addr() as u64,
                count: self.batch.min(remaining),
                map_fd: self.fd.as_raw_fd() as u32,
                ..Attr::default()
            };

            // SAFETY: `keys` holds `batch` four-byte keys and `values` holds `batch` slots of
            // `BANK_SLOT_BYTES`, which is what `count` at most asks the kernel to write.
            let done = match unsafe { command(BPF_MAP_LOOKUP_BATCH, &mut attr) } {
                Ok(()) => false,
                // ENOENT ends the walk. The elements this call returned are valid and the
                // count is written back either way, so they are taken before stopping.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => true,
                Err(err) => return Err(err),
            };

            let got = attr.count as usize;
            for i in 0..got {
                let Some(&index) = self.keys.get(i) else {
                    break;
                };
                let at = i * BANK_SLOT_BYTES as usize + LEVEL_AT;
                let Some(bytes) = self.values.get(at..at + 8) else {
                    break;
                };
                let Some(slot) = self.pending.get_mut(index as usize) else {
                    // An index outside the bank is a map that is not the one this reader was
                    // built for. Skipped rather than trusted: the alternative is writing past
                    // a buffer sized from the constructor's promise.
                    continue;
                };
                let mut word = [0u8; 8];
                word.copy_from_slice(bytes);
                // Both sides are the host's byte order: the data path stores with a plain
                // store and this loads with a plain load, and there is no wire in between.
                *slot = u64::from_ne_bytes(word);
            }

            walked += got as u32;
            first = false;
            if done {
                break;
            }
            if got == 0 {
                // No progress and no ENOENT: the walk would spin. Reported as an incomplete
                // pass rather than looped on, because a caller that never returns is worse
                // than one that says it could not finish.
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
        }

        if walked < self.buckets {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        std::mem::swap(&mut self.pending, &mut self.levels);
        Ok(&self.levels)
    }

    /// The levels the last completed pass left, without walking again.
    pub fn last(&self) -> &[u64] {
        &self.levels
    }
}
