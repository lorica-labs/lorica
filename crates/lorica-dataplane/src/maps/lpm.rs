//! Writing the unified list.

use std::{io, os::fd::BorrowedFd};

use lorica_common::{LpmKey, LpmValue};

use super::batch;

/// The kernel strides a batch buffer by the map's own key size, and for an `LPM_TRIE`
/// that size is the `u32` prefix length in front of the address. `lorica-ebpf`
/// declares the list as `LpmTrie<[u8; 16], LpmValue>` and already asserts that aya's key
/// type is the same size as this one; this states the number that assertion rests on,
/// where the buffer is actually built.
const _: () = assert!(size_of::<LpmKey>() == 20);

/// Writes `entries` into the unified list, `chunk` of them per syscall.
///
/// An entry already present is overwritten, so a reload is a write of the new list over
/// the old one and there is no window in which the list is empty. Keys the new list
/// drops are **not** removed: nothing in this phase reloads a shrinking list, and a
/// removal path with no caller and no test would be worse than one that does not exist.
pub fn load(fd: BorrowedFd<'_>, entries: &[(LpmKey, LpmValue)], chunk: usize) -> io::Result<()> {
    let chunk = chunk.clamp(1, entries.len().max(1));
    let mut keys = Vec::with_capacity(chunk);
    let mut values = Vec::with_capacity(chunk);

    for group in entries.chunks(chunk) {
        keys.clear();
        values.clear();
        keys.extend(group.iter().map(|(key, _)| *key));
        values.extend(group.iter().map(|(_, value)| *value));
        // SAFETY: LpmKey and LpmValue are the key and value types the list is declared
        // with in lorica-ebpf, so their sizes are the map's key and value sizes. The
        // two buffers hold the same number of elements, and the list is not per-CPU.
        unsafe { batch::update(fd, &keys, &values) }?;
    }
    Ok(())
}
