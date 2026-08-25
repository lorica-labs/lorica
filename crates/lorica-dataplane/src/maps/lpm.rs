//! Writing the unified list, and taking one entry back out of it.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

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
/// drops are **not** removed here: nothing reloads a shrinking list, and one entry at a
/// time is what a withdrawal is — see [`remove`].
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

/// `BPF_MAP_DELETE_ELEM`. libc carries no `bpf_cmd` enum, and the number is ABI: a wrong
/// one is a different operation on the same map.
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;

/// The `BPF_MAP_*_ELEM` arm of `union bpf_attr`, field for field as the kernel declares
/// it. The kernel reads it by offset, so the four-byte hole behind `map_fd` is part of
/// the contract and is named rather than left to the layout algorithm.
#[repr(C)]
#[derive(Default)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Takes one entry out of the list, by the exact key it was written under.
///
/// The prefix length is part of that key: an `LPM_TRIE` deletes the node whose prefix is
/// exactly the one given, so a withdrawal never removes a longer entry that happens to
/// sit under it.
///
/// **The two alternatives, with their numbers.** `BPF_MAP_DELETE_BATCH` would reuse the
/// attribute arm [`batch`] already has, but a withdrawal is 1 entry — the one key a rung
/// was confirmed on — so a batch command would be a batch of one and would add a
/// per-map-type kernel op to the set this crate depends on for nothing. aya's typed
/// `LpmTrie::remove` is the other, and it needs `&mut MapData`: the agent leaks its
/// `Ebpf` so the maps outlive every reader of them, so at the point a withdrawal happens
/// there is exactly 1 borrow available and it is shared. A borrowed descriptor is what
/// both callers already hold.
///
/// A key that is not in the list answers `ENOENT`, which is not translated here: whether
/// that is an error is the caller's question, not the map's.
pub fn remove(fd: BorrowedFd<'_>, key: LpmKey) -> io::Result<()> {
    let mut attr = ElemAttr {
        map_fd: fd.as_raw_fd() as u32,
        key: core::ptr::from_ref(&key).addr() as u64,
        ..ElemAttr::default()
    };
    // SAFETY: attr.key points at one LpmKey, which is the key type UNIFIED_LIST is
    // declared with and the size the kernel reads — the assertion above is that size.
    // The size passed is that of ElemAttr rather than of the whole union, so the kernel
    // reads exactly the bytes that exist here and zeroes the rest of what it copies into.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_DELETE_ELEM,
            (&raw mut attr).cast::<libc::c_void>(),
            size_of::<ElemAttr>() as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
