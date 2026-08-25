//! `BPF_MAP_*_BATCH` as a raw syscall against `map.fd()`, and the loading of the
//! unified list.
//!
//! The two raw-syscall entry points are `unsafe` because a buffer length the kernel
//! cannot check is what makes them sound. The safe functions here are the only place
//! that length is tied to a map declared in `lorica-ebpf`, so a caller never has to
//! restate the invariant.

pub mod batch;
pub mod lpm;

use std::{
    fs, io,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use aya::{Ebpf, maps::Map};

/// The descriptor of one of the program's maps.
///
/// aya hands out `&Map`, an enum whose variants all wrap the same `MapData`, while the
/// typed wrappers keep their descriptor behind a sealed trait. This match is the only
/// way across, and it names only the three map types this crate reaches by descriptor.
///
/// `Array` is there for `.bss`, which nobody declared as a map: aya materialises a data
/// section as an `ARRAY` of one entry whose value is the whole section, and that is where the
/// two blocklist tables live. So their kernel cost is read off a descriptor like every other
/// map's rather than multiplied out of the constants they were declared with.
pub fn fd<'a>(ebpf: &'a Ebpf, name: &str) -> Option<BorrowedFd<'a>> {
    match ebpf.map(name)? {
        Map::PerCpuArray(data) | Map::LpmTrie(data) | Map::Array(data) => Some(data.fd().as_fd()),
        _ => None,
    }
}

/// A reader over the program's counter map, built once and read as often as wanted:
/// `read` allocates nothing and returns `entries` sums, the named counters at their own
/// index and then one slot per entry of the unified list.
///
/// The reader borrows the program, so it cannot outlive the maps it reads.
pub fn counters<'a>(
    ebpf: &'a Ebpf,
    entries: u32,
    batch: u32,
) -> io::Result<batch::PerCpuU64Reader<'a>> {
    let fd = fd(ebpf, "COUNTERS")
        .ok_or_else(|| io::Error::other("no COUNTERS map in the loaded program"))?;
    // SAFETY: COUNTERS is declared `PerCpuArray<u64>` in lorica-ebpf, which is the map
    // type and the value size PerCpuU64Reader requires. This is the only place that has
    // to know it, so no caller restates it.
    unsafe { batch::PerCpuU64Reader::new(fd, entries, batch) }
}

/// Kernel memory the map is charged, as the kernel itself accounts it.
///
/// This is the dominant cost of a deployment and it is invisible in the RSS of any
/// process. `/proc/self/fdinfo` rather than `bpftool map show`: no external command, no
/// JSON key whose spelling changed between versions, and it names the descriptor we hold
/// rather than whichever loaded map happens to match by name.
///
/// For an `LPM_TRIE`, which is `BPF_F_NO_PREALLOC`, the number starts at zero and tracks
/// the prefixes actually inserted. It also **undercounts**: the kernel reports the nodes
/// it allocated at their nominal size, while the slab rounds every one of them up and
/// the trie allocates intermediate nodes it never reports. The slab delta is what a
/// small machine feels; this is what is attributable to one map.
pub fn memlock_bytes(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    let info = fs::read_to_string(&path)?;
    let field = info
        .lines()
        .find_map(|line| line.strip_prefix("memlock:"))
        .ok_or_else(|| io::Error::other(format!("{path} carries no memlock line")))?
        .trim();
    field
        .parse()
        .map_err(|err| io::Error::other(format!("{path}: memlock {field:?} is unreadable: {err}")))
}
