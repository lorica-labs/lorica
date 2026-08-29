//! `BPF_MAP_*_BATCH` as a raw syscall against `map.fd()`, the mapped read of the counter
//! array, and the loading of the unified list.
//!
//! The raw-syscall and `mmap` entry points are `unsafe` because a buffer length the kernel
//! cannot check is what makes them sound. The safe functions here are the only place that
//! length is tied to a map declared in `lorica-ebpf`, so a caller never has to restate the
//! invariant.

pub mod batch;
pub mod blocklist;
pub mod lpm;
pub mod mmap;

use std::{
    fs, io,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use aya::{Ebpf, EbpfLoader, maps::Map, util::nr_cpus};
use lorica_common::{COUNTER_STRIPE_SYMBOL, CounterLayout, MAX_CPUS};

/// The name the object gives the counter array. Written once, because the loader sets its
/// size and the reader opens it by the same name and a typo in one of them is a map nobody
/// finds.
pub const COUNTERS: &str = "COUNTERS";

/// The descriptor of one of the program's maps.
///
/// aya hands out `&Map`, an enum whose variants all wrap the same `MapData`, while the
/// typed wrappers keep their descriptor behind a sealed trait. This match is the only
/// way across, and it names only the three map types this crate reaches by descriptor.
///
/// `Array` covers two very different things. The counter array is one, declared as an `ARRAY`
/// so it can carry `BPF_F_MMAPABLE`; the other is `.bss`, which nobody declared as a map: aya
/// materialises a data section as an `ARRAY` of one entry whose value is the whole section,
/// and that is where the two blocklist tables live. So their kernel cost is read off a
/// descriptor like every other map's rather than multiplied out of the constants they were
/// declared with.
pub fn fd<'a>(ebpf: &'a Ebpf, name: &str) -> Option<BorrowedFd<'a>> {
    match ebpf.map(name)? {
        Map::PerCpuArray(data) | Map::LpmTrie(data) | Map::Array(data) => Some(data.fd().as_fd()),
        _ => None,
    }
}

/// The counter layout for this machine and this slot count.
///
/// The processor count is the *possible* one and not the online one, because
/// `bpf_get_smp_processor_id` can return any of them and a stripe that does not exist is a
/// counter written past the end of the map.
pub fn counter_layout(slots: u32) -> io::Result<CounterLayout> {
    let cpus =
        nr_cpus().map_err(|(path, err)| io::Error::new(err.kind(), format!("{path}: {err}")))?;
    let cpus = u32::try_from(cpus).unwrap_or(u32::MAX);
    CounterLayout::new(slots, cpus).ok_or_else(|| {
        io::Error::other(format!(
            "no counter layout for {slots} slots on {cpus} possible processors: the ceiling is \
             {MAX_CPUS} processors, and past it the map is a size no profile budgeted for"
        ))
    })
}

/// Sizes the counter map and patches the stripe width the program indexes it with.
///
/// **The two are one decision and this is why the function exists.** The map is a flat array
/// striped by processor, so the program computes `cpu * stripe + slot` from a `.rodata` word
/// the loader writes, and the map has to be created with `stripe × cpus` entries. Setting one
/// without the other gives a program that counts into the wrong slots, or into no slot at all,
/// with nothing failing anywhere — which is the restatement failure this tree keeps finding.
/// Nothing else in the workspace may call `map_max_entries` on the counter map.
///
/// The layout is borrowed for as long as the loader lives, because that is what
/// `override_global` records: a pointer to the caller's bytes, read when `load` runs.
pub fn size_counters<'a, 'loader>(
    loader: &'loader mut EbpfLoader<'a>,
    layout: &'a CounterLayout,
) -> &'loader mut EbpfLoader<'a> {
    loader
        .map_max_entries(COUNTERS, layout.entries())
        .override_global(COUNTER_STRIPE_SYMBOL, &layout.stripe, true)
}

/// A reader over the program's counter map: the mapped one where the kernel allows it, the
/// batch walk where it does not.
///
/// Both hand back the same thing — one sum per slot, in slot order, `layout.slots` of them —
/// so nothing above this has to know which path it got. `tests/batch.rs` asserts the two agree
/// on a known state, which is the only reason keeping two implementations is defensible.
pub enum Counters<'fd> {
    /// No syscall: the array's own pages, read as relaxed atomic loads.
    Mapped(mmap::Mapped),
    /// One `BPF_MAP_LOOKUP_BATCH` walk per pass.
    Batched {
        reader: batch::StripedU64Reader<'fd>,
        /// Why the mapping was refused, when one was attempted. `None` when the caller asked
        /// for this path outright.
        ///
        /// Kept here rather than returned beside the reader because it is a property of the
        /// reader that every caller would otherwise have to thread through: the difference
        /// between the two paths is a factor of 52 to 78 in what a sweep costs, measured, so an
        /// agent has
        /// to be able to say which one it got and why, at any point and not only at
        /// construction.
        unmapped: Option<io::Error>,
    },
}

impl<'fd> Counters<'fd> {
    /// Maps the counter array, and falls back to the batch walk if the kernel refuses.
    ///
    /// The refusal worth planning for is a map created without `BPF_F_MMAPABLE` — an object
    /// built before that flag was added, or one loaded by something else — and it comes back as
    /// `EINVAL` from `mmap` rather than as a load failure. A kernel below 5.5 cannot create the
    /// map at all, so it never reaches here.
    ///
    /// # Safety
    ///
    /// `fd` must be the counter array declared in `lorica-ebpf`: a `BPF_MAP_TYPE_ARRAY` of
    /// eight-byte values with at least `layout.entries()` of them.
    pub unsafe fn open(fd: BorrowedFd<'fd>, layout: CounterLayout, batch: u32) -> Self {
        // SAFETY: the descriptor is the caller's precondition, unchanged.
        match unsafe { mmap::Mapped::new(fd, layout) } {
            Ok(mapped) => Self::Mapped(mapped),
            Err(err) => Self::Batched {
                // SAFETY: as above.
                reader: unsafe { batch::StripedU64Reader::new(fd, layout, batch) },
                unmapped: Some(err),
            },
        }
    }

    /// The batch walk, unconditionally. For the equivalence test, and for a caller that wants
    /// to measure the path it is not using.
    ///
    /// # Safety
    ///
    /// As [`Self::open`].
    pub unsafe fn batched(fd: BorrowedFd<'fd>, layout: CounterLayout, batch: u32) -> Self {
        Self::Batched {
            // SAFETY: the descriptor is the caller's precondition, unchanged.
            reader: unsafe { batch::StripedU64Reader::new(fd, layout, batch) },
            unmapped: None,
        }
    }

    /// Why this reader is not the mapped one, when a mapping was attempted and refused.
    pub const fn unmapped(&self) -> Option<&io::Error> {
        match self {
            Self::Mapped(_) => None,
            Self::Batched { unmapped, .. } => unmapped.as_ref(),
        }
    }

    pub fn with_stride(self, stride: u32) -> Self {
        match self {
            // The mapped read has no per-element syscall cost to spread, so there is nothing
            // for a stride to buy and refreshing a fraction of the slots would only make them
            // staler. It is not an error to ask: the flag is one number for a whole agent and
            // the mapped path is the one that made the flag unnecessary.
            Self::Mapped(mapped) => Self::Mapped(mapped),
            Self::Batched { reader, unmapped } => Self::Batched {
                reader: reader.with_stride(stride),
                unmapped,
            },
        }
    }

    pub fn read(&mut self) -> io::Result<&[u64]> {
        match self {
            Self::Mapped(mapped) => Ok(mapped.read()),
            Self::Batched { reader, .. } => reader.read(),
        }
    }

    /// Reads one pass has spread over. One on the mapped path, always.
    pub const fn stride(&self) -> u32 {
        match self {
            Self::Mapped(_) => 1,
            Self::Batched { reader, .. } => reader.stride(),
        }
    }

    /// Elements the last read asked the kernel for. Zero on the mapped path, because it asks
    /// the kernel for nothing — which is the number the whole conversion was about.
    pub const fn walked(&self) -> usize {
        match self {
            Self::Mapped(_) => 0,
            Self::Batched { reader, .. } => reader.walked(),
        }
    }

    pub const fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped(_))
    }

    pub const fn layout(&self) -> CounterLayout {
        match self {
            Self::Mapped(mapped) => mapped.layout(),
            Self::Batched { reader, .. } => reader.layout(),
        }
    }
}

/// A reader over the program's counter map, built once and read as often as wanted: `read`
/// allocates nothing and returns `slots` sums, the named counters at their own index and then
/// one slot per entry of the unified list.
///
/// The reader borrows the program, so it cannot outlive the maps it reads.
pub fn counters<'a>(ebpf: &'a Ebpf, slots: u32, batch: u32) -> io::Result<Counters<'a>> {
    let layout = counter_layout(slots)?;
    let fd = fd(ebpf, COUNTERS)
        .ok_or_else(|| io::Error::other("no COUNTERS map in the loaded program"))?;
    // SAFETY: COUNTERS is declared `Array<u64>` with BPF_F_MMAPABLE in lorica-ebpf and sized
    // by `size_counters` from the same layout, which is the map type, the value width and the
    // entry count both readers require. This is the only place that has to know it, so no
    // caller restates it.
    Ok(unsafe { Counters::open(fd, layout, batch) })
}

/// One slot, summed over every processor's stripe, read one element at a time.
///
/// For tests and for anything asking a single question: it is a syscall per stripe, which is
/// the cost the readers above exist to avoid, and correct without any of their state.
pub fn counter_at(ebpf: &Ebpf, slots: u32, index: u32) -> io::Result<u64> {
    use aya::maps::{Array, MapData};

    let layout = counter_layout(slots)?;
    let map = ebpf
        .map(COUNTERS)
        .ok_or_else(|| io::Error::other("no COUNTERS map in the loaded program"))?;
    let array: Array<&MapData, u64> = Array::try_from(map)
        .map_err(|err| io::Error::other(format!("COUNTERS is not a flat array: {err}")))?;
    let mut total = 0u64;
    for cpu in 0..layout.cpus {
        let value = array
            .get(&layout.index(cpu, index), 0)
            .map_err(|err| io::Error::other(format!("reading counter slot {index}: {err}")))?;
        total = total.wrapping_add(value);
    }
    Ok(total)
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
