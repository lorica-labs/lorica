//! The counter map read as memory, with no syscall on the path at all.
//!
//! **This is the whole point of the flat layout.** Reading fifty thousand counter slots ten
//! times a second through `BPF_MAP_LOOKUP_BATCH` cost about 13 % of a core: ~130 ns fixed plus
//! ~34 ns per possible processor per element, two `copy_to_user` calls and a `cond_resched()`
//! for every one of them. None of that is a syscall that can be made faster — it is the syscall
//! itself. `BPF_F_MMAPABLE` (kernel 5.5, commit `fc9702273e2e`) lets the array's pages be
//! mapped into the reading process, so the same numbers become loads.
//!
//! **What the kernel requires**, and it is short: `MAP_SHARED`, the length rounded up to a
//! page, no `bpf_spin_lock` inside the value, and no writable mapping of a frozen map. Only
//! `BPF_MAP_TYPE_ARRAY` is accepted — a per-CPU array is refused — which is why the counter map
//! stopped being one.
//!
//! **Why every read goes through `AtomicU64`.** The data path writes these words with a plain
//! non-atomic add while this process reads them. In Rust that is a data race and therefore
//! undefined behaviour if the read is a `&u64`, whatever the machine does: the optimiser is
//! entitled to assume the memory does not change under it and to fold two reads into one, or to
//! tear one. `AtomicU64::load(Relaxed)` is the same instruction on x86-64 and aarch64 — an
//! aligned eight-byte load is single-copy atomic on both — and it is a load the optimiser is
//! not allowed to invent anything about. So this costs nothing and buys the whole soundness
//! argument.
//!
//! **There is still no coherent snapshot, and there was none before.** Two slots read here are
//! read at two instants; `LOOKUP_BATCH` offered no more, since it yielded the processor between
//! elements. The counters only increase, so a sum assembled over a few microseconds is a lower
//! bound and never a drop.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use lorica_common::CounterLayout;

/// The counter array, mapped read-only.
///
/// Owns the mapping and unmaps it on drop. The descriptor is only needed to create the
/// mapping: once `mmap` has returned, the pages stay valid until they are unmapped, so nothing
/// here borrows the program.
pub struct Mapped {
    /// First byte of the mapping. Kept separately from the slice below because it is what
    /// `munmap` takes, and the length it takes is the rounded one and not the useful one.
    base: NonNull<u64>,
    mapped_bytes: usize,
    layout: CounterLayout,
    /// One sum per slot, so a caller gets the same shape as the batch reader hands back and
    /// this allocates nothing per read.
    sums: Vec<u64>,
}

// SAFETY: the mapping is read-only and the pointer is owned by this value alone, so moving it
// between threads moves the whole mapping with it. Every read goes through an atomic load, so
// concurrent readers are sound as well — which is what makes `Sync` correct and not merely
// convenient.
unsafe impl Send for Mapped {}
// SAFETY: as above; `&Mapped` exposes no way to write.
unsafe impl Sync for Mapped {}

impl Mapped {
    /// Maps the counter array.
    ///
    /// Fails rather than degrading, because the caller has a fallback and a mapping that
    /// silently read the wrong bytes would not be one. The error is worth reporting as it
    /// stands: `EINVAL` is a map that was not created with `BPF_F_MMAPABLE`, `EACCES` a frozen
    /// map asked for write access, `ENOMEM` an address space or accounting limit.
    ///
    /// # Safety
    ///
    /// `fd` must be a `BPF_MAP_TYPE_ARRAY` of eight-byte values with at least
    /// `layout.entries()` of them, created with `BPF_F_MMAPABLE`. The kernel checks the flag
    /// and the map type; it does not check that the value width is the one assumed here, and a
    /// wider value would make every index point somewhere else.
    pub unsafe fn new(fd: BorrowedFd<'_>, layout: CounterLayout) -> io::Result<Self> {
        let wanted = usize::try_from(layout.bytes())
            .map_err(|_| io::Error::other("the counter map is larger than this address space"))?;
        // The kernel maps whole pages and refuses a length of zero.
        let page = page_size();
        let mapped_bytes = wanted.max(1).next_multiple_of(page);

        // SAFETY: a null hint asks the kernel to choose the address; the length is a whole
        // number of pages; MAP_SHARED is what the kernel requires for a BPF map and PROT_READ
        // is all this ever wants. The descriptor is the caller's precondition.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped_bytes,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "cannot map {mapped_bytes} bytes of the counter array \
                     ({} slots x {} processors): {err}",
                    layout.stripe, layout.cpus
                ),
            ));
        }
        let Some(base) = NonNull::new(base.cast::<u64>()) else {
            // A successful mmap never returns null, and treating it as an error is cheaper
            // than a comment explaining why the branch cannot be taken.
            return Err(io::Error::other("mmap succeeded and returned null"));
        };

        Ok(Self {
            base,
            mapped_bytes,
            layout,
            sums: vec![0; layout.slots as usize],
        })
    }

    pub const fn layout(&self) -> CounterLayout {
        self.layout
    }

    /// Bytes the mapping covers, which is the useful length rounded up to a page. Exposed
    /// because it is what a memory measurement of the agent has to attribute, and it is not
    /// derivable from the layout alone.
    pub const fn mapped_bytes(&self) -> usize {
        self.mapped_bytes
    }

    /// One sum per slot: every processor's stripe added up, slot by slot.
    ///
    /// Allocates nothing. The loop is `cpus × slots` relaxed loads and no syscall, which at
    /// four thousand slots and eight processors is tens of microseconds against the 1.6 ms the
    /// same read cost as a batch walk.
    pub fn read(&mut self) -> &[u64] {
        let stripe = self.layout.stripe as usize;
        let cpus = self.layout.cpus as usize;
        // Moved out and moved back, so the sums can be written while the mapping is read.
        // `mem::take` on a `Vec` leaves an empty one behind and allocates nothing, which is the
        // property the tick is asserted on; splitting the borrow any other way here needs
        // `unsafe` for no gain.
        let mut sums = std::mem::take(&mut self.sums);
        sums.fill(0);
        let words = self.words();
        for cpu in 0..cpus {
            let offset = cpu * stripe;
            // A stripe the mapping does not cover is a map smaller than the layout says, which
            // is a caller error the constructor cannot detect. Stopping is the answer that
            // cannot read another map's memory.
            let Some(region) = words.get(offset..offset + sums.len()) else {
                break;
            };
            for (sum, word) in sums.iter_mut().zip(region) {
                // Relaxed: there is nothing to order against. Each word is written by one
                // processor with a plain add and read here; what is needed is that the load is
                // a load the compiler may not fold, tear or hoist, and that is exactly what
                // this is. See the module header for why a `&u64` here would be undefined
                // behaviour rather than merely racy.
                *sum = sum.wrapping_add(word.load(Ordering::Relaxed));
            }
        }
        self.sums = sums;
        &self.sums
    }

    /// The mapping as atomics.
    ///
    /// The length is the layout's and not the rounded one: the words past `entries` are page
    /// padding the kernel zeroed, and a caller that summed them would be summing a stripe that
    /// does not exist.
    fn words(&self) -> &[AtomicU64] {
        let len = self.layout.entries() as usize;
        // SAFETY: the mapping covers `mapped_bytes >= entries * 8` bytes of readable memory
        // that lives as long as `self`, it is page-aligned and therefore eight-byte aligned,
        // and `AtomicU64` has the size and alignment of `u64` with no validity requirement
        // beyond it. Handing out `&[AtomicU64]` rather than `&[u64]` is what makes the
        // concurrent writes in the kernel sound to read.
        unsafe { std::slice::from_raw_parts(self.base.as_ptr().cast::<AtomicU64>(), len) }
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        // SAFETY: the address and length are the ones `mmap` returned and was given, and no
        // slice handed out by `words` can outlive `self`.
        unsafe {
            libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.mapped_bytes);
        }
    }
}

fn page_size() -> usize {
    // SAFETY: no argument is a pointer and the name is a constant of the C library.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // A sysconf that fails returns -1; 4 KiB is the only page size any target of this project
    // has, and rounding to it is still a valid rounding on a 64 KiB machine.
    if size > 0 { size as usize } else { 4096 }
}
