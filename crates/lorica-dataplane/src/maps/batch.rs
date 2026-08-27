//! `BPF_MAP_*_BATCH` as a raw syscall against `map.fd()`.
//!
//! aya 0.14 does not expose these commands (aya-rs/aya#1124, #1434, #1479). Forking it
//! would be a permanent rebase debt on a 0.x that breaks its API between minor
//! versions, for code that loads privileged bytecode — and it would buy nothing:
//! `map.fd()` is public, so nothing here needs the library changed. Every piece is
//! upstreamable as it stands, and when it lands upstream this file is deleted.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use aya::util::nr_cpus;

/// Commands of the `bpf` syscall. libc carries no `bpf_cmd` enum, and only the two this
/// crate uses are named here. The numbers are ABI: a wrong one is a different operation
/// on the same map.
const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const BPF_MAP_UPDATE_BATCH: libc::c_long = 26;

/// The `batch` arm of `union bpf_attr`, field for field as the kernel declares it. The
/// kernel reads this by offset, so the layout is the contract; `count` is also read back
/// out of it, because the kernel writes there how many elements it actually handled.
#[repr(C)]
#[derive(Default)]
struct Attr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

/// # Safety
///
/// `attr.keys` must point to at least `attr.count` keys of the map's key size, and
/// `attr.values` to at least `attr.count` values of the size the map reports for one
/// element — which is one value per possible processor for a per-CPU map. The kernel
/// has no way to learn how long either buffer is.
unsafe fn command(cmd: libc::c_long, attr: &mut Attr) -> io::Result<()> {
    // SAFETY: the buffer lengths are the caller's precondition. The size passed is that
    // of Attr itself rather than of the whole union, so the kernel reads exactly the
    // bytes that exist here and zeroes the rest of the union it copies into.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            (&raw mut *attr).cast::<libc::c_void>(),
            size_of::<Attr>() as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A reusable reader over a per-CPU array of `u64`.
///
/// It allocates its buffers once, at construction, and **nothing** per read. That is not
/// a micro-optimisation. aya's `PerCpuArray::get` returns a boxed slice per slot, so
/// reading fifty thousand counters ten times a second is half a million allocations a
/// second before a single syscall is counted, and the agent's tick is asserted to
/// allocate nothing at all.
///
/// **The per-processor layout stays inside.** The kernel writes `count ×
/// num_possible_cpus` values per call, grouped by key and in processor order;
/// [`Self::read`] hands back one **sum per slot, in slot order** — `entries` values,
/// whatever the batch size and whatever the machine's processor count. A caller never
/// sizes a per-CPU buffer and never has to know the grouping, which is the one thing
/// here that is an out-of-bounds write when it is guessed.
///
/// **A read is not a coherent snapshot, and never was.** `generic_map_lookup_batch`
/// calls `cond_resched()` between elements, so the slots of one read are sampled at
/// times that differ by whatever the scheduler did in between; two slots of the same
/// read already belong to two different instants. That is what makes [`Self::with_stride`]
/// free rather than a trade: reading a fraction of the map per call widens a staleness
/// that is not zero to begin with, and it widens it on quantities that only ever grow.
pub struct PerCpuU64Reader<'fd> {
    fd: BorrowedFd<'fd>,
    cpus: usize,
    batch: u32,
    /// Fraction of the map one read covers, as a divisor. One reads all of it.
    stride: u32,
    /// The slot the next read starts at. Zero means a pass is about to begin, which is
    /// also the state in which no resume token is sent.
    next: usize,
    /// The key the kernel wrote back at the end of the last call, which is where the next
    /// one resumes from. Held across reads and not only across the calls of one read: that
    /// is the whole of the incremental sweep.
    token: u32,
    /// The keys one call returns, at most `batch` of them.
    keys: Vec<u32>,
    /// `batch × cpus` values: the most one call can write.
    values: Vec<u64>,
    /// The result, one sum per slot.
    sums: Vec<u64>,
    /// Elements the last read asked the kernel for. See [`Self::walked`].
    walked: usize,
}

impl<'fd> PerCpuU64Reader<'fd> {
    /// # Safety
    ///
    /// `fd` must be a `BPF_MAP_TYPE_PERCPU_ARRAY` of eight-byte values. The kernel
    /// writes one value per possible processor for every key it returns, so a map with a
    /// wider value writes past the buffer sized here.
    pub unsafe fn new(fd: BorrowedFd<'fd>, entries: u32, batch: u32) -> io::Result<Self> {
        let cpus = nr_cpus()
            .map_err(|(path, err)| io::Error::new(err.kind(), format!("{path}: {err}")))?;
        // A batch of zero would ask for nothing forever; one larger than the map only
        // wastes the buffer.
        let batch = batch.clamp(1, entries.max(1));
        Ok(Self {
            fd,
            cpus,
            batch,
            stride: 1,
            next: 0,
            token: 0,
            keys: vec![0; batch as usize],
            // The length that makes the syscall sound. Taking the processor count from
            // anywhere but the possible-CPU mask — which is what `nr_cpus` reads, not
            // the online count — is an out-of-bounds write.
            values: vec![0; batch as usize * cpus],
            sums: vec![0; entries as usize],
            walked: 0,
        })
    }

    /// How many slots one syscall asks for. Never how many it gets: the last call of a
    /// walk is short, and the count the kernel writes back is the only length that may
    /// be read.
    pub const fn batch(&self) -> u32 {
        self.batch
    }

    /// Spreads one pass over the map across `stride` reads instead of one.
    ///
    /// **What it buys and what it costs.** The cost of a read is exactly linear in the
    /// elements it asks the kernel for, and the kernel is preemptible between them, so the
    /// worst read of a sweep is divided by `stride` and the mean CPU is unchanged. What
    /// widens is freshness: a given slot is now refreshed once every `stride` reads instead
    /// of every read.
    ///
    /// **Why that is sound here and would not be for an arbitrary map.** These slots are
    /// counters the data path only ever increments, so a slot this read did not visit keeps
    /// the value the last one left — which is a lower bound on the truth, never a drop.
    /// Detection compares a snapshot against an earlier snapshot, and a lower bound on both
    /// ends of a difference is a difference that under-reports rather than one that invents
    /// an attack. A map whose values could decrease would need the whole pass.
    ///
    /// One is the whole map per read, which is what the reader does without this call.
    pub const fn with_stride(mut self, stride: u32) -> Self {
        // A stride of zero would claim no slots and finish no pass, and the reader is the
        // wrong place to refuse a number: the caller that parsed it says so instead.
        self.stride = if stride == 0 { 1 } else { stride };
        self
    }

    /// The divisor [`Self::with_stride`] set. The slots one read asks for are
    /// `entries / stride`, rounded up, which is the number a cost is computed from.
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    /// How many elements the last read actually asked the kernel for.
    ///
    /// The cost of a read is exactly linear in this and in nothing else — 264 ns an
    /// element on the target, measured — so it is the number to look at when a reader
    /// costs more than expected, and the number a test asserts on to prove that a reader
    /// built for the named counters is not quietly walking fifty thousand slots.
    pub const fn walked(&self) -> usize {
        self.walked
    }

    /// Walks the slots this read is due and returns one sum per slot, for every slot the
    /// reader was built for. Allocates nothing.
    ///
    /// It stops at `entries` rather than at the end of the map. An array map is walked in
    /// index order from zero, so a bound on the count is a bound on the slots, and without
    /// it a reader built for the eighteen named counters would read every per-entry slot
    /// above them and throw the answers away — paying the full cost for a fraction of the
    /// data, which is the whole cost this reader exists to control.
    ///
    /// At the default stride of one, "the slots this read is due" is every slot and the
    /// returned values are all fresh. Above it, this read refreshes its window and the
    /// slots outside it carry what the read that last covered them found — see
    /// [`Self::with_stride`] for why that is a lower bound and not a lie.
    pub fn read(&mut self) -> io::Result<&[u64]> {
        // The window this read claims. Rounded up, so a stride that does not divide the
        // map still finishes a pass in `stride` reads rather than in one more.
        let window = self.sums.len().div_ceil(self.stride as usize);
        let start = self.next.min(self.sums.len());
        let end = (start + window).min(self.sums.len());
        // Cleared, because a slot inside the window that the walk does not reach — the map
        // is smaller than this reader was built for — must read zero and not the number
        // some earlier read left. Only the window: outside it, the previous value standing
        // is the point.
        self.sums[start..end].fill(0);
        self.walked = 0;

        // in_batch and out_batch are pointers to one key: the kernel resumes the walk from
        // the key it left off at, exclusive, and for an array map that key is the index. So
        // `next` and `token` say the same thing twice — `token` to the kernel, `next` to the
        // arithmetic above — and they are only correct together.
        while self.walked < end - start {
            let remaining = end - start - self.walked;
            let mut attr = Attr {
                in_batch: if self.next == 0 {
                    0
                } else {
                    (&raw mut self.token).addr() as u64
                },
                out_batch: (&raw mut self.token).addr() as u64,
                keys: self.keys.as_mut_ptr().addr() as u64,
                values: self.values.as_mut_ptr().addr() as u64,
                // Never more than the buffers hold, and never more than is left to read.
                count: (self.batch as usize).min(remaining) as u32,
                map_fd: self.fd.as_raw_fd() as u32,
                ..Attr::default()
            };

            // SAFETY: keys holds `batch` four-byte keys and values `batch * cpus`
            // eight-byte values, which is `count` keys and `count` per-processor values
            // for the per-CPU array of u64 this type's constructor requires.
            let done = match unsafe { command(BPF_MAP_LOOKUP_BATCH, &mut attr) } {
                Ok(()) => false,
                // ENOENT is how the walk ends. The elements this call returned are valid
                // and there are no more; the count is written back either way.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => true,
                Err(err) => return Err(err),
            };

            let n = (attr.count as usize).min(self.keys.len());
            for (i, key) in self.keys[..n].iter().enumerate() {
                if let Some(slot) = self.sums.get_mut(*key as usize) {
                    *slot = self.values[i * self.cpus..(i + 1) * self.cpus].iter().sum();
                }
            }
            self.walked += n;
            // Advanced per call and not per read: it is what the next `in_batch` is judged
            // against, and a call that returned elements has moved the kernel's cursor
            // whether or not the window is finished.
            self.next = start + self.walked;

            if done {
                // The map ends here, so every slot above what this call returned does not
                // exist and has to read zero rather than an older number — and the next
                // read starts a fresh pass from the beginning.
                let above = self.next.min(self.sums.len());
                self.sums[above..].fill(0);
                self.next = 0;
                return Ok(&self.sums);
            }
            if n == 0 {
                return Err(io::Error::other(
                    "BPF_MAP_LOOKUP_BATCH returned no element and did not say the walk was over",
                ));
            }
        }
        if self.next >= self.sums.len() {
            self.next = 0;
        }
        Ok(&self.sums)
    }
}

/// Processors the kernel sizes a per-CPU value for against processors that can run code,
/// when the first is larger — which is a cost multiplier nobody chose.
///
/// `bpf_map_value_size` multiplies a per-CPU value by `num_possible_cpus()`, and
/// `bpf_percpu_array_copy` walks `for_each_possible_cpu`, so a guest booted with more
/// possible processors than online ones pays a copy per phantom processor on every element
/// of every batch read. The measured cost of this read is about 130 ns fixed plus 34 ns per
/// processor, so four phantom processors are a third of the read spent on slots that are
/// permanently zero.
///
/// `None` when there is nothing to say, so the caller has nothing to decide.
pub fn phantom_cpus() -> Option<(usize, usize)> {
    let possible = nr_cpus().ok()?;
    let online = aya::util::online_cpus().ok()?.len();
    (possible > online).then_some((possible, online))
}

/// One `BPF_MAP_UPDATE_BATCH`: every element of `keys` in a single syscall.
///
/// Ten million single-element updates at 1,5 µs each would be fifteen seconds, which is
/// the reason a blocklist reload needs this at all.
///
/// A partial write is an error and the message carries the count, because the operator's
/// question after a failed reload is how much of the list is loaded, and an errno does
/// not answer it.
///
/// # Safety
///
/// `size_of::<K>()` must be the map's key size and `size_of::<V>()` its value size: the
/// kernel strides both buffers by its own sizes, not by the caller's. Not for a per-CPU
/// map, whose value buffer carries one value per possible processor.
pub unsafe fn update<K: Copy, V: Copy>(
    fd: BorrowedFd<'_>,
    keys: &[K],
    values: &[V],
) -> io::Result<()> {
    assert_eq!(
        keys.len(),
        values.len(),
        "the kernel reads one value per key, from two buffers it cannot measure"
    );
    let asked = keys.len();
    let mut attr = Attr {
        keys: keys.as_ptr().addr() as u64,
        values: values.as_ptr().addr() as u64,
        count: u32::try_from(asked).map_err(|_| io::Error::other("more than u32::MAX entries"))?,
        map_fd: fd.as_raw_fd() as u32,
        ..Attr::default()
    };

    // SAFETY: both buffers hold `asked` elements, which is the count passed, and their
    // element sizes are the map's key and value sizes by this function's contract.
    let result = unsafe { command(BPF_MAP_UPDATE_BATCH, &mut attr) };
    let taken = attr.count;
    match result {
        Ok(()) if taken as usize == asked => Ok(()),
        Ok(()) => Err(io::Error::other(format!(
            "BPF_MAP_UPDATE_BATCH took {taken} of {asked} entries and reported success"
        ))),
        Err(err) => Err(io::Error::new(
            err.kind(),
            format!("BPF_MAP_UPDATE_BATCH took {taken} of {asked} entries: {err}"),
        )),
    }
}
