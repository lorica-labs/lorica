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
use lorica_common::CounterLayout;

/// Commands of the `bpf` syscall. libc carries no `bpf_cmd` enum, and only the two this
/// crate uses are named here. The numbers are ABI: a wrong one is a different operation
/// on the same map.
pub(super) const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const BPF_MAP_UPDATE_BATCH: libc::c_long = 26;

/// The `batch` arm of `union bpf_attr`, field for field as the kernel declares it. The
/// kernel reads this by offset, so the layout is the contract; `count` is also read back
/// out of it, because the kernel writes there how many elements it actually handled.
#[repr(C)]
#[derive(Default)]
pub(super) struct Attr {
    pub(super) in_batch: u64,
    pub(super) out_batch: u64,
    pub(super) keys: u64,
    pub(super) values: u64,
    pub(super) count: u32,
    pub(super) map_fd: u32,
    pub(super) elem_flags: u64,
    pub(super) flags: u64,
}

/// # Safety
///
/// `attr.keys` must point to at least `attr.count` keys of the map's key size, and
/// `attr.values` to at least `attr.count` values of the size the map reports for one
/// element — which is one value per possible processor for a per-CPU map. The kernel
/// has no way to learn how long either buffer is.
pub(super) unsafe fn command(cmd: libc::c_long, attr: &mut Attr) -> io::Result<()> {
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

/// A reusable reader over the striped counter array.
///
/// It allocates its buffers once, at construction, and **nothing** per read. That is not
/// a micro-optimisation. aya's typed lookups box a value per slot, so reading fifty thousand
/// counters ten times a second is half a million allocations a second before a single syscall
/// is counted, and the agent's tick is asserted to allocate nothing at all.
///
/// **The stripe layout stays inside.** The map is `stripe × cpus` flat `u64` laid out
/// CPU-major, so each processor owns a contiguous region —
/// [`CounterLayout`](lorica_common::CounterLayout) is where that arithmetic lives.
/// [`Self::read`] hands back one **sum per slot, in slot order**, `slots` values, whatever the
/// batch size and whatever the machine's processor count. A caller never indexes a stripe and
/// never has to know its width, which is the one thing here that reads the wrong counter when
/// it is guessed.
///
/// **This is the fallback path.** The map carries `BPF_F_MMAPABLE`, so the agent normally
/// reads the same bytes through [`super::mmap::Mapped`] with no syscall at all. This exists
/// for the case where the mapping is refused — and it is what the mapping is checked against,
/// which is the other reason to keep it.
///
/// **A read is not a coherent snapshot, and never was.** `generic_map_lookup_batch` calls
/// `cond_resched()` between elements, so the elements of one pass are sampled at times that
/// differ by whatever the scheduler did in between; two of them already belong to two
/// instants. That is what makes [`Self::with_stride`] free rather than a trade: spreading a
/// pass over several reads widens a staleness that is not zero to begin with, and it widens it
/// on quantities that only ever grow.
pub struct StripedU64Reader<'fd> {
    fd: BorrowedFd<'fd>,
    layout: CounterLayout,
    batch: u32,
    /// Reads one pass over the map is spread across. One reads all of it.
    stride: u32,
    /// The flat index the next read starts at, inside the pass in progress.
    next: usize,
    /// The key the kernel wrote back at the end of the last call, which is where the next one
    /// resumes from. Held across reads and not only across the calls of one read: that is the
    /// whole of the incremental sweep.
    token: u32,
    /// The keys one call returns, at most `batch` of them.
    keys: Vec<u32>,
    /// One value per key. A flat `ARRAY` and not a `PERCPU_ARRAY`, so the kernel writes one
    /// eight-byte value per element rather than one per possible processor — which is also
    /// why a machine with phantom processors no longer pays a copy per element for them, only
    /// the elements of their stripes.
    values: Vec<u64>,
    /// Sums the pass in progress has accumulated, over the stripes it has reached so far.
    pending: Vec<u64>,
    /// The last completed pass, which is what a caller reads. Published whole: a pass that has
    /// covered three stripes of eight holds three eighths of every slot, and handing that out
    /// would report a collapse that did not happen.
    sums: Vec<u64>,
    /// Elements the last read asked the kernel for. See [`Self::walked`].
    walked: usize,
}

impl<'fd> StripedU64Reader<'fd> {
    /// # Safety
    ///
    /// `fd` must be a `BPF_MAP_TYPE_ARRAY` of eight-byte values. The kernel strides the value
    /// buffer by its own value size, so a map with a wider value writes past the buffer sized
    /// here. A map with fewer entries than `layout.entries()` is merely a walk that ends
    /// early.
    pub unsafe fn new(fd: BorrowedFd<'fd>, layout: CounterLayout, batch: u32) -> Self {
        // A batch of zero would ask for nothing forever; one larger than the map only
        // wastes the buffer.
        let batch = batch.clamp(1, layout.entries().max(1));
        Self {
            fd,
            layout,
            batch,
            stride: 1,
            next: 0,
            token: 0,
            keys: vec![0; batch as usize],
            values: vec![0; batch as usize],
            pending: vec![0; layout.slots as usize],
            sums: vec![0; layout.slots as usize],
            walked: 0,
        }
    }

    /// How many elements one syscall asks for. Never how many it gets: the last call of a
    /// walk is short, and the count the kernel writes back is the only length that may
    /// be read.
    pub const fn batch(&self) -> u32 {
        self.batch
    }

    /// Spreads one pass over the map across `stride` reads instead of one.
    ///
    /// **What it buys and what it costs.** The cost of a read is exactly linear in the
    /// elements it asks the kernel for, and the kernel is preemptible between them, so the
    /// worst read of a pass is divided by `stride` and the mean CPU is unchanged. What widens
    /// is freshness: the sums a caller reads are refreshed once per pass, so once every
    /// `stride` reads.
    ///
    /// **Why that is sound here and would not be for an arbitrary map.** These slots are
    /// counters the data path only ever increments, so a pass that has not finished leaves the
    /// previous pass's totals standing — a lower bound on the truth, never a drop. Detection
    /// compares a snapshot against an earlier snapshot, and a lower bound on both ends of a
    /// difference is a difference that under-reports rather than one that invents an attack. A
    /// map whose values could decrease would need the whole pass.
    ///
    /// One is the whole map per read, which is what the reader does without this call.
    pub const fn with_stride(mut self, stride: u32) -> Self {
        // A stride of zero would claim no elements and finish no pass, and the reader is the
        // wrong place to refuse a number: the caller that parsed it says so instead.
        self.stride = if stride == 0 { 1 } else { stride };
        self
    }

    /// The divisor [`Self::with_stride`] set. The elements one read asks for are
    /// `entries / stride`, rounded up, which is the number a cost is computed from.
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    /// How many elements the last read actually asked the kernel for.
    ///
    /// The cost of a read is exactly linear in this and in nothing else, so it is the number
    /// to look at when a reader costs more than expected, and the number a test asserts on to
    /// prove that a reader built for the named counters is not quietly walking fifty thousand
    /// slots.
    pub const fn walked(&self) -> usize {
        self.walked
    }

    pub const fn layout(&self) -> CounterLayout {
        self.layout
    }

    /// Walks the elements this read is due and returns one sum per slot.
    ///
    /// Allocates nothing. It stops at `layout.entries()` rather than at the end of the map: an
    /// array map is walked in index order from zero, so a bound on the count is a bound on the
    /// elements, and without it a reader built for a small map would read every element above
    /// it and throw the answers away — paying the full cost for a fraction of the data, which
    /// is the whole cost this reader exists to control.
    /// The sums the last completed pass left, without reading again. As `Mapped::last`.
    ///
    /// A pass in progress is not visible here: this reader accumulates into a separate buffer
    /// and publishes whole, so what a caller sees is always one coherent sweep and never half
    /// of two.
    pub fn last(&self) -> &[u64] {
        &self.sums
    }

    pub fn read(&mut self) -> io::Result<&[u64]> {
        let entries = self.layout.entries() as usize;
        // The window this read claims. Rounded up, so a stride that does not divide the map
        // still finishes a pass in `stride` reads rather than in one more.
        let window = entries.div_ceil(self.stride as usize);
        let start = self.next.min(entries);
        let end = (start + window).min(entries);
        self.walked = 0;

        // in_batch and out_batch are pointers to one key: the kernel resumes the walk from the
        // key it left off at, exclusive, and for an array map that key is the index. So `next`
        // and `token` say the same thing twice — `token` to the kernel, `next` to the
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

            // SAFETY: keys holds `batch` four-byte keys and values `batch` eight-byte values,
            // which is `count` keys and `count` values for the flat array of u64 this type's
            // constructor requires.
            let done = match unsafe { command(BPF_MAP_LOOKUP_BATCH, &mut attr) } {
                Ok(()) => false,
                // ENOENT is how the walk ends. The elements this call returned are valid
                // and there are no more; the count is written back either way.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => true,
                Err(err) => return Err(err),
            };

            let n = (attr.count as usize).min(self.keys.len());
            for (i, key) in self.keys[..n].iter().enumerate() {
                // The slot a flat index belongs to. The top of a stripe belongs to none:
                // the width is rounded up to a cache line, so the last few indices of a
                // stripe are padding nobody counts.
                let slot = (*key % self.layout.stripe) as usize;
                if slot < self.pending.len() {
                    // Accumulated and not assigned: one slot's total is the sum over every
                    // processor's stripe, and the stripes are reached at different points of
                    // the walk. Wrapping, because a counter that overflowed in the kernel
                    // wrapped there too and the sum should say the same thing.
                    self.pending[slot] = self.pending[slot].wrapping_add(self.values[i]);
                }
            }
            self.walked += n;
            // Advanced per call and not per read: it is what the next `in_batch` is judged
            // against, and a call that returned elements has moved the kernel's cursor
            // whether or not the window is finished.
            self.next = start + self.walked;

            if done {
                // The map ends here, so the pass is over — early, which means the map is
                // smaller than this reader was built for. Publishing is what makes the slots
                // it never reached read zero instead of some older number.
                self.publish();
                return Ok(&self.sums);
            }
            if n == 0 {
                return Err(io::Error::other(
                    "BPF_MAP_LOOKUP_BATCH returned no element and did not say the walk was over",
                ));
            }
        }
        if self.next >= entries {
            self.publish();
        }
        Ok(&self.sums)
    }

    /// Ends a pass: what it accumulated becomes what callers read, and the next pass starts
    /// from the beginning with nothing carried over.
    fn publish(&mut self) {
        self.sums.copy_from_slice(&self.pending);
        self.pending.fill(0);
        self.next = 0;
    }
}

/// Processors the kernel sizes the counter map for against processors that can run code, when
/// the first is larger — which is a cost multiplier nobody chose.
///
/// `bpf_get_smp_processor_id` can return any *possible* processor, so the map is striped for
/// all of them and both read paths sum all of them. A guest booted with more possible
/// processors than online ones therefore carries stripes that can never be written and pays to
/// read them: `stripe × 8` bytes of kernel memory each, and one element per stripe slot on the
/// batch path. It is fixed at boot — `maxcpus=`, or the hypervisor's hotplug window — and
/// nothing the agent does can change it, so it is said once and not exported.
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
