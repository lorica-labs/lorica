//! Loading the operator's list, and why the win is the kind of page and not the clock.
//!
//! **`mmap` is not here because the call is fast.** 80 MiB of blocklist read into a `Vec` is
//! 80 MiB of anonymous heap: the allocator holds it after the load peak, and the kernel
//! cannot reclaim it under pressure at any price. The same 80 MiB mapped from a file is
//! file-backed and clean, so the kernel evicts it the moment it needs the memory and reads
//! it back if it is touched again. That is the whole argument, and it would still hold if
//! the call were slower than the 7.2 ms it measures warm.
//!
//! Three things about a mapping are not obvious, and each has a test of its own.
//!
//! **1. Mapped pages count in the RSS an operator sees.** `ps` will show 80 MiB and someone
//! will open a ticket. `/proc/self/smaps_rollup` is the only place the distinction lives, so
//! [`Resident`] reads it: `Private_Dirty` is what the agent really owns and what the budget
//! is about, `Rss - Anonymous` is the file-backed part the kernel can take back. There is no
//! `File` line in `smaps_rollup` — `Pss_File` exists and is a proportional share, not an
//! RSS — so the file-backed figure is a subtraction and is named as one.
//!
//! Two things break that accounting, and both were found by measuring rather than reasoning.
//! **The file must be on a real filesystem**: on tmpfs a mapping is shmem, which is dirty by
//! nature and swappable rather than evictable, and the same 76 MiB list reported +79 600 KiB
//! of `Private_Dirty` instead of +8. **And the file must have been `fsync`ed before it is
//! mapped**: `smaps_account` calls a page dirty when `PageDirty` is set on the page-cache
//! page, so a list written and not yet written back reports as memory the agent owns, by the
//! whole size of the file. `lorica-export` fsyncs before its `rename()`, which is therefore
//! not only a crash-consistency measure.
//!
//! **2. A page fault is synchronous.** On a `current_thread` runtime a cold fault blocks the
//! whole runtime, timer included, for the duration of a disk read. So the mapping is
//! populated at load with `MAP_POPULATE`, and **nothing is ever looked up through it**: the
//! entries are read once, in order, into whatever answers queries, and the mapping is
//! dropped. This type deliberately has no lookup — the absence is the guard.
//!
//! **3. A file truncated under a live mapping is `SIGBUS`, not an error return.** So a
//! reload writes a *new* file and `rename()`s it into place: the old inode stays whole for
//! as long as a mapping holds it, and the running load finishes reading what it started on.
//! `truncation_under_a_live_mapping_raises_no_sigbus` is what makes that a proven property
//! rather than an intention, and it fails loudly against a writer that truncates in place.

pub mod binary;

use std::{fs::File, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use memmap2::{Mmap, MmapOptions};
use zerocopy::FromBytes;

use binary::{ENTRY_BYTES, Entry, HEADER_BYTES, Header, MAGIC, VERSION};

/// A mapped blocklist file.
///
/// Dropping it unmaps. Nothing else releases it, because "read the entries then let it go"
/// is the only usage pattern the synchronous-fault argument permits, and a release method
/// would suggest there is another one.
pub struct Blocklist {
    map: Mmap,
    count: usize,
}

impl Blocklist {
    /// Maps the file and validates its header, populating every page before returning.
    ///
    /// Opened read-only and never for writing: the loader is one half of the `rename()`
    /// discipline and the half that must not be able to break it.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("cannot open the blocklist at {}", path.display()))?;
        let len = file
            .metadata()
            .with_context(|| format!("cannot stat {}", path.display()))?
            .len();
        if len < HEADER_BYTES as u64 {
            bail!(
                "{} is {len} bytes, shorter than the {HEADER_BYTES}-byte header",
                path.display()
            );
        }

        let mut options = MmapOptions::new();
        // MAP_POPULATE. Without it the first pass over the entries takes one synchronous
        // fault per page, on the runtime thread that also owns the timer. `madvise` with
        // MADV_WILLNEED would be the alternative and is strictly weaker: it is a hint the
        // kernel may drop, where MAP_POPULATE has already faulted the pages in when `map`
        // returns, which is the property the single-threaded runtime needs.
        options.populate();
        // SAFETY: the mapping is read-only and lives inside `Blocklist`, so no reference to
        // it outlives the map. The file may still be replaced under it — that is what the
        // `rename()` discipline is for, and a replaced file leaves this inode intact.
        let map = unsafe { options.map(&file) }
            .with_context(|| format!("cannot map {}", path.display()))?;

        let (header, _) = Header::ref_from_prefix(&map)
            .map_err(|err| anyhow!("cannot read the header of {}: {err}", path.display()))?;
        if header.magic != MAGIC {
            bail!(
                "{} does not begin with the blocklist magic; it was not written by lorica-export",
                path.display()
            );
        }
        if header.version != VERSION {
            bail!(
                "{} is format version {}, this build reads {VERSION}",
                path.display(),
                header.version
            );
        }
        let count = header.count as usize;
        let wanted = HEADER_BYTES + count * ENTRY_BYTES;
        if (len as usize) < wanted {
            bail!(
                "{} claims {count} entries, which needs {wanted} bytes, and holds {len}",
                path.display()
            );
        }

        // Cast once here, and throw the slice away. What is being bought is that
        // `entries()` cannot fail afterwards: a size or alignment complaint belongs to the
        // load, where there is a path to report it, and not to a getter in a loop.
        <[Entry]>::ref_from_bytes(&map[HEADER_BYTES..wanted])
            .map_err(|err| anyhow!("{} is not a well-formed entry array: {err}", path.display()))?;

        Ok(Self { map, count })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The entries, in the order the file holds them: ascending [`Entry::key`].
    pub fn entries(&self) -> &[Entry] {
        let wanted = HEADER_BYTES + self.count * ENTRY_BYTES;
        <[Entry]>::ref_from_bytes(&self.map[HEADER_BYTES..wanted])
            .expect("the size and the alignment were checked by load")
    }
}

/// The three `smaps_rollup` figures that separate memory the agent owns from memory the
/// kernel is lending it.
///
/// Produced here, exported nowhere: putting these on a metric is another task's, and this is
/// the reading it will call.
#[derive(Clone, Copy, Debug)]
pub struct Resident {
    pub rss_kib: u64,
    pub anonymous_kib: u64,
    pub private_dirty_kib: u64,
}

impl Resident {
    /// Reads `/proc/self/smaps_rollup`.
    ///
    /// A missing line is an error and never a zero. A budget assertion that silently
    /// compared against zero would pass for every process that ever ran.
    pub fn read() -> Result<Self> {
        let text = std::fs::read_to_string("/proc/self/smaps_rollup")
            .context("cannot read /proc/self/smaps_rollup")?;
        Ok(Self {
            rss_kib: field(&text, "Rss:")?,
            anonymous_kib: field(&text, "Anonymous:")?,
            private_dirty_kib: field(&text, "Private_Dirty:")?,
        })
    }

    /// The part of the RSS that is a file mapping, and therefore the part the kernel can
    /// evict without the agent's cooperation. A subtraction because `smaps_rollup` has no
    /// file-backed line to read.
    pub const fn file_backed_kib(&self) -> u64 {
        self.rss_kib.saturating_sub(self.anonymous_kib)
    }
}

fn field(text: &str, name: &str) -> Result<u64> {
    let line = text
        .lines()
        .find(|line| line.starts_with(name))
        .with_context(|| format!("/proc/self/smaps_rollup has no {name} line"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .with_context(|| format!("cannot read a kilobyte count out of {line:?}"))
}
