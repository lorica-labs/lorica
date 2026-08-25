//! The three things about a mapped blocklist that are not obvious, one test each.
//!
//! Linux only: `MAP_POPULATE`, `/proc/self/smaps_rollup` and `SIGBUS`-on-truncation are the
//! whole subject and none of them exists elsewhere. The module under test is included by
//! path, because an integration test cannot reach into a binary crate and a second copy of
//! the loader would be a second thing to keep true.

#![cfg(target_os = "linux")]

#[path = "../src/store/blocklist/mod.rs"]
#[allow(dead_code)]
mod blocklist;
mod support;

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use zerocopy::IntoBytes;

use support::{Scratch, filesystem, machine};

use blocklist::{
    Blocklist, Resident,
    binary::{ENTRY_BYTES, Entry, HEADER_BYTES, Header, MAGIC, VERSION},
};

/// The case the format exists for.
const TEN_MILLION: u32 = 10_000_000;

/// Entries written per `write_all`. Small enough that building the list never costs the
/// 80 MiB of anonymous heap the test is about to assert nobody is holding.
const CHUNK: usize = 8_192;

/// Stride between addresses. Odd, and 10 000 000 * 397 stays inside `u32`, so the addresses
/// are strictly increasing and the file is sorted by construction.
const STRIDE: u32 = 397;

/// `Action::Drop`, the verdict a blocklist line carries. Written as a byte because the file
/// stores a byte.
const DENY: u8 = 2;

/// Writes a blocklist file and returns the checksum of the addresses in it.
///
/// The checksum is what proves later that a mapping is still showing the content it was
/// opened on, rather than a length that would also match the replacement.
fn write_list(path: &Path, count: u32) -> u64 {
    let header = Header {
        magic: MAGIC,
        version: VERSION,
        count,
    };
    let file = File::create(path).expect("cannot create the blocklist file");
    let mut out = BufWriter::new(file);
    out.write_all(header.as_bytes())
        .expect("cannot write the header");

    let mut chunk = vec![
        Entry {
            addr: 0,
            prefix_len: 32,
            action: DENY,
            pad: [0; 2],
        };
        CHUNK
    ];
    let mut checksum = 0u64;
    let mut written = 0u32;
    while written < count {
        let take = (count - written).min(CHUNK as u32) as usize;
        for (offset, entry) in chunk[..take].iter_mut().enumerate() {
            entry.addr = (written + offset as u32).wrapping_mul(STRIDE);
            checksum = checksum.wrapping_add(u64::from(entry.addr));
        }
        out.write_all(chunk[..take].as_bytes())
            .expect("cannot write the entries");
        written += take as u32;
    }
    out.flush().expect("cannot flush the blocklist file");
    // **`fsync`, and it is not hygiene: without it the whole mapping reports as
    // `Private_Dirty`.** `smaps_account` counts a page as dirty when `PageDirty` is set on the
    // page-cache page, so a file that has been written and not yet written back maps as memory
    // the agent owns — measured at +79 612 KiB for this 78 125 KiB file on ext4. It is also
    // what `lorica-export` does before its `rename()`, so this is the exporter's discipline and
    // not the test's convenience.
    out.into_inner()
        .expect("cannot recover the file from the writer")
        .sync_all()
        .expect("cannot fsync the blocklist file");
    checksum
}

fn file_kib(count: u32) -> u64 {
    (HEADER_BYTES as u64 + u64::from(count) * ENTRY_BYTES as u64) / 1024
}

/// The RSS budget, read out of the script that enforces it rather than restated here.
///
/// A number copied from one file to another expires in silence; this project has watched it
/// happen twice. `scripts/lab/measure-agent-cpu.sh` is what fails a run in the lab, so it is
/// the one place the ceiling is written, and this test reads it.
fn rss_budget_kib() -> u64 {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lab/measure-agent-cpu.sh");
    let text = std::fs::read_to_string(&script)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", script.display()));
    text.lines()
        .filter_map(|line| line.strip_prefix("RSS_MAX="))
        .find_map(|value| value.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            panic!(
                "{} carries no RSS_MAX default, so this test has no budget to compare against",
                script.display()
            )
        })
}

#[test]
fn ten_million_cidr_load_stays_within_the_rss_budget() {
    let directory = Scratch::new("blocklist-budget");
    let path = directory.join("blocklist.bin");
    let checksum = write_list(&path, TEN_MILLION);
    let size_kib = file_kib(TEN_MILLION);

    // Read after the file is written, so what the writer's buffers cost is part of the
    // baseline and not part of the load.
    let before = Resident::read().expect("cannot read smaps_rollup");
    let list = Blocklist::load(&path).expect("cannot load the blocklist");
    // The entries are walked, because a budget measured on a mapping nobody read would be a
    // budget on a promise. This is also the only access pattern the loader permits: once,
    // in order, and never a lookup.
    let seen: u64 = list
        .entries()
        .iter()
        .map(|entry| u64::from(entry.addr))
        .fold(0, u64::wrapping_add);
    let after = Resident::read().expect("cannot read smaps_rollup");

    assert_eq!(list.len(), TEN_MILLION as usize);
    assert_eq!(seen, checksum, "the mapping does not hold what was written");

    let budget = rss_budget_kib();
    println!(
        "{} entries, {size_kib} KiB of file, on {}, {} on {}:\n  \
         rss {} -> {} KiB, anonymous {} -> {} KiB, private_dirty {} -> {} KiB, \
         file_backed {} -> {} KiB\n  budget {budget} KiB",
        TEN_MILLION,
        machine(),
        directory.path().display(),
        filesystem(directory.path()),
        before.rss_kib,
        after.rss_kib,
        before.anonymous_kib,
        after.anonymous_kib,
        before.private_dirty_kib,
        after.private_dirty_kib,
        before.file_backed_kib(),
        after.file_backed_kib(),
    );

    // The assertions are on the memory the agent owns, and that is the whole point of the
    // format. The visible RSS is over the budget and is *supposed* to be: those pages are
    // file-backed and clean, and the kernel takes them back when it needs them.
    assert!(
        after.anonymous_kib <= budget,
        "the load left {} KiB of anonymous memory, over the {budget} KiB budget: the entries \
         were copied somewhere instead of being mapped",
        after.anonymous_kib
    );
    // Private_Dirty is the stronger of the two and the one that catches a mapping which is not
    // evictable. On tmpfs this reached 79 600 KiB for this same file, because a tmpfs mapping is
    // shmem and shmem is dirty by nature — the format's argument only holds on a real
    // filesystem, and this is the assertion that says so.
    assert!(
        after.private_dirty_kib <= budget,
        "the load left {} KiB of private dirty memory, over the {budget} KiB budget: the \
         mapping is not clean file-backed memory the kernel can reclaim",
        after.private_dirty_kib
    );
    assert!(
        after.file_backed_kib() - before.file_backed_kib() >= size_kib * 4 / 5,
        "file-backed RSS grew by {} KiB for a {size_kib} KiB file, so MAP_POPULATE did not \
         populate and the first real read will fault synchronously on the runtime thread",
        after.file_backed_kib() - before.file_backed_kib()
    );
}

#[test]
fn smaps_rollup_separates_file_backed_from_private_dirty() {
    let directory = Scratch::new("blocklist-rollup");
    let path = directory.join("blocklist.bin");
    // Two million entries, 16 MiB: large enough that a mapping is unmistakable against the
    // noise of a test process, small enough to be a second test rather than a repeat.
    const ENTRIES: u32 = 2_000_000;
    write_list(&path, ENTRIES);
    let size_kib = file_kib(ENTRIES);

    let before = Resident::read().expect("cannot read smaps_rollup");
    assert!(
        before.rss_kib > 0 && before.anonymous_kib > 0 && before.private_dirty_kib > 0,
        "one of the three lines read as zero, which is what a missing line would look like: \
         {before:?}"
    );
    assert!(before.anonymous_kib <= before.rss_kib, "{before:?}");
    assert!(before.private_dirty_kib <= before.rss_kib, "{before:?}");

    let list = Blocklist::load(&path).expect("cannot load the blocklist");
    let touched: u64 = list
        .entries()
        .iter()
        .map(|entry| u64::from(entry.prefix_len))
        .sum();
    assert_eq!(touched, u64::from(ENTRIES) * 32);
    let after = Resident::read().expect("cannot read smaps_rollup");

    let file_growth = after.file_backed_kib() - before.file_backed_kib();
    let dirty_growth = after
        .private_dirty_kib
        .saturating_sub(before.private_dirty_kib);
    println!(
        "a {size_kib} KiB mapping on {}, {} on {}: file_backed +{file_growth} KiB, \
         private_dirty +{dirty_growth} KiB, rss +{} KiB",
        machine(),
        directory.path().display(),
        filesystem(directory.path()),
        after.rss_kib - before.rss_kib
    );

    assert!(
        file_growth >= size_kib * 9 / 10,
        "file_backed grew by {file_growth} KiB for a {size_kib} KiB mapping"
    );
    // The distinction is the whole reason the reading exists: a metric that reported RSS
    // alone would show this mapping as memory the agent will not give back, and it is not.
    assert!(
        dirty_growth < 1024,
        "private_dirty grew by {dirty_growth} KiB, so the mapping is being written to and is \
         not the clean file-backed memory this format claims"
    );
}

#[test]
fn truncation_under_a_live_mapping_raises_no_sigbus() {
    let directory = Scratch::new("blocklist-sigbus");
    let path = directory.join("blocklist.bin");
    // Half a megabyte of entries, so the replacement removes thousands of pages from under
    // the mapping and a mistake here is not a matter of luck.
    const BEFORE: u32 = 524_288;
    const AFTER: u32 = 1_024;
    let checksum = write_list(&path, BEFORE);

    let live = Blocklist::load(&path).expect("cannot load the blocklist");
    reload(&path, AFTER);

    // Every page of the live mapping, after the file it was opened on has been replaced by a
    // much shorter one. On a writer that truncated in place this line is where the process
    // dies on SIGBUS, which no `Result` anywhere can catch.
    let seen: u64 = live
        .entries()
        .iter()
        .map(|entry| u64::from(entry.addr))
        .fold(0, u64::wrapping_add);
    assert_eq!(
        seen, checksum,
        "the live mapping changed under the reload, so rename() did not preserve the inode"
    );
    assert_eq!(live.len(), BEFORE as usize);

    let fresh = Blocklist::load(&path).expect("cannot load the replacement");
    assert_eq!(
        fresh.len(),
        AFTER as usize,
        "the reload did not become visible to a new load"
    );
    println!(
        "on {}: {} entries read out of a mapping whose file had been replaced by a {} entry one, \
         no SIGBUS",
        machine(),
        live.len(),
        fresh.len()
    );
}

/// A hot reload, in the only form that is safe.
///
/// A new file, then `rename()`. The old inode stays whole for as long as a mapping holds it,
/// so a load already in progress finishes on the content it started with. Writing into the
/// existing file instead — `set_len` on the mapped path — truncates under the mapping and the
/// next read of a dropped page is `SIGBUS`, delivered to a process that has no handler and
/// cannot usefully have one.
fn reload(path: &Path, entries: u32) {
    let temporary = path.with_extension("tmp");
    write_list(&temporary, entries);
    std::fs::rename(&temporary, path).expect("cannot rename the replacement into place");
}
