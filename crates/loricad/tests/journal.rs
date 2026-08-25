//! What the journal has to be true about, one test each.
//!
//! Linux only, and not incidentally: three of the four numbers printed here are a page
//! accounting or a filesystem figure, and the fourth is a throughput against a named disk.
//! The module under test is included by path, because an integration test cannot reach into
//! a binary crate and a second copy of the record layout would be a second thing to keep
//! true — which for a format is the failure that produces a wrong answer with nothing
//! reporting it.
//!
//! `Resident` comes from the blocklist loader by the same inclusion. The reading that
//! separates memory the agent owns from memory the kernel is lending it is written once in
//! this repository, and a journal test that reimplemented it would be measuring its own copy.

#![cfg(target_os = "linux")]

#[path = "../src/store/blocklist/mod.rs"]
#[allow(dead_code)]
mod blocklist;
#[path = "../src/journal/mod.rs"]
mod journal;
// Shared with the other persistence tests, which use parts of it this one does not. The
// allowance is on the declaration rather than in the file, so the file stays what the other
// tests wrote.
#[allow(dead_code)]
mod support;

use std::{hint::black_box, path::PathBuf, time::Instant};

use lorica_common::{Deadline, LpmKey};
use lorica_detect::{Confirmation, Decision, Reason, Tier};
use zerocopy::IntoBytes;

use blocklist::Resident;
use journal::{
    Rollup,
    record::{HEADER_BYTES, NANOS_PER_SEC, REASON_CONFIRMED, RECORD_BYTES, Record},
    rotate::{Writer, files, read},
};
use support::{Scratch, filesystem, machine};

/// Records the rotation test writes. Forty-eight megabytes at the fixed stride, which is
/// enough for a throughput figure to be about the disk and the buffer rather than about the
/// first page fault.
const RECORDS: u64 = 1_000_000;

/// Bytes a journal file may reach. Small on purpose: the property under test is that
/// rotation loses nothing, so the test wants many rotations and not a realistic file size.
const LIMIT: u64 = 256 * 1024;

/// Records the writer buffers. Chosen so that a rotation always arrives with a partially
/// filled buffer — 21 records pending at every rotation with this limit — because a rotation
/// that arrives on an empty buffer cannot lose anything and would prove nothing.
const BUFFERED: usize = 64;

/// What the roll-up's share of a core is asserted against, at the agent's default cadence.
///
/// The figure this was written against; the measurement is printed with every run and is
/// three orders of magnitude under it, which is the point — the roll-up is an integer
/// comparison and a field assignment, and the reason to assert a budget at all is that a
/// future roll-up which started allocating or formatting would cross this without anyone
/// looking at the number.
const CORE_SHARE_LIMIT: f64 = 0.0012;

/// The cadence the share is computed at: `--hz` defaults to 10 in `main.rs`. Also the number
/// of ticks a second holds, which is what makes [`rung`]'s period a second's worth.
const HZ: u64 = 10;

/// Ticks the roll-up measurement folds in.
const TICKS: u64 = 2_000_000;

/// Where `the_export_reads_back_the_count_that_was_written` leaves its journal when it is
/// asked to, so the Parquet proof can run against a real one.
///
/// A knob and not a fixture: the third-party half of that proof is a query engine reading
/// the exported file, which belongs outside the test harness for the same reason
/// `scripts/lab/measure-blocklist-reload.sh` does. Unset, the test cleans up after itself.
const KEEP: &str = "LORICA_JOURNAL_DIR";

/// The test the module exists for: every record written comes back, once, in order, and in
/// the file whose byte range it was counted against.
///
/// **The third clause is there because the first two do not catch the bug.** A rotation that
/// changes files before draining does not throw the buffer away — the buffer outlives the
/// swap and its contents land in the next file — so the count and the order survive it, and
/// this test passed against the broken version. What the broken version leaves behind is a
/// closed file that stopped short of [`LIMIT`]: those bytes were counted against its range
/// and written outside it. Hence the length assertion below, which is the one that fails.
///
/// The records are regenerated rather than remembered. A `Vec` of a million expectations is
/// 48 MB of anonymous heap, which would make the RSS figure printed below a figure about the
/// test's own bookkeeping.
#[test]
fn rotation_loses_no_record() {
    let scratch = Scratch::new("journal-rotation");
    let dir = scratch.join("journal");

    let before = Resident::read().expect("cannot read smaps_rollup");
    let mut writer = Writer::create(&dir, LIMIT, BUFFERED).expect("cannot create the journal");
    let at = Instant::now();
    for index in 0..RECORDS {
        writer
            .append(&synthetic(index))
            .expect("cannot append a record");
    }
    writer.flush().expect("cannot flush the journal");
    let elapsed = at.elapsed();
    // Read before the verification below allocates anything of its own.
    let after = Resident::read().expect("cannot read smaps_rollup");

    let paths = files(&dir).expect("cannot list the journal files");
    let mut index = 0u64;
    for path in &paths {
        for record in read(path).expect("cannot read a journal file") {
            assert_eq!(
                record,
                synthetic(index),
                "record {index} came back changed, from {}",
                path.display()
            );
            index += 1;
        }
    }

    let per_sec = RECORDS as f64 / elapsed.as_secs_f64();
    println!(
        "{}: {} records, {} files, {:.1} ms, {:.2} M records/s, {:.1} MB/s, \
         RSS {} -> {} KiB (+{}), anonymous +{} KiB, {} on {}, {} profile",
        machine(),
        index,
        paths.len(),
        elapsed.as_secs_f64() * 1e3,
        per_sec / 1e6,
        per_sec * RECORD_BYTES as f64 / 1e6,
        before.rss_kib,
        after.rss_kib,
        after.rss_kib.saturating_sub(before.rss_kib),
        after.anonymous_kib.saturating_sub(before.anonymous_kib),
        dir.display(),
        filesystem(&dir),
        profile(),
    );

    assert_eq!(
        index, RECORDS,
        "the journal came back short of what was written"
    );
    assert!(
        paths.len() > 100,
        "{} files is too few rotations for this to be a test of rotation",
        paths.len()
    );
    // Every file but the one still open. A rotation happens on the append that takes a file
    // to its limit and drains first, so a closed file is at or over the limit by exactly the
    // pending buffer — and under the limit by exactly the buffer that was not drained.
    for path in &paths[..paths.len() - 1] {
        let len = std::fs::metadata(path)
            .expect("cannot stat a journal file")
            .len();
        assert!(
            len >= LIMIT,
            "{} closed at {len} bytes, {} short of the {LIMIT} it was rotated at: \
             the bytes counted against it were written to another file",
            path.display(),
            LIMIT - len
        );
    }
}

/// The roll-up's arithmetic, and what it costs at the agent's cadence.
///
/// Both halves in one test because the cost is only interesting if the thing being timed is
/// the thing that is correct: a roll-up that emitted nothing would be free. So the assertions
/// are that every second produces exactly one record, that the record carries the worst rung
/// of its second and not the last, and only then that the whole fold fits in
/// [`CORE_SHARE_LIMIT`] of a core.
#[test]
fn second_rollup_fits_in_its_share_of_a_core() {
    // The worst rung of every second, computed once. [`rung`]'s period is a second's worth of
    // ticks, so this is the same for each of them — and it is not the rung of a second's last
    // tick, which is what makes the assertion below discriminate between "worst of" and
    // "last of".
    let worst = (0..HZ).map(|tick| rung(tick).rung()).max().unwrap();
    assert_ne!(
        worst,
        rung(HZ - 1).rung(),
        "the pattern cannot tell the two rules apart"
    );

    let mut rollup = Rollup::default();
    let mut emitted = 0u64;

    let at = Instant::now();
    for tick in 0..TICKS {
        let at_ns = tick * (NANOS_PER_SEC / HZ);
        let decision = decision(rung(tick));
        if let Some(record) = rollup.observe(black_box(at_ns), black_box(&decision)) {
            assert_eq!(
                record.tier, worst,
                "the roll-up kept a rung that was not the worst"
            );
            assert_eq!(record.reason, REASON_CONFIRMED);
            assert_eq!(
                record.at_ns % NANOS_PER_SEC,
                0,
                "at_ns is not a second boundary"
            );
            emitted += 1;
            black_box(record);
        }
    }
    let elapsed = at.elapsed();
    // The second still open has not been reported, which is exactly the one record `close`
    // owes a shutdown.
    assert!(
        rollup.close().is_some(),
        "the open second was already emitted"
    );

    let per_tick = elapsed.as_secs_f64() / TICKS as f64;
    let share = per_tick * HZ as f64;
    println!(
        "{}: {} ticks, {} seconds emitted, {:.1} ns per tick, {:.6} % of a core at {} Hz, \
         {:.4} % at 1000 Hz, worst rung {}, {} profile",
        machine(),
        TICKS,
        emitted,
        per_tick * 1e9,
        share * 100.0,
        HZ,
        per_tick * 1000.0 * 100.0,
        worst,
        profile(),
    );

    assert_eq!(
        emitted,
        TICKS / HZ - 1,
        "a second was dropped or a tick emitted twice"
    );
    assert!(
        share <= CORE_SHARE_LIMIT,
        "the roll-up takes {:.4} % of a core at {HZ} Hz, over the {:.4} % budget",
        share * 100.0,
        CORE_SHARE_LIMIT * 100.0
    );
}

/// The count `lorica-export` will put in the Parquet file, through the code path it uses.
///
/// The export's row count is `files()` then `read()` per file, summed — this test is that
/// sum against a known number, across a rotation, so a Parquet row count that disagrees with
/// it is the writer's fault and not the journal's. The third-party half is a query engine
/// opening the exported file, which is a step outside the harness: set [`KEEP`] to a
/// directory and this test leaves a journal there for `--to parquet` to convert.
#[test]
fn the_export_reads_back_the_count_that_was_written() {
    let scratch = Scratch::new("journal-export");
    let (dir, keep) = match std::env::var_os(KEEP) {
        Some(path) => (PathBuf::from(path), true),
        None => (scratch.join("journal"), false),
    };
    let _ = std::fs::remove_dir_all(&dir);

    // Enough seconds to cross the limit several times, so the count is a count over a set of
    // files and not over one.
    let seconds = 40_000u64;
    let mut rollup = Rollup::default();
    let mut writer = Writer::create(&dir, LIMIT, BUFFERED).expect("cannot create the journal");
    let mut appended = 0u64;
    for tick in 0..seconds * HZ {
        let at_ns = tick * (NANOS_PER_SEC / HZ);
        if let Some(record) = rollup.observe(at_ns, &decision(rung(tick))) {
            writer.append(&record).expect("cannot append a record");
            appended += 1;
        }
    }
    if let Some(record) = rollup.close() {
        writer
            .append(&record)
            .expect("cannot append the open second");
        appended += 1;
    }
    writer.flush().expect("cannot flush the journal");

    let paths = files(&dir).expect("cannot list the journal files");
    let counted: u64 = paths
        .iter()
        .map(|path| read(path).expect("cannot read a journal file").len() as u64)
        .sum();
    // The same count derived from the file lengths alone, which is what the fixed stride is
    // for and what a reader that does not trust this build would compute.
    let from_lengths: u64 = paths
        .iter()
        .map(|path| {
            let len = std::fs::metadata(path)
                .expect("cannot stat a journal file")
                .len();
            (len - HEADER_BYTES as u64) / RECORD_BYTES as u64
        })
        .sum();

    println!(
        "{}: {appended} records appended, {counted} read back, {from_lengths} from the file \
         lengths, {} files, {} {}",
        machine(),
        paths.len(),
        dir.display(),
        if keep { "kept" } else { "removed" },
    );

    assert_eq!(counted, appended, "the reader disagrees with the writer");
    assert_eq!(
        from_lengths, appended,
        "the stride disagrees with the reader"
    );
    assert_eq!(
        appended, seconds,
        "one record per second is the whole roll-up"
    );
    assert!(paths.len() > 1, "the count did not cross a rotation");
    if !keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A record is forty-eight bytes on the disk, and all forty-eight come back.
///
/// The padding is the part worth asserting. It is a named field so `IntoBytes` will accept
/// the type, which means it is written, which means a build that stopped initialising it
/// would put whatever was on the stack into the file — and two runs of the same agent would
/// then produce journals that differ in bytes nobody reads. So the test writes a record whose
/// padding is deliberately not zero and requires those bytes back: the format carries the
/// padding, it does not normalise it.
#[test]
fn a_fixed_size_record_survives_the_disk_bit_for_bit() {
    let scratch = Scratch::new("journal-roundtrip");
    let dir = scratch.join("journal");

    let plain = synthetic(7);
    let marked = Record {
        pad: [0xde, 0xad, 0xbe, 0xef, 0x5a],
        ..synthetic(8)
    };
    let mut writer = Writer::create(&dir, LIMIT, BUFFERED).expect("cannot create the journal");
    writer.append(&plain).expect("cannot append");
    writer.append(&marked).expect("cannot append");
    writer.flush().expect("cannot flush");
    let path = writer.path();
    drop(writer);

    let bytes = std::fs::read(&path).expect("cannot read the journal file");
    assert_eq!(
        bytes.len(),
        HEADER_BYTES + 2 * RECORD_BYTES,
        "the file is not a header plus two strides"
    );

    let back = read(&path).expect("cannot read the records");
    assert_eq!(back.len(), 2);
    assert_eq!(back[0], plain, "the first record changed");
    assert_eq!(back[1], marked, "the second record changed");
    assert_eq!(back[1].pad, marked.pad, "the padding was normalised");
    assert_eq!(back[0].pad, [0; 5], "an untouched padding is not zero");

    // The stride, read off the file rather than off `size_of`: record one begins where the
    // header ends and record two exactly a stride later.
    for (index, record) in back.iter().enumerate() {
        let start = HEADER_BYTES + index * RECORD_BYTES;
        let raw = record.as_bytes();
        assert_eq!(
            &bytes[start..start + RECORD_BYTES],
            raw,
            "record {index} does not sit at its stride"
        );
    }

    println!(
        "{}: {} bytes, header {HEADER_BYTES}, stride {RECORD_BYTES}, padding carried, {} on {}",
        machine(),
        bytes.len(),
        path.display(),
        filesystem(&dir),
    );
}

/// A record whose every field depends on the index, so a swapped, dropped or duplicated one
/// is caught by value and not only by count.
fn synthetic(index: u64) -> Record {
    let octets = (index as u32).to_be_bytes();
    let key = LpmKey::host_v4(octets);
    Record {
        at_ns: index * NANOS_PER_SEC,
        rate: index * 977,
        deadline: index + 1,
        addr: key.addr,
        prefix_len: key.prefix_len as u8,
        tier: (index % 7) as u8,
        reason: REASON_CONFIRMED,
        pad: [0; 5],
    }
}

/// A confirmed decision on a fixed key. Confirmed because it is the only reason a dropping
/// rung is allowed to rest on, so one shape of reason covers every rung the ladder has.
fn decision(tier: Tier) -> Decision {
    Decision::new(
        tier,
        Reason::Confirmed {
            key: LpmKey::host_v4([203, 0, 113, 7]),
            by: Confirmation::ExactKey,
            per_sec: 41_000,
        },
        Deadline(600),
    )
    .expect("a confirmed reason carries the exact key every rung needs")
}

/// The rung of a tick. One period is a second's worth of ticks at [`HZ`], and the walk peaks
/// in the middle so that a second's worst rung is never its last tick's.
fn rung(tick: u64) -> Tier {
    match tick % HZ {
        0 | 9 => Tier::Observe,
        1 | 8 => Tier::Mark,
        2 | 7 => Tier::Limit,
        3 => Tier::DropSurgical,
        4 => Tier::DropBroad,
        _ => Tier::Rtbh,
    }
}

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}
