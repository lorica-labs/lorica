//! Text in, binary out, and never on the startup path.
//!
//! **This tool exists to hold a peak.** Parsing ten million CIDR lines costs 563 ms and
//! 249 MiB of peak RSS — five times the agent's entire budget — so the parse happens here,
//! in a process whose peak nobody watches, and the agent maps 80 MiB of pre-sorted
//! `#[repr(C)]` records it never has to touch twice. Moving the parse rather than optimising
//! it is the whole design; a faster parser would still allocate ten million times.
//!
//! `--verify` is in the same binary on purpose: the tool that writes a file is the one that
//! proves the file loads, through the agent's own loader rather than a second reader that
//! could agree with the writer while both were wrong. It is also what
//! `scripts/lab/measure-blocklist-reload.sh` times, which keeps the campaign out of the test
//! harness.
//!
//! Both halves of the format are included by path rather than copied: one layout, one
//! loader, two crates.
//!
//! **Parquet lives here and not in the agent, and that is a size decision with numbers.**
//! `--to parquet` turns a journal into a file DuckDB, Polars or pandas can open, which is
//! what makes the fixed-size record a usable format rather than a private one. The writer it
//! needs is measured in the report for this change; whatever it weighs, it weighs it in a
//! process an operator starts and that exits, where the agent's budget does not apply. The
//! same weight inside `loricad` would be the whole argument of
//! `crates/loricad/src/journal/mod.rs` given away.

#[path = "../../loricad/src/store/blocklist/mod.rs"]
// The agent uses parts of the loader this tool does not, and the reverse. Sharing the module
// is the point; sharing it means each side leaves something unused.
#[allow(dead_code)]
mod blocklist;
#[path = "../../loricad/src/journal/mod.rs"]
mod journal;

use std::{
    fs::File,
    io::{BufWriter, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use lorica_common::Action;
use parquet::{
    data_type::{FixedLenByteArray, Int32Type, Int64Type},
    file::{
        properties::WriterProperties,
        writer::{SerializedFileWriter, SerializedRowGroupWriter},
    },
    schema::parser::parse_message_type,
};
use zerocopy::IntoBytes;

use blocklist::{
    Blocklist, Resident,
    binary::{Entry, Header, MAGIC, VERSION},
};
use journal::{record::Record, rotate};

const USAGE: &str = "usage: lorica-export --in PATH --out PATH\n       \
                     lorica-export --to parquet --in DIR --out PATH\n       \
                     lorica-export --verify PATH";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("lorica-export: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut verify: Option<PathBuf> = None;
    let mut to: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--in" => input = Some(PathBuf::from(value()?)),
            "--out" => output = Some(PathBuf::from(value()?)),
            "--verify" => verify = Some(PathBuf::from(value()?)),
            "--to" => to = Some(value()?),
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }

    match (input, output, verify, to.as_deref()) {
        (Some(input), Some(output), None, None) => export(&input, &output),
        (Some(input), Some(output), None, Some("parquet")) => parquet(&input, &output),
        (_, _, _, Some(other)) => bail!("--to {other} is not a format this tool writes\n{USAGE}"),
        (None, None, Some(file), None) => report(&file),
        _ => bail!("either --in and --out, or --verify, and not a mixture\n{USAGE}"),
    }
}

/// The Parquet schema, and the reason every integer carries an unsigned annotation.
///
/// A journal record is unsigned throughout, and `deadline` reaches `u64::MAX` — that is
/// `Deadline::never()`, which rung zero writes on every quiet second, so it is the common
/// value and not an edge case. Written as a plain `int64` it would read as `-1` in every
/// query engine that opens the file. `INTEGER(64,false)` is the annotation that makes the
/// same bits read back as what they are.
///
/// The column order is the order the row groups are written in below, and Parquet has no
/// other way to match them up.
const SCHEMA: &str = "message journal_second {
  required int64 at_ns (INTEGER(64,false));
  required int32 tier (INTEGER(8,false));
  required int32 reason (INTEGER(8,false));
  required int32 prefix_len (INTEGER(8,false));
  required fixed_len_byte_array(16) addr;
  required int64 rate (INTEGER(64,false));
  required int64 deadline (INTEGER(64,false));
}";

/// Converts a journal directory into one Parquet file.
///
/// **One row group per journal file, which is what rotation already bounds.** A row group is
/// held in memory until it is written, so its size has to be bounded by something; the
/// alternative is a row count picked here, which would be a second bound competing with the
/// one the agent's `--journal-limit` already sets. The seven columns are built as seven
/// vectors of one journal file's records, which is a few megabytes at any sane limit.
fn parquet(input: &Path, output: &Path) -> Result<()> {
    let paths = rotate::files(input)?;
    if paths.is_empty() {
        bail!(
            "{} holds no journal file; the agent names them journal-NNNNNN.bin",
            input.display()
        );
    }
    let schema = Arc::new(parse_message_type(SCHEMA).context("the schema does not parse")?);
    let file =
        File::create(output).with_context(|| format!("cannot create {}", output.display()))?;
    let mut writer = SerializedFileWriter::new(file, schema, Arc::new(WriterProperties::new()))
        .context("cannot start the Parquet file")?;

    let mut rows = 0u64;
    let mut groups = 0u64;
    for path in &paths {
        let records = rotate::read(path)?;
        // A file that holds only its header is the one a rotation opened and nothing reached
        // yet. An empty row group is legal and useless, and some readers refuse it.
        if records.is_empty() {
            continue;
        }
        let mut group = writer
            .next_row_group()
            .context("cannot start a row group")?;
        columns(&mut group, &records)?;
        group.close().context("cannot close a row group")?;
        rows += records.len() as u64;
        groups += 1;
    }
    let metadata = writer.close().context("cannot close the Parquet file")?;

    println!(
        "{} rows, {} row groups, {} journal files, {} bytes, {}",
        metadata.file_metadata().num_rows(),
        groups,
        paths.len(),
        std::fs::metadata(output)
            .with_context(|| format!("cannot stat {}", output.display()))?
            .len(),
        output.display()
    );
    if metadata.file_metadata().num_rows() != rows as i64 {
        bail!(
            "the footer claims {} rows and {rows} were written",
            metadata.file_metadata().num_rows()
        );
    }
    Ok(())
}

/// The seven columns of one row group, in the order [`SCHEMA`] declares them.
///
/// The unsigned-to-signed casts are the bit pattern and not a conversion, which is what the
/// `INTEGER(n,false)` annotations in the schema tell the reader to expect.
fn columns(group: &mut SerializedRowGroupWriter<'_, File>, records: &[Record]) -> Result<()> {
    let addresses: Vec<FixedLenByteArray> = records
        .iter()
        .map(|record| FixedLenByteArray::from(record.addr.to_vec()))
        .collect();
    let int64s = [
        records.iter().map(|r| r.at_ns as i64).collect::<Vec<_>>(),
        records.iter().map(|r| r.rate as i64).collect(),
        records.iter().map(|r| r.deadline as i64).collect(),
    ];
    let int32s = [
        records
            .iter()
            .map(|r| i32::from(r.tier))
            .collect::<Vec<_>>(),
        records.iter().map(|r| i32::from(r.reason)).collect(),
        records.iter().map(|r| i32::from(r.prefix_len)).collect(),
    ];

    write_column::<Int64Type>(group, &int64s[0])?;
    write_column::<Int32Type>(group, &int32s[0])?;
    write_column::<Int32Type>(group, &int32s[1])?;
    write_column::<Int32Type>(group, &int32s[2])?;
    write_column::<parquet::data_type::FixedLenByteArrayType>(group, &addresses)?;
    write_column::<Int64Type>(group, &int64s[1])?;
    write_column::<Int64Type>(group, &int64s[2])?;
    Ok(())
}

fn write_column<T: parquet::data_type::DataType>(
    group: &mut SerializedRowGroupWriter<'_, File>,
    values: &[T::T],
) -> Result<()> {
    let mut column = group
        .next_column()
        .context("cannot open a column")?
        .context("the row group has fewer columns than the schema declares")?;
    column
        .typed::<T>()
        .write_batch(values, None, None)
        .context("cannot write a column")?;
    column.close().context("cannot close a column")
}

/// Converts a text list into the binary form.
///
/// One entry per line, `PREFIX` or `PREFIX allow|deny`, `#` starting a comment. The two
/// action words are the ones the operator configuration already uses, so nobody has to learn
/// a second vocabulary for the same decision; `deny` is the default because a list with no
/// verdict on it is a blocklist.
fn export(input: &Path, output: &Path) -> Result<()> {
    let text = std::fs::read_to_string(input)
        .with_context(|| format!("cannot read {}", input.display()))?;

    let mut entries: Vec<Entry> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        entries.push(parse(line).with_context(|| format!("{}:{}", input.display(), number + 1))?);
    }

    // Sorted here so the agent never has to. `sort_unstable_by_key` because the key is total
    // over what survives the duplicate check below.
    entries.sort_unstable_by_key(Entry::key);
    if let Some(pair) = entries
        .windows(2)
        .find(|pair| pair[0].key() == pair[1].key())
    {
        let addr = Ipv4Addr::from(pair[0].addr);
        bail!(
            "{addr}/{} appears twice; two verdicts on one prefix is a decision the operator \
             has to make, not one this tool can pick",
            pair[0].prefix_len
        );
    }

    let count = u32::try_from(entries.len())
        .with_context(|| format!("{} entries does not fit the header count", entries.len()))?;

    // Written beside the target and renamed onto it. An agent mapping the old file keeps a
    // whole inode, where writing in place would truncate under its mapping and kill it with
    // SIGBUS. This is the writing half of that discipline and the only place it can live.
    let temporary = output.with_extension("tmp");
    let header = Header {
        magic: MAGIC,
        version: VERSION,
        count,
    };
    {
        let file = File::create(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        let mut out = BufWriter::new(file);
        out.write_all(header.as_bytes())
            .context("cannot write the header")?;
        out.write_all(entries.as_bytes())
            .context("cannot write the entries")?;
        out.flush().context("cannot flush the entries")?;
        // fsync before the rename: a rename that lands before the data is on disk gives the
        // agent a valid name over an incomplete file, which is the one failure this
        // discipline exists to prevent.
        out.into_inner()
            .context("cannot recover the file from the writer")?
            .sync_all()
            .context("cannot fsync the entries")?;
    }
    std::fs::rename(&temporary, output).with_context(|| {
        format!(
            "cannot rename {} onto {}",
            temporary.display(),
            output.display()
        )
    })?;

    println!(
        "{} entries, {} bytes, {}",
        count,
        std::fs::metadata(output)
            .with_context(|| format!("cannot stat {}", output.display()))?
            .len(),
        output.display()
    );
    Ok(())
}

fn parse(line: &str) -> Result<Entry> {
    let mut fields = line.split_whitespace();
    let prefix = fields.next().context("an empty line reached the parser")?;
    let action = match fields.next() {
        None | Some("deny") => Action::Drop,
        Some("allow") => Action::Allow,
        Some(other) => {
            bail!("{other} is not an action; the configuration spells them allow and deny")
        }
    };
    if let Some(extra) = fields.next() {
        bail!("{extra} follows the action, and a line carries a prefix and an action");
    }

    let (addr, prefix_len) = match prefix.split_once('/') {
        // A bare address is a single host, which is how the configuration reads it too.
        None => (address(prefix)?, 32u8),
        Some((addr, len)) => (
            address(addr)?,
            len.parse::<u8>()
                .with_context(|| format!("{len} is not a prefix length"))?,
        ),
    };
    if prefix_len > 32 {
        bail!("/{prefix_len} is longer than an IPv4 address");
    }

    // Refused rather than masked. An operator who wrote 10.0.0.1/24 meant one of two things
    // and this tool cannot tell which, and clearing the bits silently would widen a rule.
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    if addr & !mask != 0 {
        bail!(
            "{}/{prefix_len} has bits set below the prefix; write {}/{prefix_len}",
            Ipv4Addr::from(addr),
            Ipv4Addr::from(addr & mask)
        );
    }

    Ok(Entry {
        addr,
        prefix_len,
        action: action as u8,
        pad: [0; 2],
    })
}

fn address(text: &str) -> Result<u32> {
    match Ipv4Addr::from_str(text) {
        Ok(addr) => Ok(addr.to_bits()),
        Err(_) if text.contains(':') => bail!(
            "{text} is IPv6; the flat tables are IPv4 and IPv6 prefixes stay in the LPM_TRIE, \
             so they do not belong in this file"
        ),
        Err(err) => bail!("{text} is not an IPv4 address: {err}"),
    }
}

/// Maps the file through the agent's loader, walks it once, and reports what that cost.
///
/// The scan is separate from the map because they answer different questions: the map is
/// what `MAP_POPULATE` pays for up front, the scan is what the builder will pay to copy the
/// entries out. The RSS figures are printed on both sides, because the number worth having is
/// the difference and the sign of it — file-backed grows, private-dirty does not.
fn report(file: &Path) -> Result<()> {
    let before = Resident::read()?;

    let at = Instant::now();
    let list = Blocklist::load(file)?;
    let map_us = at.elapsed().as_micros();

    let at = Instant::now();
    let entries = list.entries();
    let mut sorted = true;
    let mut checksum = 0u64;
    let mut previous = None;
    for entry in entries {
        if previous.is_some_and(|key| key >= entry.key()) {
            sorted = false;
        }
        previous = Some(entry.key());
        checksum = checksum.wrapping_add(u64::from(entry.addr));
    }
    let scan_us = at.elapsed().as_micros();

    let after = Resident::read()?;
    println!(
        concat!(
            "{{\"file\": \"{}\", \"entries\": {}, \"sorted\": {}, \"checksum\": {}, ",
            "\"map_us\": {}, \"scan_us\": {}, ",
            "\"rss_kib_before\": {}, \"rss_kib_after\": {}, ",
            "\"anonymous_kib_before\": {}, \"anonymous_kib_after\": {}, ",
            "\"private_dirty_kib_before\": {}, \"private_dirty_kib_after\": {}, ",
            "\"file_backed_kib_before\": {}, \"file_backed_kib_after\": {}}}"
        ),
        file.display(),
        entries.len(),
        sorted,
        checksum,
        map_us,
        scan_us,
        before.rss_kib,
        after.rss_kib,
        before.anonymous_kib,
        after.anonymous_kib,
        before.private_dirty_kib,
        after.private_dirty_kib,
        before.file_backed_kib(),
        after.file_backed_kib(),
    );
    if !sorted {
        bail!(
            "{} is not sorted; the agent's loader trusts the order",
            file.display()
        );
    }
    Ok(())
}
