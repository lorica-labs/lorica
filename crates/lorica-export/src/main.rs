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

#[path = "../../loricad/src/store/blocklist/mod.rs"]
// The agent uses parts of the loader this tool does not, and the reverse. Sharing the module
// is the point; sharing it means each side leaves something unused.
#[allow(dead_code)]
mod blocklist;

use std::{
    fs::File,
    io::{BufWriter, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use lorica_common::Action;
use zerocopy::IntoBytes;

use blocklist::{
    Blocklist, Resident,
    binary::{Entry, Header, MAGIC, VERSION},
};

const USAGE: &str = "usage: lorica-export --in PATH --out PATH\n       \
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

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--in" => input = Some(PathBuf::from(value()?)),
            "--out" => output = Some(PathBuf::from(value()?)),
            "--verify" => verify = Some(PathBuf::from(value()?)),
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }

    match (input, output, verify) {
        (Some(input), Some(output), None) => export(&input, &output),
        (None, None, Some(file)) => report(&file),
        _ => bail!("either --in and --out, or --verify, and not a mixture\n{USAGE}"),
    }
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
