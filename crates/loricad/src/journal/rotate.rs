//! Appending records to a bounded set of files, and the one ordering that must not change.
//!
//! **The buffer is a `Vec<u8>` the writer owns and not a `BufWriter`, because rotation must
//! not allocate.** `BufWriter` allocates its buffer in `new`, so rotating would allocate on
//! the agent's timer thread — the one thread whose allocation count `tests/tick_budget.rs`
//! is written about. One buffer, reserved once in [`Writer::create`] and reused across every
//! file, allocates nothing after startup; the cost is that flushing it is this module's job
//! and not the standard library's, which is what makes [`Writer::rotate`] the one place in
//! the write path where a record can end up somewhere it does not belong.
//!
//! **So the ordering is the invariant: drain, then change files.** And the exact damage a
//! rotation that swaps first does was measured rather than assumed, because the obvious
//! guess is wrong. It does **not** lose the records: the buffer survives the swap and its
//! contents land in the *next* file, so a test that only counts records across every file
//! and checks their order passes against the broken version — which it did, 1 000 000 records
//! and 184 files, green. What it does is leave the file it closed short of [`Writer::limit`]
//! by whatever was pending, because those bytes were counted against that file's range and
//! written outside it. So the assertion that catches it is that **a closed file has reached
//! its limit**, and `rotation_loses_no_record` carries both: the count and the order, which
//! are what the journal is for, and the per-file completeness, which is what fails when the
//! ordering here is wrong.
//!
//! There is no `Drop` on [`Writer`], and that absence is deliberate: a `Drop` flush would
//! make the tail of a journal depend on whether the writer was dropped or the process died,
//! which is the difference [`Writer::flush`] exists to make explicit.
//!
//! Rotation does not `fsync` the file it closes. What it can lose is the buffer, not the
//! page cache, and an `fsync` per file would be a hardening cadence — which is
//! `store/state.rs`'s subject, measured there, and not something to re-decide here.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use zerocopy::{FromBytes, IntoBytes};

use super::record::{HEADER_BYTES, Header, MAGIC, RECORD_BYTES, Record, VERSION};

/// File name shape: the prefix, the sequence padded to six digits, the suffix. Padded so
/// the lexical order of the names is the chronological order of the files, which is what
/// lets [`files`] sort strings instead of parsing them.
const PREFIX: &str = "journal-";
const SUFFIX: &str = ".bin";

/// An append-only journal spread over rotating files.
pub struct Writer {
    dir: PathBuf,
    /// Bytes a file may reach, header included, before the next record opens a new one.
    limit: u64,
    /// Reserved once. `len` is what is pending, `capacity` is the ceiling and never grows.
    buffer: Vec<u8>,
    file: File,
    sequence: u32,
    /// Bytes already written to [`Self::file`]. Not the buffer's.
    written: u64,
}

impl Writer {
    /// Opens the next file in `dir`, creating the directory if it is absent.
    ///
    /// The sequence continues past the highest file already there rather than starting at
    /// zero, so an agent that restarts appends to the history instead of writing over it.
    pub fn create(dir: &Path, limit: u64, buffered_records: usize) -> Result<Self> {
        let smallest = (HEADER_BYTES + RECORD_BYTES) as u64;
        if limit < smallest {
            bail!("a limit of {limit} bytes cannot hold a header and one record ({smallest})");
        }
        if buffered_records == 0 {
            bail!("a buffer of zero records has nothing to drain and would write per record");
        }
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create the journal directory {}", dir.display()))?;

        let sequence = match files(dir)?.last() {
            Some(last) => {
                sequence_of(last)
                    .with_context(|| format!("cannot read the sequence of {}", last.display()))?
                    + 1
            }
            None => 0,
        };
        let file = open(dir, sequence)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            limit,
            buffer: Vec::with_capacity(buffered_records * RECORD_BYTES),
            file,
            sequence,
            written: HEADER_BYTES as u64,
        })
    }

    /// The file records are currently landing in.
    pub fn path(&self) -> PathBuf {
        path(&self.dir, self.sequence)
    }

    pub fn append(&mut self, record: &Record) -> Result<()> {
        if self.buffer.len() + RECORD_BYTES > self.buffer.capacity() {
            self.drain()?;
        }
        self.buffer.extend_from_slice(record.as_bytes());
        // Counted against what the file would hold once the buffer lands, not against what
        // it holds now: the alternative overshoots the limit by a whole buffer.
        if self.written + self.buffer.len() as u64 >= self.limit {
            self.rotate()?;
        }
        Ok(())
    }

    /// Drains the buffer and puts the current file on the disk.
    ///
    /// Not called from [`Self::append`] and not from a `Drop`. Whoever owns the writer calls
    /// it when it stops appending, which is the only moment at which "everything is on disk"
    /// is a statement about anything.
    pub fn flush(&mut self) -> Result<()> {
        self.drain()?;
        self.file
            .sync_all()
            .with_context(|| format!("cannot fsync {}", self.path().display()))
    }

    fn drain(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.file
            .write_all(&self.buffer)
            .with_context(|| format!("cannot append to {}", self.path().display()))?;
        self.written += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        // First, and the reason this module exists. Everything below changes which file
        // `drain` would write to.
        self.drain()?;
        self.sequence += 1;
        self.file = open(&self.dir, self.sequence)?;
        self.written = HEADER_BYTES as u64;
        Ok(())
    }
}

fn path(dir: &Path, sequence: u32) -> PathBuf {
    dir.join(format!("{PREFIX}{sequence:06}{SUFFIX}"))
}

/// Creates the file and writes its header, refusing to reopen one that exists.
///
/// `create_new`: a sequence that collided with a file already on disk would append records
/// after that file's records and behind a second header, which no reader can untangle.
fn open(dir: &Path, sequence: u32) -> Result<File> {
    let path = path(dir, sequence);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(Header::new().as_bytes())
        .with_context(|| format!("cannot write the header of {}", path.display()))?;
    Ok(file)
}

/// Every journal file in `dir`, oldest first.
pub fn files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", dir.display())),
    };
    for entry in entries {
        let path = entry
            .with_context(|| format!("cannot read an entry of {}", dir.display()))?
            .path();
        if sequence_of(&path).is_some() {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

/// `None` for anything that is not a journal file name, which is how [`files`] filters.
fn sequence_of(path: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    name.strip_prefix(PREFIX)?
        .strip_suffix(SUFFIX)?
        .parse()
        .ok()
}

/// Every record of one file, in order.
///
/// Copied out rather than cast in place, and the reason is alignment: a `Vec<u8>` from
/// `read` is aligned to one byte, and [`Record`] needs eight, so a cast would fail on the
/// alignment of a buffer nobody controls. `read_from_bytes` copies each record, which costs
/// a memcpy of the file in a tool whose peak nobody watches — the same trade
/// `lorica-export` already makes for the blocklist, in the same direction.
pub fn read(path: &Path) -> Result<Vec<Record>> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() < HEADER_BYTES {
        bail!(
            "{} is {} bytes, shorter than the {HEADER_BYTES}-byte header",
            path.display(),
            bytes.len()
        );
    }
    let header = Header::read_from_bytes(&bytes[..HEADER_BYTES])
        .map_err(|err| anyhow::anyhow!("cannot read the header of {}: {err}", path.display()))?;
    if header.magic != MAGIC {
        bail!(
            "{} does not begin with the journal magic; it was not written by loricad",
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
    if header.record_bytes as usize != RECORD_BYTES {
        bail!(
            "{} is written at a stride of {} bytes, this build reads {RECORD_BYTES}",
            path.display(),
            header.record_bytes
        );
    }

    let body = &bytes[HEADER_BYTES..];
    // A partial record at the end is the tail of a writer that died, and it is reported
    // rather than dropped: a journal that silently rounds down is a journal whose count
    // cannot be used as evidence of anything.
    let remainder = body.len() % RECORD_BYTES;
    if remainder != 0 {
        bail!(
            "{} ends with {remainder} bytes that are not a whole record",
            path.display()
        );
    }
    let mut records = Vec::with_capacity(body.len() / RECORD_BYTES);
    for chunk in body.chunks_exact(RECORD_BYTES) {
        records.push(
            Record::read_from_bytes(chunk)
                .map_err(|err| anyhow::anyhow!("{} holds a bad record: {err}", path.display()))?,
        );
    }
    Ok(records)
}
