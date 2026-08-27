//! Three throwaway measurements, none of which the product has to carry: how a
//! redb file grows under a prolonged `Durability::None`, what a cold mmap of a
//! binary blocklist really costs, and whether an allocator's retention policy
//! makes RSS lie after the load peak.

use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use redb::{Database, Durability, TableDefinition};

/// A blocklist record is a prefix plus its metadata; 16 bytes is an IPv6 /128
/// with nothing to spare, which is the smallest honest value size.
const ENTRY_BYTES: usize = 16;

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("entries");

#[derive(Parser)]
#[command(about = "Persistence probes: redb growth, cold blocklist load, allocator retention")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// redb file growth under a prolonged Durability::None. Runs for days: detach it.
    Growth(GrowthArgs),
    /// Cost of loading a binary blocklist by mmap with the page cache evicted.
    ColdLoad(ColdLoadArgs),
    /// Whether RSS comes back down after the load peak, per allocator.
    AllocMmap(AllocArgs),
}

#[derive(Args)]
struct GrowthArgs {
    /// Fractional so the probe can be smoke-tested in seconds before it is
    /// detached for days.
    #[arg(long, default_value_t = 48.0)]
    hours: f64,
    #[arg(long)]
    out: PathBuf,
    /// The agent's tick. One Durability::None commit per tick.
    #[arg(long, default_value_t = 100)]
    tick_ms: u64,
    #[arg(long, default_value_t = 10)]
    durable_every_s: u64,
    #[arg(long, default_value_t = 12.0)]
    compact_every_h: f64,
    #[arg(long, default_value_t = 64)]
    entries_per_tick: u64,
    /// Entries kept before the oldest is dropped. Removals are what free pages,
    /// and free pages that no durable commit reclaims are the whole question.
    #[arg(long, default_value_t = 65536)]
    window_entries: u64,
    #[arg(long, default_value_t = 60)]
    sample_every_s: u64,
    /// fsync p99 of the target's virtual disk, from docs/mesures/05-stockage.md.
    /// A declared parameter, never re-measured here: durable commits slower than
    /// it are counted, so the cadence is judged against a known disk.
    #[arg(long, default_value_t = 6.26)]
    fsync_p99_ms: f64,
    /// A detached run that fills the target's disk is worse than a late number.
    #[arg(long, default_value_t = 4096)]
    max_file_mb: u64,
}

#[derive(Args)]
struct ColdLoadArgs {
    #[arg(long, value_parser = parse_size, default_value = "80M")]
    size: u64,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct AllocArgs {
    #[arg(long, value_enum, default_value = "both")]
    allocator: Allocator,
    #[arg(long, value_parser = parse_size, default_value = "80M")]
    size: u64,
    #[arg(long, value_parser = parse_size, default_value = "64K")]
    chunk: u64,
    /// How long RSS is watched after everything has been freed.
    #[arg(long, default_value_t = 20)]
    settle_s: u64,
    #[arg(long, default_value_t = 100)]
    tick_ms: u64,
    /// jemalloc dirty_decay_ms and muzzy_decay_ms, both set to this.
    #[arg(long, default_value_t = 10000)]
    decay_ms: i64,
    /// Watch the decay policy alone: no mi_collect, no jemalloc decay on the tick.
    #[arg(long)]
    no_collect: bool,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Allocator {
    Jemalloc,
    Mimalloc,
    Both,
}

impl Allocator {
    fn as_str(self) -> &'static str {
        match self {
            Allocator::Jemalloc => "jemalloc",
            Allocator::Mimalloc => "mimalloc",
            Allocator::Both => "both",
        }
    }
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().mode {
        Mode::Growth(a) => growth(&a),
        Mode::ColdLoad(a) => cold_load(&a),
        Mode::AllocMmap(a) => alloc_mmap(&a),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("store-probe: {e}");
            ExitCode::FAILURE
        }
    }
}

// ----------------------------------------------------------------- growth

fn growth(a: &GrowthArgs) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(&a.out)?;
    let db_path = a.out.join("growth.redb");
    let csv_path = a.out.join("growth.csv");
    // A file left by an earlier run would answer a different question.
    let _ = std::fs::remove_file(&db_path);

    let mut db = Database::create(&db_path)?;
    let mut csv = File::create(&csv_path)?;
    writeln!(
        csv,
        "# store-probe growth: redb file growth under a prolonged Durability::None"
    )?;
    writeln!(
        csv,
        "# start_utc={} start_unix={} pid={} host={}",
        utc_now(),
        unix_now(),
        std::process::id(),
        hostname()
    )?;
    writeln!(
        csv,
        "# hours={} tick_ms={} durable_every_s={} compact_every_h={} entries_per_tick={} \
         window_entries={} entry_bytes={ENTRY_BYTES} sample_every_s={} max_file_mb={}",
        a.hours,
        a.tick_ms,
        a.durable_every_s,
        a.compact_every_h,
        a.entries_per_tick,
        a.window_entries,
        a.sample_every_s,
        a.max_file_mb
    )?;
    writeln!(
        csv,
        "# fsync_p99_ms={} is a parameter measured elsewhere, not a result of this run",
        a.fsync_p99_ms
    )?;
    writeln!(
        csv,
        "elapsed_s,file_bytes,ticks,overruns,durable_commits,durable_over_parameter,\
         durable_p50_us,durable_p99_us,compactions,compact_before_bytes,compact_after_bytes,\
         compact_ms,note"
    )?;
    csv.flush()?;

    println!("state file: {}", csv_path.display());
    println!("harvest:    tail -n 5 {}", csv_path.display());

    let tick = Duration::from_millis(a.tick_ms);
    let entry = [0xa5u8; ENTRY_BYTES];
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(a.hours * 3600.0);
    let mut next_durable = started + Duration::from_secs(a.durable_every_s);
    let mut next_sample = started + Duration::from_secs(a.sample_every_s);
    let mut next_compact = started + Duration::from_secs_f64(a.compact_every_h * 3600.0);

    let mut st = GrowthState::default();
    let mut key: u64 = 0;

    while Instant::now() < deadline {
        let tick_start = Instant::now();

        let durable = tick_start >= next_durable;
        let mut txn = db.begin_write()?;
        // Fallible since redb 4, and only for a durability reduced inside a transaction
        // that touched a persistent savepoint. This probe creates none.
        txn.set_durability(if durable {
            Durability::Immediate
        } else {
            Durability::None
        })?;
        {
            let mut table = txn.open_table(TABLE)?;
            for _ in 0..a.entries_per_tick {
                table.insert(key, entry.as_slice())?;
                if key >= a.window_entries {
                    table.remove(key - a.window_entries)?;
                }
                key += 1;
            }
        }
        let commit_at = Instant::now();
        txn.commit()?;
        st.ticks += 1;
        if durable {
            let us = commit_at.elapsed().as_micros() as u64;
            st.latencies.push(us);
            st.durables += 1;
            if us as f64 > a.fsync_p99_ms * 1000.0 {
                st.over_parameter += 1;
            }
            next_durable = Instant::now() + Duration::from_secs(a.durable_every_s);
        }

        if Instant::now() >= next_compact {
            compact(&mut db, &db_path, &mut st)?;
            next_compact = Instant::now() + Duration::from_secs_f64(a.compact_every_h * 3600.0);
            write_growth_row(&mut csv, started, file_len(&db_path), &st, "compact")?;
        }

        let bytes = file_len(&db_path);
        if bytes > a.max_file_mb * (1 << 20) {
            write_growth_row(&mut csv, started, bytes, &st, "stopped:max_file_mb")?;
            return Err(format!(
                "growth stopped: file reached {bytes} bytes, over --max-file-mb {}",
                a.max_file_mb
            )
            .into());
        }
        if Instant::now() >= next_sample {
            write_growth_row(&mut csv, started, bytes, &st, "sample")?;
            next_sample = Instant::now() + Duration::from_secs(a.sample_every_s);
        }

        match tick.checked_sub(tick_start.elapsed()) {
            Some(rest) => std::thread::sleep(rest),
            // A tick that cannot hold its cadence is a result, not a hiccup.
            None => st.overruns += 1,
        }
    }

    compact(&mut db, &db_path, &mut st)?;
    write_growth_row(&mut csv, started, file_len(&db_path), &st, "final")?;
    println!(
        "growth: {} ticks ({} overruns), {} durable commits, {} over the {} ms parameter, \
         file {} bytes, last compact {} -> {} bytes in {} ms",
        st.ticks,
        st.overruns,
        st.durables,
        st.over_parameter,
        a.fsync_p99_ms,
        file_len(&db_path),
        st.compact_before,
        st.compact_after,
        st.compact_ms
    );
    Ok(())
}

#[derive(Default)]
struct GrowthState {
    ticks: u64,
    overruns: u64,
    durables: u64,
    over_parameter: u64,
    latencies: Vec<u64>,
    compactions: u64,
    compact_before: u64,
    compact_after: u64,
    compact_ms: u64,
}

fn compact(db: &mut Database, path: &Path, st: &mut GrowthState) -> Result<(), Box<dyn Error>> {
    // Every non-durable commit registers a live read transaction pinning the last
    // durable state, and redb refuses to compact while one exists. A durable
    // commit is therefore a precondition of compaction, not an option — which
    // also makes the cadence realistic: compaction follows hardening.
    let mut txn = db.begin_write()?;
    txn.set_durability(Durability::Immediate)?;
    txn.commit()?;

    let before = file_len(path);
    let at = Instant::now();
    db.compact()?;
    st.compact_ms = at.elapsed().as_millis() as u64;
    st.compact_before = before;
    st.compact_after = file_len(path);
    st.compactions += 1;
    Ok(())
}

/// Every row carries the running totals, so `tail -n 1` on a run still going —
/// or on one that was killed — is a whole answer and not a fragment.
fn write_growth_row(
    csv: &mut File,
    started: Instant,
    bytes: u64,
    st: &GrowthState,
    note: &str,
) -> io::Result<()> {
    let mut sorted = st.latencies.clone();
    sorted.sort_unstable();
    writeln!(
        csv,
        "{},{bytes},{},{},{},{},{},{},{},{},{},{},{note}",
        started.elapsed().as_secs(),
        st.ticks,
        st.overruns,
        st.durables,
        st.over_parameter,
        percentile(&sorted, 0.50),
        percentile(&sorted, 0.99),
        st.compactions,
        st.compact_before,
        st.compact_after,
        st.compact_ms
    )?;
    csv.flush()
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank, the definition fio uses, so these microseconds are
    // comparable with the fsync percentiles the cadence is judged against.
    let rank = (sorted.len() as f64 * q).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

// -------------------------------------------------------------- cold-load

fn cold_load(a: &ColdLoadArgs) -> Result<(), Box<dyn Error>> {
    let path = a
        .file
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("lorica-cold-load.bin"));
    write_incompressible(&path, a.size)?;

    let eviction = evict(&path)?;
    let cold = touch_mapped(&path)?;
    let hot = touch_mapped(&path)?;

    println!(
        "cold-load: {} MiB, eviction={eviction}, cold {} ms ({} MB/s, {} major faults), \
         hot {} ms ({} MB/s, {} major faults)",
        a.size >> 20,
        cold.elapsed.as_millis(),
        throughput_mbs(a.size, cold.elapsed),
        cold.majflt,
        hot.elapsed.as_millis(),
        throughput_mbs(a.size, hot.elapsed),
        hot.majflt
    );
    if eviction != "drop_caches" {
        println!("caveat: the guest page cache was not dropped wholesale, only this file's pages");
    }
    println!("caveat: the host page cache stays warm, so this is not a bare-media read");

    if let Some(out) = &a.out {
        std::fs::create_dir_all(out)?;
        let csv_path = out.join("cold-load.csv");
        let mut csv = File::create(&csv_path)?;
        writeln!(
            csv,
            "# store-probe cold-load, {} host={}",
            utc_now(),
            hostname()
        )?;
        writeln!(
            csv,
            "# size_bytes={} eviction={eviction} page_bytes={}",
            a.size,
            page_size()
        )?;
        writeln!(csv, "pass,elapsed_us,mb_per_s,minor_faults,major_faults")?;
        for (name, p) in [("cold", &cold), ("hot", &hot)] {
            writeln!(
                csv,
                "{name},{},{},{},{}",
                p.elapsed.as_micros(),
                throughput_mbs(a.size, p.elapsed),
                p.minflt,
                p.majflt
            )?;
        }
        println!("{}", csv_path.display());
    }
    Ok(())
}

struct Pass {
    elapsed: Duration,
    minflt: u64,
    majflt: u64,
}

fn throughput_mbs(bytes: u64, elapsed: Duration) -> u64 {
    let s = elapsed.as_secs_f64();
    if s <= 0.0 {
        0
    } else {
        (bytes as f64 / s / 1e6) as u64
    }
}

/// Random content, because a hypervisor that deduplicates or compresses runs of
/// zeroes would answer a question nobody asked.
fn write_incompressible(path: &Path, size: u64) -> io::Result<()> {
    let mut block = vec![0u8; 1 << 20];
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut file = File::create(path)?;
    let mut written = 0u64;
    while written < size {
        for word in block.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            word.copy_from_slice(&state.to_le_bytes());
        }
        let take = ((size - written) as usize).min(block.len());
        file.write_all(&block[..take])?;
        written += take as u64;
    }
    file.sync_all()
}

/// Dropping the guest's whole page cache needs root; `posix_fadvise` does not,
/// and evicts this file's pages only. Which one ran is returned and printed,
/// because a cold number that is not cold is worse than no number at all.
fn evict(path: &Path) -> io::Result<String> {
    let dropped = Command::new("sudo")
        .args(["-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if dropped {
        return Ok("drop_caches".into());
    }
    let file = File::open(path)?;
    let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok("fadvise-dontneed".into())
}

fn touch_mapped(path: &Path) -> io::Result<Pass> {
    let file = File::open(path)?;
    let len = file.metadata()?.len() as usize;
    let page = page_size();
    let (min0, maj0) = faults()?;
    let at = Instant::now();
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mut sum = 0u64;
    let mut off = 0usize;
    while off < len {
        // read_volatile so the fault really happens; the sum only keeps the loop
        // from being optimised away.
        sum = sum.wrapping_add(unsafe { (base as *const u8).add(off).read_volatile() }.into());
        off += page;
    }
    std::hint::black_box(sum);
    let elapsed = at.elapsed();
    unsafe { libc::munmap(base, len) };
    let (min1, maj1) = faults()?;
    Ok(Pass {
        elapsed,
        minflt: min1 - min0,
        majflt: maj1 - maj0,
    })
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// minflt and majflt are fields 10 and 12 of /proc/self/stat. Field 2, the
/// process name, may itself hold spaces and parentheses, so the split starts
/// after its closing one.
fn faults() -> io::Result<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let tail = stat
        .rfind(") ")
        .map(|i| &stat[i + 2..])
        .ok_or_else(|| io::Error::other("/proc/self/stat has no comm field"))?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let field = |i: usize| -> io::Result<u64> {
        fields
            .get(i)
            .and_then(|f| f.parse().ok())
            .ok_or_else(|| io::Error::other("/proc/self/stat is shorter than expected"))
    };
    Ok((field(7)?, field(9)?))
}

// ------------------------------------------------------------- alloc-mmap

fn alloc_mmap(a: &AllocArgs) -> Result<(), Box<dyn Error>> {
    if a.allocator == Allocator::Both {
        // One child per allocator, so each starts from an RSS baseline the other
        // has not already inflated with its retained pages.
        for one in [Allocator::Jemalloc, Allocator::Mimalloc] {
            let mut cmd = Command::new(std::env::current_exe()?);
            cmd.args(["alloc-mmap", "--allocator", one.as_str()]);
            cmd.args([
                "--size",
                &a.size.to_string(),
                "--chunk",
                &a.chunk.to_string(),
            ]);
            cmd.args([
                "--settle-s",
                &a.settle_s.to_string(),
                "--tick-ms",
                &a.tick_ms.to_string(),
            ]);
            cmd.args(["--decay-ms", &a.decay_ms.to_string()]);
            if a.no_collect {
                cmd.arg("--no-collect");
            }
            if let Some(out) = &a.out {
                cmd.arg("--out").arg(out);
            }
            let status = cmd.status()?;
            if !status.success() {
                return Err(format!("{} run failed: {status}", one.as_str()).into());
            }
        }
        return Ok(());
    }

    let jemalloc = a.allocator == Allocator::Jemalloc;
    // MALLCTL_ARENAS_ALL (4096) is accepted by arena.<i>.decay but not by the
    // arena.<i>.*_decay_ms setters, which call arena_get(4096), find nothing and
    // return EFAULT. So the thread's own arena is read and addressed by index.
    // mallctl rather than MALLOC_CONF because jemalloc is not the global
    // allocator here: it initialises on the first call below, so the setting
    // needs no re-exec.
    let arena = if jemalloc {
        je_read_u32("thread.arena")?
    } else {
        0
    };
    if jemalloc {
        je_write_ssize(&format!("arena.{arena}.dirty_decay_ms"), a.decay_ms)?;
        je_write_ssize(&format!("arena.{arena}.muzzy_decay_ms"), a.decay_ms)?;
    }

    let count = (a.size / a.chunk).max(1) as usize;
    let chunk = a.chunk as usize;
    let baseline = rss()?;

    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let p = unsafe {
            if jemalloc {
                tikv_jemalloc_sys::mallocx(chunk, 0).cast::<u8>()
            } else {
                libmimalloc_sys::mi_malloc(chunk).cast::<u8>()
            }
        };
        if p.is_null() {
            return Err(format!(
                "{}: allocation of {chunk} bytes failed",
                a.allocator.as_str()
            )
            .into());
        }
        // An untouched page is not resident, and an RSS that never rose would
        // make the whole measurement vacuous.
        unsafe { std::ptr::write_bytes(p, 0xa5, chunk) };
        blocks.push(p);
    }
    let peak = rss()?;

    for p in blocks.drain(..) {
        unsafe {
            if jemalloc {
                tikv_jemalloc_sys::sdallocx(p.cast(), chunk, 0);
            } else {
                libmimalloc_sys::mi_free(p.cast());
            }
        }
    }
    let after_free = rss()?;

    let tick = Duration::from_millis(a.tick_ms);
    let mut series: Vec<(u64, Rss)> = Vec::new();
    let at = Instant::now();
    while at.elapsed() < Duration::from_secs(a.settle_s) {
        if !a.no_collect {
            if jemalloc {
                je_write_void(&format!("arena.{arena}.decay"))?;
            } else {
                unsafe { libmimalloc_sys::mi_collect(false) };
            }
        }
        series.push((at.elapsed().as_millis() as u64, rss()?));
        std::thread::sleep(tick);
    }
    let settled = series.last().map(|(_, r)| r).unwrap_or(&after_free);

    // The share of the peak that actually went back to the kernel: the number
    // that says whether RSS lies.
    let grew = peak.resident.saturating_sub(baseline.resident);
    let returned = peak.resident.saturating_sub(settled.resident);
    let returned_pct = if grew == 0 {
        0.0
    } else {
        returned as f64 * 100.0 / grew as f64
    };
    let recovered_at = series
        .iter()
        .find(|(_, r)| r.resident <= baseline.resident + grew / 10)
        .map(|(ms, _)| *ms);

    println!(
        "{}: baseline {} KiB, peak {} KiB, after free {} KiB, settled {} KiB, \
         {returned_pct:.1} % returned, anonymous at settle {} KiB, 90 % recovered {}",
        a.allocator.as_str(),
        baseline.resident >> 10,
        peak.resident >> 10,
        after_free.resident >> 10,
        settled.resident >> 10,
        settled.anonymous() >> 10,
        match recovered_at {
            Some(ms) => format!("after {ms} ms"),
            None => format!("never within {} s", a.settle_s),
        }
    );

    if let Some(out) = &a.out {
        std::fs::create_dir_all(out)?;
        let csv_path = out.join(format!("alloc-mmap-{}.csv", a.allocator.as_str()));
        let mut csv = File::create(&csv_path)?;
        writeln!(
            csv,
            "# store-probe alloc-mmap, {} host={}",
            utc_now(),
            hostname()
        )?;
        writeln!(
            csv,
            "# allocator={} size_bytes={} chunk_bytes={} decay_ms={} tick_ms={} \
             collect_on_tick={}",
            a.allocator.as_str(),
            a.size,
            a.chunk,
            a.decay_ms,
            a.tick_ms,
            !a.no_collect
        )?;
        writeln!(
            csv,
            "# baseline_kib={} peak_kib={} after_free_kib={} settled_kib={} \
             returned_pct={returned_pct:.1}",
            baseline.resident >> 10,
            peak.resident >> 10,
            after_free.resident >> 10,
            settled.resident >> 10
        )?;
        writeln!(
            csv,
            "elapsed_ms,resident_bytes,file_backed_bytes,anonymous_bytes"
        )?;
        for (ms, r) in &series {
            writeln!(csv, "{ms},{},{},{}", r.resident, r.shared, r.anonymous())?;
        }
        println!("{}", csv_path.display());
    }
    Ok(())
}

struct Rss {
    resident: u64,
    shared: u64,
}

impl Rss {
    /// Allocator arenas live here; a file mapping does not, which is why the two
    /// are reported apart.
    fn anonymous(&self) -> u64 {
        self.resident.saturating_sub(self.shared)
    }
}

fn rss() -> io::Result<Rss> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let mut fields = statm.split_whitespace().skip(1);
    let mut next = || -> io::Result<u64> {
        fields
            .next()
            .and_then(|f| f.parse::<u64>().ok())
            .ok_or_else(|| io::Error::other("/proc/self/statm is shorter than expected"))
    };
    let page = page_size() as u64;
    let resident = next()? * page;
    let shared = next()? * page;
    Ok(Rss { resident, shared })
}

fn je_read_u32(name: &str) -> Result<u32, Box<dyn Error>> {
    let cname = CString::new(name)?;
    let mut out: libc::c_uint = 0;
    let mut len = size_of::<libc::c_uint>();
    let rc = unsafe {
        tikv_jemalloc_sys::mallctl(
            cname.as_ptr(),
            (&raw mut out).cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!("mallctl {name} returned {rc}").into());
    }
    Ok(out)
}

fn je_write_ssize(name: &str, value: i64) -> Result<(), Box<dyn Error>> {
    let cname = CString::new(name)?;
    let mut v = value as libc::ssize_t;
    let rc = unsafe {
        tikv_jemalloc_sys::mallctl(
            cname.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&raw mut v).cast(),
            size_of::<libc::ssize_t>(),
        )
    };
    if rc != 0 {
        return Err(format!("mallctl {name}={value} returned {rc}").into());
    }
    Ok(())
}

/// A void mallctl takes a null `newp`; handing it a value returns EINVAL, and a
/// silently ignored purge would make the comparison with `mi_collect` a lie.
fn je_write_void(name: &str) -> Result<(), Box<dyn Error>> {
    let cname = CString::new(name)?;
    let rc = unsafe {
        tikv_jemalloc_sys::mallctl(
            cname.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!("mallctl {name} returned {rc}").into());
    }
    Ok(())
}

// ----------------------------------------------------------------- shared

fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, scale) = match text.chars().last() {
        Some('K' | 'k') => (&text[..text.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&text[..text.len() - 1], 1u64 << 20),
        Some('G' | 'g') => (&text[..text.len() - 1], 1u64 << 30),
        _ => (text, 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|n| n * scale)
        .map_err(|e| format!("{text}: {e}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shelling out to `date` rather than carrying a calendar: the probe only runs
/// on Linux, and the epoch second sits next to it in the same header.
fn utc_now() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("unix:{}", unix_now()))
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_with_and_without_a_suffix() {
        assert_eq!(parse_size("80M").unwrap(), 80 << 20);
        assert_eq!(parse_size("64K").unwrap(), 64 << 10);
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("80MB").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn percentiles_pick_the_element_and_never_panic_when_empty() {
        assert_eq!(percentile(&[], 0.99), 0);
        assert_eq!(percentile(&[7], 0.99), 7);
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 0.50), 50);
        assert_eq!(percentile(&sorted, 0.99), 99);
    }

    /// Both readers slice /proc by field position, which is exactly the kind of
    /// parsing that breaks silently and reports a plausible zero.
    #[test]
    fn proc_readers_return_something_alive() {
        let (minor, _major) = faults().unwrap();
        assert!(minor > 0, "a running process has taken minor faults");
        let r = rss().unwrap();
        assert!(r.resident > 0 && r.resident >= r.shared);
    }
}
