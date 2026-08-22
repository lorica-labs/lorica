//! Throughput of the batch commands, and the kernel memory the maps really cost.
//!
//! Not a test: it takes parameters, prints one record and asserts nothing. libtest has
//! no way to pass `--entries` through to a test, so this target owns its own `main`.
//! Run with no argument it measures nothing and says so, which is what a full
//! `kernel-tests.sh` run gets.
//!
//! It lives in `tests/` because the measurement machine has no toolchain and a glibc
//! binary from the build VM does not start there: `target-build.sh` packs test
//! binaries built against static musl, and that is the shipping path a measurement
//! reuses rather than duplicates. `scripts/lab/measure-map-batch.sh` drives it.
//!
//! The one-element-per-syscall path is measured too, on the same machine in the same
//! run, because the ratio is the whole question and the figure the plan carries for it
//! was never measured here. A batch command with a count of one is *not* that baseline:
//! it is the same command doing the same per-call kernel allocations for one element.
//!
//! The driving script builds this at `opt-level=3`. It has to: aya's single-element read
//! boxes a slice per slot, and an unoptimised build inflates the naive side of the ratio
//! more than the batched side, which would flatter batching for a reason that has
//! nothing to do with the kernel.

use std::{
    env, fs,
    hint::black_box,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{
        MapData, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    util::nr_cpus,
};
use carapace_common::{Action, CounterId, LpmKey, LpmValue};
use carapace_dataplane::maps::{self, lpm};

/// A local wrapper so `Pod` can be implemented for a foreign type, as in the tests.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodValue(LpmValue);

// SAFETY: LpmValue is Copy and 'static, and nothing reads a value out of this map that
// this file did not write into it.
unsafe impl aya::Pod for PodValue {}

const USAGE: &str = "\
measure_batch [--entries N] [--sizes A,B,C] [--settle-ms MS]

Prints one JSON record on stdout. Reads the eBPF object from CARAPACE_EBPF_PLAIN_OBJ,
or CARAPACE_EBPF_OBJ if that is unset.";

type Failure = Box<dyn std::error::Error>;

fn main() -> Result<(), Failure> {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("measure_batch: no argument, nothing measured\n\n{USAGE}");
        return Ok(());
    }

    let mut entries: u32 = 1_000_000;
    let mut sizes: Vec<u32> = vec![1, 100, 1_000, 10_000, 100_000];
    let mut settle = Duration::from_millis(2_000);

    let next = |at: usize| -> Result<&String, Failure> {
        argv.get(at + 1)
            .ok_or_else(|| format!("{} needs a value", argv[at]).into())
    };
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--entries" => entries = next(i)?.parse()?,
            "--sizes" => {
                sizes = next(i)?
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<_, _>>()?;
            }
            "--settle-ms" => settle = Duration::from_millis(next(i)?.parse()?),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}").into()),
        }
        i += 2;
    }
    if entries == 0 || sizes.is_empty() {
        return Err("--entries and --sizes both have to name something".into());
    }

    let object = object_bytes()?;
    let counter_entries = CounterId::COUNT + entries;
    let cpus = nr_cpus().map_err(|(path, err)| format!("{path}: {err}"))?;

    // Built once and reused: the cost of building it is not part of any number below,
    // and at a million entries it is seventy megabytes of userspace that would
    // otherwise be reallocated per run.
    let list: Vec<(LpmKey, LpmValue)> = (0..entries)
        .map(|i| (host(i), entry(CounterId::COUNT + i)))
        .collect();

    // ----- kernel memory -----
    //
    // Two idle baselines first, because SUnreclaim is the only field that holds still
    // while MemFree wanders by megabytes on its own. A delta without the noise floor
    // beside it is noise with a unit attached.
    let idle_a = Meminfo::read()?;
    std::thread::sleep(settle);
    let idle_b = Meminfo::read()?;

    let ebpf = load(&object, entries, counter_entries)?;
    std::thread::sleep(settle);
    let created = Meminfo::read()?;
    let memlock_list_empty = maps::memlock_bytes(list_fd(&ebpf)?)?;
    let memlock_counters = maps::memlock_bytes(counters_fd(&ebpf)?)?;

    lpm::load(list_fd(&ebpf)?, &list, 10_000)?;
    std::thread::sleep(settle);
    let filled = Meminfo::read()?;
    let memlock_list_full = maps::memlock_bytes(list_fd(&ebpf)?)?;

    drop(ebpf);
    std::thread::sleep(settle);
    let released = Meminfo::read()?;

    // ----- throughput -----
    //
    // A fresh trie per batch size. Rewriting keys already present costs no node
    // allocation at all, so reusing one map would measure overwrite and call it insert.
    let mut rows = Vec::new();
    for &batch in &sizes {
        let ebpf = load(&object, entries, counter_entries)?;

        let started = Instant::now();
        lpm::load(list_fd(&ebpf)?, &list, batch as usize)?;
        rows.push(Row::new(
            "update_batch_lpm_trie",
            batch,
            entries,
            started.elapsed(),
        ));

        // Built outside the timed region on purpose: the buffers are the agent's, held
        // for its lifetime, and their allocation is not part of the cost of a read.
        let mut reader = maps::counters(&ebpf, counter_entries, batch)?;
        let started = Instant::now();
        let counters = reader.read()?;
        rows.push(Row::new(
            "lookup_batch_per_cpu_array",
            batch,
            counter_entries,
            started.elapsed(),
        ));
        if counters.len() != counter_entries as usize {
            return Err(format!("read {} of {counter_entries} counters", counters.len()).into());
        }
        black_box(counters);
    }

    // ----- the path this module exists to replace -----
    //
    // One syscall per element, through aya, which is what an agent without this module
    // would do. The boxed slice aya returns per slot is part of the cost and not an
    // artefact: that allocation is exactly what makes the naive read expensive on top of
    // the syscall count.
    {
        let mut ebpf = load(&object, entries, counter_entries)?;
        let map = ebpf
            .map_mut("UNIFIED_LIST")
            .ok_or("no UNIFIED_LIST map in the object")?;
        let mut trie: LpmTrie<&mut MapData, [u8; 16], PodValue> = LpmTrie::try_from(map)?;
        let started = Instant::now();
        for (key, value) in &list {
            trie.insert(&Key::new(key.prefix_len, key.addr), PodValue(*value), 0)?;
        }
        rows.push(Row::new(
            "update_elem_lpm_trie",
            1,
            entries,
            started.elapsed(),
        ));

        let map = ebpf
            .map("COUNTERS")
            .ok_or("no COUNTERS map in the object")?;
        let counters: PerCpuArray<&MapData, u64> = PerCpuArray::try_from(map)?;
        let started = Instant::now();
        let mut total: u64 = 0;
        for slot in 0..counter_entries {
            total += counters.get(&slot, 0)?.iter().sum::<u64>();
        }
        rows.push(Row::new(
            "lookup_elem_per_cpu_array",
            1,
            counter_entries,
            started.elapsed(),
        ));
        black_box(total);
    }

    let noise = idle_b.minus(idle_a);
    let on_create = created.minus(idle_b);
    let on_fill = filled.minus(created);
    let on_release = released.minus(filled);

    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let memlock_fill = memlock_list_full.saturating_sub(memlock_list_empty);
    println!("{{");
    println!("  \"captured_epoch\": {epoch},");
    println!(
        "  \"host\": \"{}\",",
        proc_line("/proc/sys/kernel/hostname")
    );
    println!(
        "  \"kernel\": \"{}\",",
        proc_line("/proc/sys/kernel/osrelease")
    );
    println!("  \"possible_cpus\": {cpus},");
    println!("  \"list_entries\": {entries},");
    println!("  \"counter_entries\": {counter_entries},");
    println!("  \"settle_ms\": {},", settle.as_millis());
    println!("  \"memlock_bytes\": {{");
    println!("    \"list_empty\": {memlock_list_empty},");
    println!("    \"list_full\": {memlock_list_full},");
    println!("    \"counters\": {memlock_counters}");
    println!("  }},");
    println!("  \"meminfo_kb\": {{");
    println!("    \"idle_noise\": {},", noise.json());
    println!("    \"on_create\": {},", on_create.json());
    println!("    \"on_fill\": {},", on_fill.json());
    println!("    \"on_release\": {}", on_release.json());
    println!("  }},");
    // The ratio the plan needs and neither number gives alone: what the slab actually
    // grew by against what the map reports for itself. The kernel rounds every node up
    // and never reports the intermediate ones.
    println!(
        "  \"fill_sunreclaim_over_memlock\": {},",
        ratio_signed(on_fill.s_unreclaim * 1024, memlock_fill)
    );
    println!("  \"throughput\": [");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        println!("    {}{comma}", row.json());
    }
    println!("  ]");
    println!("}}");
    Ok(())
}

/// One measured run: an operation, the batch it used, and what it cost.
struct Row {
    op: &'static str,
    batch: u32,
    elements: u32,
    elapsed: Duration,
}

impl Row {
    fn new(op: &'static str, batch: u32, elements: u32, elapsed: Duration) -> Self {
        Self {
            op,
            batch,
            elements,
            elapsed,
        }
    }

    fn json(&self) -> String {
        let Self {
            op,
            batch,
            elements,
            elapsed,
        } = self;
        let ns = elapsed.as_nanos();
        let per = ratio(ns, u128::from(*elements));
        let per_second = ratio(u128::from(*elements) * 1_000_000_000, ns);
        format!(
            "{{ \"op\": \"{op}\", \"batch\": {batch}, \"elements\": {elements}, \
             \"elapsed_ns\": {ns}, \"ns_per_element\": {per}, \"elements_per_s\": {per_second} }}"
        )
    }
}

/// The fields of `/proc/meminfo` that answer the question, and `MemFree`, which does
/// not: it is dominated by the page cache and by anything else the machine did during
/// the run. It is printed so a reader can see it moving while `SUnreclaim` does not.
#[derive(Clone, Copy)]
struct Meminfo {
    mem_free: i64,
    slab: i64,
    s_unreclaim: i64,
    percpu: i64,
}

impl Meminfo {
    fn read() -> Result<Self, Failure> {
        let text = fs::read_to_string("/proc/meminfo")?;
        Ok(Self {
            mem_free: field(&text, "MemFree")?,
            slab: field(&text, "Slab")?,
            s_unreclaim: field(&text, "SUnreclaim")?,
            percpu: field(&text, "Percpu")?,
        })
    }

    fn minus(self, earlier: Self) -> Self {
        Self {
            mem_free: self.mem_free - earlier.mem_free,
            slab: self.slab - earlier.slab,
            s_unreclaim: self.s_unreclaim - earlier.s_unreclaim,
            percpu: self.percpu - earlier.percpu,
        }
    }

    fn json(self) -> String {
        let Self {
            mem_free,
            slab,
            s_unreclaim,
            percpu,
        } = self;
        format!(
            "{{ \"mem_free\": {mem_free}, \"slab\": {slab}, \
             \"s_unreclaim\": {s_unreclaim}, \"percpu\": {percpu} }}"
        )
    }
}

/// A named field of `/proc/meminfo`, in kilobytes. Missing is an error: a guard that
/// compares against a silently absent value is the worst of the two failures.
fn field(text: &str, name: &str) -> Result<i64, Failure> {
    let (_, value) = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| *key == name)
        .ok_or_else(|| format!("/proc/meminfo carries no {name} line"))?;
    let value = value.trim().trim_end_matches("kB").trim();
    value
        .parse()
        .map_err(|err| format!("/proc/meminfo {name} is {value:?}, unreadable: {err}").into())
}

/// Three decimals, and `null` rather than a division by zero: a JSON reader can refuse
/// a null, and a zero it cannot tell from a real one.
fn ratio(numerator: impl Into<u128>, denominator: impl Into<u128>) -> String {
    let (numerator, denominator): (u128, u128) = (numerator.into(), denominator.into());
    if denominator == 0 {
        return "null".to_owned();
    }
    let scaled = numerator * 1_000 / denominator;
    format!("{}.{:03}", scaled / 1_000, scaled % 1_000)
}

/// The slab can shrink across a phase — another process freeing while we allocate — and
/// a negative growth over a positive allocation is not a ratio, it is a run to discard.
fn ratio_signed(numerator: i64, denominator: u64) -> String {
    if numerator < 0 {
        return "null".to_owned();
    }
    ratio(
        u128::from(numerator.unsigned_abs()),
        u128::from(denominator),
    )
}

fn proc_line(path: &str) -> String {
    fs::read_to_string(path)
        .map(|text| text.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn object_bytes() -> Result<Vec<u8>, Failure> {
    let path = env::var("CARAPACE_EBPF_PLAIN_OBJ")
        .or_else(|_| env::var("CARAPACE_EBPF_OBJ"))
        .map_err(|_| "neither CARAPACE_EBPF_PLAIN_OBJ nor CARAPACE_EBPF_OBJ is set")?;
    fs::read(&path).map_err(|err| format!("cannot read the eBPF object at {path}: {err}").into())
}

/// The maps at the size being measured. The program is not loaded: a map measurement
/// needs no verifier and no attach.
fn load(object: &[u8], entries: u32, counter_entries: u32) -> Result<Ebpf, Failure> {
    EbpfLoader::new()
        .map_max_entries("UNIFIED_LIST", entries)
        .map_max_entries("COUNTERS", counter_entries)
        .load(object)
        .map_err(|err| format!("creating the maps failed: {err}").into())
}

fn list_fd(ebpf: &Ebpf) -> Result<std::os::fd::BorrowedFd<'_>, Failure> {
    maps::fd(ebpf, "UNIFIED_LIST").ok_or_else(|| "no UNIFIED_LIST map in the object".into())
}

fn counters_fd(ebpf: &Ebpf) -> Result<std::os::fd::BorrowedFd<'_>, Failure> {
    maps::fd(ebpf, "COUNTERS").ok_or_else(|| "no COUNTERS map in the object".into())
}

/// A distinct /32 per index. 10.0.0.0/8 holds sixteen million of them, so a million
/// entries are all leaves and none of them is a prefix of another.
fn host(i: u32) -> LpmKey {
    LpmKey::v4([10, (i >> 16) as u8, (i >> 8) as u8, i as u8], 32)
}

fn entry(counter_slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.counter_idx = counter_slot;
    value
}
