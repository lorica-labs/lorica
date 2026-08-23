//! What the unified list lookup costs once the list is full.
//!
//! Not a test: it takes parameters, prints one record per size and asserts nothing.
//! Run with no argument it measures nothing and says so, which is what a full
//! `kernel-tests.sh` run gets.
//!
//! **Why this exists.** The lookup was measured at 9 ns above the floor on a trie holding
//! one entry, and that figure is quoted in a comparison against `bpf_fib_lookup`. A trie
//! with one entry is not the production case: the deployment profiles reserve sixteen
//! thousand entries on a VPS and a million on a gateway. An `LPM_TRIE` allocates per node
//! — `BPF_F_NO_PREALLOC` is not optional for the type — so a full trie is a pointer chase
//! across pages, and how far that chase goes is what this measures. The decision it feeds
//! is whether the blocklist stays one trie or becomes a hash for the exact prefixes with a
//! trie for the rest; that decision is taken at the end of the phase, on this number.
//!
//! **Three sources per size, because a miss is not one thing.** A source outside the
//! populated range diverges from the trie at the first byte and proves nothing. The figures
//! that matter are a source sharing a long prefix with real entries and absent — the deep
//! miss — and one that is present. The shallow miss is measured anyway because it is the
//! packet every other figure in this project is quoted for, so it is the bridge between
//! this table and the rest.
//!
//! It lives in `tests/` for the reason `measure_batch.rs` gives: the measurement machine
//! has no toolchain, and `target-build.sh` packs test binaries built against static musl.
//! It carries its own loader rather than the one in `tests/support/run.rs` because it has
//! to size a map before the object is loaded, which that harness deliberately does not
//! expose, and its own frame builder because `PktBuilder` lives in a module a measurement
//! target does not compile.

use std::{env, fs};

use aya::{
    Ebpf, EbpfLoader,
    programs::{TestRun, TestRunOptions, Xdp},
};
use carapace_common::{
    Action, CounterId, DEFAULT_SETTINGS, Deadline, LpmKey, LpmValue, SETTINGS_SYMBOL,
};
use carapace_dataplane::maps::{self, lpm};

type Failure = Box<dyn std::error::Error>;

const USAGE: &str = "\
measure_lpm_depth [--sizes A,B,C] [--repeat N] [--passes N]

Prints one CSV row per size and case on stdout. Reads the eBPF object from
CARAPACE_EBPF_PLAIN_OBJ, or CARAPACE_EBPF_OBJ if that is unset.";

/// One million, as everywhere else here: enough that the per-run average is stable.
const DEFAULT_REPEAT: u32 = 1_000_000;

/// The passes interleave the sizes rather than repeating each one in place, for the reason
/// `stage_cost.rs` gives: a single pass puts ten nanoseconds of drift on a figure of two
/// hundred, and drift that lands on one size reads exactly like a property of that size.
const DEFAULT_PASSES: usize = 5;

/// `bench/results/floor-20260822T093726Z.json`, subtracted here so every row is comparable
/// with the rest of the project's figures.
const FLOOR_NS: u128 = 15;

const PROGRAM: &str = "carapace_xdp";
const GAME_PORT: u16 = 30_120;
const CASES: [&str; 3] = ["shallow_miss", "deep_miss", "hit"];

struct Sized {
    entries: u32,
    ebpf: Ebpf,
    memlock: u64,
}

fn main() -> Result<(), Failure> {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("measure_lpm_depth: no argument, nothing measured\n\n{USAGE}");
        return Ok(());
    }

    let mut sizes: Vec<u32> = Vec::new();
    let mut repeat = DEFAULT_REPEAT;
    let mut passes = DEFAULT_PASSES;

    let mut i = 0;
    while i < argv.len() {
        let value = || -> Result<&String, Failure> {
            argv.get(i + 1)
                .ok_or_else(|| format!("{} wants a value\n\n{USAGE}", argv[i]).into())
        };
        match argv[i].as_str() {
            "--sizes" => {
                sizes = value()?
                    .split(',')
                    .map(|s| s.trim().parse::<u32>())
                    .collect::<Result<_, _>>()?;
            }
            "--repeat" => repeat = value()?.parse()?,
            "--passes" => passes = value()?.parse()?,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}").into()),
        }
        i += 2;
    }
    if sizes.is_empty() || passes == 0 {
        return Err("--sizes has to name something and --passes cannot be zero".into());
    }
    sizes.sort_unstable();

    let object = object_bytes()?;

    // Every size is loaded and filled once, then all of them are held for the whole sweep,
    // so the interleaved passes do not refill a million-entry trie five times. Filling one
    // is about a second, and holding them all is a few hundred megabytes of kernel memory,
    // which the deployment profiles already budget for.
    let mut loaded = Vec::with_capacity(sizes.len());
    for &entries in &sizes {
        let mut ebpf = maps_at_size(&object, entries)?;
        verify(&mut ebpf)?;
        let fd = maps::fd(&ebpf, "UNIFIED_LIST").ok_or("no UNIFIED_LIST map in the object")?;
        let list: Vec<(LpmKey, LpmValue)> = (0..entries)
            .map(|index| (host(index), entry(CounterId::COUNT + index)))
            .collect();
        lpm::load(fd, &list, 10_000)?;
        let memlock = maps::memlock_bytes(fd)?;
        loaded.push(Sized {
            entries,
            ebpf,
            memlock,
        });
    }

    println!("entries,case,repeat,ns_above_floor,ns_spread,memlock_bytes");
    for case in CASES {
        let mut samples: Vec<Vec<u128>> = vec![Vec::with_capacity(passes); loaded.len()];
        for _ in 0..passes {
            for (index, sized) in loaded.iter().enumerate() {
                let frame = frame_for(case, sized.entries);
                samples[index].push(run_ns(&sized.ebpf, &frame, repeat)?);
            }
        }
        for (index, sized) in loaded.iter().enumerate() {
            let low = *samples[index].iter().min().expect("one pass at least");
            let high = *samples[index].iter().max().expect("one pass at least");
            samples[index].sort_unstable();
            let median = samples[index][samples[index].len() / 2];
            println!(
                "{},{case},{repeat},{},{},{}",
                sized.entries,
                median.saturating_sub(FLOOR_NS),
                high - low,
                sized.memlock
            );
        }
    }
    Ok(())
}

/// The frame for one case at one size.
///
/// The deep miss takes the index one past the last one loaded: it shares every byte but the
/// last with entries that really are there, so the walk reaches the bottom of the trie
/// before failing. The hit takes the middle of the range. Both are derived from the size
/// rather than fixed, because a fixed address is a deep miss at one size and a shallow one
/// at another.
fn frame_for(case: &str, entries: u32) -> Vec<u8> {
    let index = match case {
        "deep_miss" => entries,
        "hit" => entries / 2,
        // Outside 10.0.0.0/8 entirely, so it leaves the trie at the first byte. It is the
        // source every other figure in this project is quoted for.
        _ => return frame([203, 0, 113, 1]),
    };
    frame([10, (index >> 16) as u8, (index >> 8) as u8, index as u8])
}

/// A legitimate UDP frame with a chosen source.
fn frame(src: [u8; 4]) -> Vec<u8> {
    const PAYLOAD: usize = 22;
    let total = 20 + 8 + PAYLOAD;
    let mut out = Vec::with_capacity(14 + total);
    out.extend_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    out.extend_from_slice(&0x0800u16.to_be_bytes());

    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0]);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&[10, 90, 1, 1]);
    let checksum = ones_complement(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&ip);

    out.extend_from_slice(&1111u16.to_be_bytes());
    out.extend_from_slice(&GAME_PORT.to_be_bytes());
    out.extend_from_slice(&((8 + PAYLOAD) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.resize(14 + total, 0);
    out
}

/// Computed rather than written down: a hand-typed constant that happens to be wrong makes
/// the kernel treat the frame in a way that reads like a program bug for an hour.
fn ones_complement(header: &[u8]) -> u16 {
    let mut total: u32 = 0;
    for pair in header.chunks(2) {
        total += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

/// Average nanoseconds per invocation, chronometered by the kernel around its own loop, so
/// no `bpf_stats_enabled` is needed — it costs 64 ns on this hardware, more than the signal.
fn run_ns(ebpf: &Ebpf, frame: &[u8], repeat: u32) -> Result<u128, Failure> {
    let program: &Xdp = ebpf
        .program(PROGRAM)
        .ok_or("the program disappeared")?
        .try_into()?;
    let result = program.test_run(TestRunOptions {
        data_in: Some(frame),
        repeat,
        ..Default::default()
    })?;
    Ok(result.duration.as_nanos())
}

fn object_bytes() -> Result<Vec<u8>, Failure> {
    let path = env::var("CARAPACE_EBPF_PLAIN_OBJ")
        .or_else(|_| env::var("CARAPACE_EBPF_OBJ"))
        .map_err(|_| "neither CARAPACE_EBPF_PLAIN_OBJ nor CARAPACE_EBPF_OBJ is set")?;
    fs::read(&path).map_err(|err| format!("cannot read the eBPF object at {path}: {err}").into())
}

/// The maps at the size being measured. Sizing them before the load is the whole reason
/// this file does not use the shared test harness.
fn maps_at_size(object: &[u8], entries: u32) -> Result<Ebpf, Failure> {
    let settings = DEFAULT_SETTINGS;
    EbpfLoader::new()
        .override_global(SETTINGS_SYMBOL, &settings, true)
        .map_max_entries("UNIFIED_LIST", entries.max(1))
        .map_max_entries("COUNTERS", CounterId::COUNT + entries)
        .load(object)
        .map_err(|err| format!("creating the maps failed: {err}").into())
}

/// `test_run` needs a verified program and no interface, which is what keeps this
/// measurement off the one machine that has a NIC worth measuring.
fn verify(ebpf: &mut Ebpf) -> Result<(), Failure> {
    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM)
        .ok_or("no program in the object")?
        .try_into()?;
    program
        .load()
        .map_err(|err| format!("the verifier rejected the program: {err}").into())
}

/// A distinct /32 per index, as `measure_batch.rs` builds them, so the two measurements
/// describe the same trie shape. 10.0.0.0/8 holds sixteen million, so a million entries are
/// all leaves and none is a prefix of another.
fn host(index: u32) -> LpmKey {
    LpmKey::v4(
        [10, (index >> 16) as u8, (index >> 8) as u8, index as u8],
        32,
    )
}

/// `Deadline::never()` explicitly. A value built by hand leaves the deadline at zero, and
/// zero is expired, so a trie filled with expired entries would time the expiry branch
/// instead of the lookup.
fn entry(counter_slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.counter_idx = counter_slot;
    value.deadline = Deadline::never();
    value
}
