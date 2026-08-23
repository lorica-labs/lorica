//! What the unified list lookup costs once the list is full.
//!
//! Not a test: it takes parameters and prints one record per size and arm. It asserts only
//! that the arms it prints are the arms it names. Run with no argument it measures nothing
//! and says so, which is what a full `kernel-tests.sh` run gets.
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
//! **Why four arms, and why the probe is what was under suspicion.** The earlier version of
//! this file reported a miss flat at 137–144 ns from one entry to a million, which is not a
//! property a trie can have: with a million hosts populated, an absent address drawn among
//! them meets its first NULL child about twenty levels down, since the subtree at depth `d`
//! is empty with probability about `exp(-2^20 / 2^d)`. A miss costing the same at both ends
//! stopped two or three levels down, so the probe sat outside the populated region and the
//! figure describes the probe. The four arms separate that:
//!
//! - `deep_miss_inside` — absent, drawn from a /16 the loaded set actually populated. This
//!   is what production traffic looks like once the list is large.
//! - `shallow_miss_control` — absent, outside the dense region. The arm that existed alone
//!   before, kept deliberately as the control: it is what every other figure in this
//!   project is quoted for, and holding it next to arm 1 is what shows a reader that the
//!   two measure different things rather than that one of them is wrong.
//! - `hit_scattered` — present, a different /16 each pass.
//! - `hit_clustered` — present, every pass inside one /16, so the last levels of the walk
//!   are the same nodes and the cache behaves differently from arm 3.
//!
//! **Units.** The nanoseconds are the `duration` field of `BPF_PROG_TEST_RUN`, measured at
//! 128 ns against 262 ns of task-clock for the same work — a stable factor of 2.06. Ratios
//! between arms are sound; the absolutes are about half the CPU time, and no claim about
//! absolute cost is made here.
//!
//! It lives in `tests/` for the reason `measure_batch.rs` gives: the measurement machine
//! has no toolchain, and `target-build.sh` packs test binaries built against static musl.
//! It carries its own loader rather than the one in `tests/support/run.rs` because it has
//! to size a map before the object is loaded, which that harness deliberately does not
//! expose, and its own frame builder because `PktBuilder` lives in a module a measurement
//! target does not compile.

use std::{collections::BTreeSet, env, fs};

use aya::{
    Ebpf, EbpfLoader,
    programs::{TestRun, TestRunOptions, Xdp},
};
use lorica_common::{
    Action, CounterId, DEFAULT_SETTINGS, Deadline, LpmKey, LpmValue, SETTINGS_SYMBOL,
};
use lorica_dataplane::maps::{self, lpm};

type Failure = Box<dyn std::error::Error>;

const USAGE: &str = "\
measure_lpm_depth [--sizes A,B,C] [--repeat N] [--passes N]

Prints one CSV row per size and arm on stdout, with the shape of the loaded set on
comment lines above the header. Reads the eBPF object from LORICA_EBPF_PLAIN_OBJ, or
LORICA_EBPF_OBJ if that is unset.";

/// One million, as everywhere else here: enough that the per-run average is stable.
const DEFAULT_REPEAT: u32 = 1_000_000;

/// The passes interleave the arms and the sizes rather than repeating each one in place,
/// for the reason `stage_cost.rs` gives: a single pass puts ten nanoseconds of drift on a
/// figure of two hundred, and drift that lands on one arm reads exactly like a property of
/// that arm.
///
/// It is also the only sample count there is. `duration` is already an average over
/// `repeat` invocations, so the tail this file can report is the one between passes — and
/// the tail is the interesting part, since the hit at a million entries showed a spread of
/// 35 ns against 1–6 ns everywhere else. Five passes make p99 the maximum; twenty-five make
/// it mean something, which is why the campaign asks for more.
const DEFAULT_PASSES: usize = 5;

/// `bench/results/floor-20260822T093726Z.json`, subtracted here so every row is comparable
/// with the rest of the project's figures.
const FLOOR_NS: u128 = 15;

const PROGRAM: &str = "lorica_xdp";
const GAME_PORT: u16 = 30_120;

const CASES: [&str; 4] = [
    "deep_miss_inside",
    "shallow_miss_control",
    "hit_scattered",
    "hit_clustered",
];

/// 10.0.0.0/8: sixteen million hosts, so the million the gateway profile reserves sits at a
/// density of one in sixteen and an address drawn inside it is usually absent.
const V4_BASE: u32 = 0x0a00_0000;

/// Outside every /8 the loader touches, so it leaves the trie at the first byte.
const CONTROL_SRC: [u8; 4] = [203, 0, 113, 1];

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

struct Trie {
    entries: u32,
    ebpf: Ebpf,
    memlock: u64,
    /// Every loaded host as a 32-bit v4 address, ascending. Every question the arms ask —
    /// which /16s exist, whether an address is present, how deep an address agrees with the
    /// set — is answered from this and never from the formula that built it, so a change to
    /// the loader cannot leave arm 1 drawing outside the populated region.
    sorted: Vec<u32>,
    /// Second octets that ended up populated, ascending.
    sixteens: Vec<u8>,
    /// The /16 holding the most entries, which is the cluster arm 4 stays inside.
    densest: u8,
}

impl Trie {
    /// How many leading bits of the address the closest loaded entry agrees on. 32 means
    /// the address is one of them.
    ///
    /// Only the two sorted neighbours can achieve the longest common prefix against a set
    /// of unsigned integers, so this costs two comparisons whatever the size of the trie.
    fn shared_bits(&self, addr: u32) -> u32 {
        let at = self.sorted.partition_point(|held| *held < addr);
        [at.checked_sub(1), Some(at)]
            .into_iter()
            .flatten()
            .filter_map(|index| self.sorted.get(index))
            .map(|held| (held ^ addr).leading_zeros())
            .max()
            .unwrap_or(0)
    }

    /// The loaded hosts inside one populated /16, ascending and never empty.
    fn inside(&self, octet: u8) -> &[u32] {
        inside(&self.sorted, octet)
    }
}

fn inside(sorted: &[u32], octet: u8) -> &[u32] {
    let low = V4_BASE | (u32::from(octet) << 16);
    let high = low | 0xffff;
    let start = sorted.partition_point(|held| *held < low);
    let end = sorted.partition_point(|held| *held <= high);
    &sorted[start..end]
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
    // which the deployment profiles already budget for. A size that will not load is said
    // out loud and dropped: reporting a smaller trie under a larger label is the one
    // failure this measurement could not survive.
    let mut loaded = Vec::with_capacity(sizes.len());
    for &entries in &sizes {
        match load(&object, entries) {
            Ok(trie) => loaded.push(trie),
            Err(err) => eprintln!("SKIP {entries} entries: {err}"),
        }
    }
    if loaded.is_empty() {
        return Err("no size could be loaded".into());
    }

    let plan: Vec<Vec<Vec<u32>>> = loaded
        .iter()
        .map(|trie| plan_probes(trie, passes))
        .collect::<Result<_, _>>()?;
    for (trie, probes) in loaded.iter().zip(&plan) {
        guard_the_arms_apart(trie, probes);
        classification_holds(trie, probes)?;
    }

    println!(
        "# repeat {repeat}, {passes} interleaved passes, floor {FLOOR_NS} ns subtracted; \
         duration is task-clock over 2.06, so the ratios are the readable part"
    );
    for (trie, probes) in loaded.iter().zip(&plan) {
        println!(
            "# {} entries: all /32, as 128-bit v4-mapped keys, spread over 10.0.0.0/8; \
             {} distinct /16s populated, densest 10.{}.0.0/16 with {}; memlock {} B",
            trie.entries,
            trie.sixteens.len(),
            trie.densest,
            trie.inside(trie.densest).len(),
            trie.memlock
        );
        for (case, addrs) in CASES.iter().zip(probes) {
            let bits: Vec<u32> = addrs.iter().map(|addr| trie.shared_bits(*addr)).collect();
            println!(
                "#   {case:<20} first {}, shared bits {}..{} over {} draws",
                dotted(addrs[0]),
                bits.iter().min().expect("one pass at least"),
                bits.iter().max().expect("one pass at least"),
                addrs.len()
            );
        }
    }

    println!(
        "entries,case,repeat,ns_above_floor,ns_spread,memlock_bytes,\
         p99_ns_above_floor,passes,shared_bits"
    );

    // The arms alternate inside a pass and so do the sizes: an arm measured in a block of
    // its own carries whatever the machine was doing during that block.
    let mut samples = vec![vec![Vec::with_capacity(passes); CASES.len()]; loaded.len()];
    for pass in 0..passes {
        for (index, trie) in loaded.iter().enumerate() {
            for (taken, addrs) in samples[index].iter_mut().zip(&plan[index]) {
                let pkt = frame(addrs[pass].to_be_bytes());
                taken.push(run_ns(&trie.ebpf, &pkt, repeat)?);
            }
        }
    }

    for (index, trie) in loaded.iter().enumerate() {
        for (case, name) in CASES.iter().enumerate() {
            let shared = plan[index][case]
                .iter()
                .map(|addr| trie.shared_bits(*addr))
                .min()
                .expect("one pass at least");
            let taken = &mut samples[index][case];
            let low = *taken.iter().min().expect("one pass at least");
            let high = *taken.iter().max().expect("one pass at least");
            taken.sort_unstable();
            println!(
                "{},{name},{repeat},{},{},{},{},{passes},{shared}",
                trie.entries,
                percentile(taken, 50).saturating_sub(FLOOR_NS),
                high - low,
                trie.memlock,
                percentile(taken, 99).saturating_sub(FLOOR_NS),
            );
        }
    }
    Ok(())
}

/// Nearest rank over the passes, which is all the resolution there is: `duration` is
/// already an average over `repeat` invocations, so the only tail visible from here is the
/// one between passes. `len * 50 / 100` is the median the earlier version of this file
/// printed, so that column keeps its meaning.
fn percentile(sorted: &[u128], p: usize) -> u128 {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

/// One source address per arm and pass.
///
/// Arm 1 draws from a /16 the loaded set populated, taken from the set itself, so the arm
/// cannot silently degrade into arm 2 when the loader changes. Arm 3 walks the populated
/// /16s so consecutive passes land far apart in the key space; arm 4 stays inside the
/// densest one, so its last levels are the same nodes every pass. Below a few hundred
/// entries a /16 holds fewer hosts than there are passes and arm 4 repeats an address,
/// which is what a cluster amounts to at that size.
fn plan_probes(trie: &Trie, passes: usize) -> Result<Vec<Vec<u32>>, Failure> {
    let control = u32::from_be_bytes(CONTROL_SRC);
    let cluster = trie.inside(trie.densest);
    let mut out = Vec::with_capacity(CASES.len());
    for case in CASES {
        let mut addrs = Vec::with_capacity(passes);
        for pass in 0..passes {
            let spread = trie.sixteens[pass * trie.sixteens.len() / passes];
            addrs.push(match case {
                "shallow_miss_control" => control,
                "deep_miss_inside" => absent_inside(trie, spread, pass)?,
                "hit_scattered" => {
                    let present = trie.inside(spread);
                    present[pass % present.len()]
                }
                _ => cluster[pass % cluster.len()],
            });
        }
        out.push(addrs);
    }
    Ok(out)
}

/// An address inside a populated /16 that is not one of the entries.
///
/// The low half is mixed from the pass rather than drawn from a generator, so a rerun of
/// the same sweep probes the same addresses and two campaigns can be subtracted. At the
/// densest size one address in sixteen is taken, so the first attempt almost always
/// answers; the loop is there because a /16 of a small trie is nearly empty and a /16 of a
/// hypothetical dense one would not be.
fn absent_inside(trie: &Trie, octet: u8, pass: usize) -> Result<u32, Failure> {
    for attempt in 0..64u32 {
        let mixed = (pass as u32)
            .wrapping_mul(0x9e37_79b1)
            .wrapping_add(attempt.wrapping_mul(0x85eb_ca6b))
            .rotate_left(13);
        let addr = V4_BASE | (u32::from(octet) << 16) | (mixed & 0xffff);
        if trie.sorted.binary_search(&addr).is_err() {
            return Ok(addr);
        }
    }
    Err(format!(
        "64 draws inside 10.{octet}.0.0/16 were all present, so arm 1 has nowhere to stand \
         at {} entries",
        trie.entries
    )
    .into())
}

/// Arm 1 and arm 2 have to be verified different. Two arms that coincide report the same
/// number twice, and a reader takes the agreement for a property of the trie rather than
/// for the two probes having been the same probe.
fn guard_the_arms_apart(trie: &Trie, probes: &[Vec<u32>]) {
    let inside = probes[0]
        .iter()
        .map(|addr| trie.shared_bits(*addr))
        .min()
        .expect("one pass at least");
    let outside = probes[1]
        .iter()
        .map(|addr| trie.shared_bits(*addr))
        .max()
        .expect("one pass at least");
    assert!(
        inside > outside,
        "at {} entries the shallowest arm-1 draw shares {inside} bits with the loaded set \
         and the control shares {outside}: the two arms are measuring the same walk",
        trie.entries
    );
}

/// That the trie holds what this file thinks it holds, checked against the kernel once per
/// size before anything is timed, while the buckets are still full.
///
/// A hit that does not drop means arms 3 and 4 are timing a miss under a label that says
/// hit, and every ratio in the table would then be between two misses.
fn classification_holds(trie: &Trie, probes: &[Vec<u32>]) -> Result<(), Failure> {
    let hit = run_action(&trie.ebpf, &frame(probes[2][0].to_be_bytes()))?;
    if hit != XDP_DROP {
        return Err(format!(
            "{} returned {hit} at {} entries, and a loaded source has to be dropped",
            dotted(probes[2][0]),
            trie.entries
        )
        .into());
    }
    let miss = run_action(&trie.ebpf, &frame(probes[1][0].to_be_bytes()))?;
    if miss != XDP_PASS {
        return Err(format!(
            "the control source returned {miss} at {} entries, and an absent source has to \
             walk the pipeline to the end",
            trie.entries
        )
        .into());
    }
    Ok(())
}

fn dotted(addr: u32) -> String {
    let octets = addr.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
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
    Ok(run(ebpf, frame, repeat)?.0)
}

fn run_action(ebpf: &Ebpf, frame: &[u8]) -> Result<u32, Failure> {
    Ok(run(ebpf, frame, 1)?.1)
}

fn run(ebpf: &Ebpf, frame: &[u8], repeat: u32) -> Result<(u128, u32), Failure> {
    let program: &Xdp = ebpf
        .program(PROGRAM)
        .ok_or("the program disappeared")?
        .try_into()?;
    let result = program.test_run(TestRunOptions {
        data_in: Some(frame),
        repeat,
        ..Default::default()
    })?;
    Ok((result.duration.as_nanos(), result.return_value))
}

fn object_bytes() -> Result<Vec<u8>, Failure> {
    let path = env::var("LORICA_EBPF_PLAIN_OBJ")
        .or_else(|_| env::var("LORICA_EBPF_OBJ"))
        .map_err(|_| "neither LORICA_EBPF_PLAIN_OBJ nor LORICA_EBPF_OBJ is set")?;
    fs::read(&path).map_err(|err| format!("cannot read the eBPF object at {path}: {err}").into())
}

/// One sized, verified, filled program, and the description of what went into it.
fn load(object: &[u8], entries: u32) -> Result<Trie, Failure> {
    let mut ebpf = maps_at_size(object, entries)?;
    verify(&mut ebpf)?;
    let fd = maps::fd(&ebpf, "UNIFIED_LIST").ok_or("no UNIFIED_LIST map in the object")?;
    let list: Vec<(LpmKey, LpmValue)> = (0..entries)
        .map(|index| (key(host_addr(index)), entry(CounterId::COUNT + index)))
        .collect();
    lpm::load(fd, &list, 10_000)?;
    let memlock = maps::memlock_bytes(fd)?;

    let mut sorted: Vec<u32> = (0..entries).map(host_addr).collect();
    sorted.sort_unstable();
    let sixteens: Vec<u8> = sorted
        .iter()
        .map(|addr| (addr >> 16) as u8)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let densest = *sixteens
        .iter()
        .max_by_key(|octet| inside(&sorted, **octet).len())
        .ok_or("a trie was loaded with no entry at all")?;

    Ok(Trie {
        entries,
        ebpf,
        memlock,
        sorted,
        sixteens,
        densest,
    })
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

/// A distinct /32 per index, spread over 10.0.0.0/8 rather than laid down consecutively.
///
/// Consecutive addresses fill the trie densely from the bottom, and then the only absent
/// address sharing a long prefix with an entry is the one just past the last one written:
/// arm 1 would probe the frontier of the fill at every size, diverge at the same bit at
/// every size, and report a flat curve that belongs to this function. Multiplying the index
/// by an odd constant modulo 2^24 is a bijection, so the set still holds exactly `entries`
/// distinct hosts, and the second octet — the one arm 1 draws its /16 from — comes from the
/// well-mixed high bits of the product.
///
/// One prefix length and no other, deliberately. A mix of /32s and /24s would make the
/// depth of a walk depend on which length it met, and depth is the only variable this file
/// is trying to read.
fn host_addr(index: u32) -> u32 {
    V4_BASE | (index.wrapping_mul(0x9e37_79b1) & 0x00ff_ffff)
}

fn key(addr: u32) -> LpmKey {
    LpmKey::v4(addr.to_be_bytes(), 32)
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
