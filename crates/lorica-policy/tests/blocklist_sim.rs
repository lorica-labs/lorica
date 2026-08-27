//! What the two table designs do at the load factor the format permits, over as many draws as
//! somebody asks for.
//!
//! Not a test: it takes parameters, prints one record and asserts almost nothing. libtest has
//! no way to pass `--trials` through, so this target owns its own `main`, which is the shape
//! `lorica-dataplane/tests/measure_batch.rs` set. Run with no argument it measures nothing and
//! says so, which is what a full `cargo test` run gets.
//!
//! # What it answers, and why each answer had to be run rather than reasoned
//!
//! **The tail of the maximum probe length under Robin Hood.** `OA_PROBES` is 16 and the dossier
//! recorded a measured maximum of 11, which was one draw and got read as a bound. It is not
//! one: the maximum at a load factor of exactly 0.5 is a random variable, and the whole
//! question of whether `OA_PROBES` may be reduced is the shape of its upper tail. The hash is
//! not keyed, so a key set that draws past the constant is refused **deterministically and for
//! ever** — there is no re-seed for an operator to try. That is why this is a distribution to
//! publish and not a number to discover in production.
//!
//! The Robin Hood used here is **unbounded**, unlike
//! [`oa_insert`](lorica_common::blocklist::oa_insert), which refuses at `OA_PROBES`. Same hash,
//! same step, same displacement rule — the bound is dropped precisely because the point is to
//! see the distribution the bound would refuse.
//!
//! **Whether a bucketised cuckoo can hold the same keys at all.** It is the candidate
//! replacement and its selling point is the absence of the cliff above; its cost is that
//! insertion *can* fail, which is exactly what Robin Hood promises never to do. So the failure
//! count and the worst displacement chain are the numbers that decide it, and the price of the
//! branchless decode — evictions forced only by the one-signature-per-bucket invariant — is
//! reported beside them.
//!
//! **What eight-bit signatures cost at lookup.** A signature that matches a lane holding
//! another key costs one key comparison and no wrong verdict. How often that happens on an
//! absent key is the number that turns "signatures filter" into a measurement.
//!
//! # Two key shapes, because one of them is what the builder actually produces
//!
//! Scattered `/32` are the pessimistic draw. Whole `/24` blocks are what the builder emits when
//! one exception forces a block fill, and 256 consecutive addresses hash to 256 unrelated slots
//! but arrive in an order nothing shuffled. Both are drawn; the dossier's own figures differ
//! between them, which is the reason neither may stand alone.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Instant,
};

use lorica_common::{
    Action,
    blocklist::{
        OA_INDEX_MASK, OA_MAX_KEYS, OA_SLOTS, OaSlot,
        cuckoo::{
            CUCKOO_BUCKETS, CUCKOO_LANES, CuckooBucket, cuckoo_hash, cuckoo_lane, cuckoo_lookup,
            cuckoo_match, cuckoo_occupancy, cuckoo_sig,
        },
        oa_index, oa_occupied, oa_psl, oa_step, oa_tag,
    },
};
use lorica_policy::blocklist::build;

const USAGE: &str = "\
blocklist_sim [--trials N] [--seed HEX] [--absent N] [--rebuild]

  --trials N    key sets to draw per shape (default 8; the campaign figure is 1000)
  --seed HEX    the draw is a function of this and nothing else
  --absent N    absent keys probed per trial for the signature false-hit rate (default 100000)
  --rebuild     also time one full lorica-policy rebuild at the maximum load

Prints one record per shape on stdout. Deterministic: the same arguments give the same
numbers on any machine.";

type Failure = Box<dyn std::error::Error>;

fn main() -> Result<(), Failure> {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("blocklist_sim: no argument, nothing measured\n\n{USAGE}");
        return Ok(());
    }

    let mut trials: u64 = 8;
    let mut seed: u64 = 0x00c0_ffee_0000_0001;
    let mut absent: usize = 100_000;
    let mut rebuild = false;

    let next = |at: usize| -> Result<&String, Failure> {
        argv.get(at + 1)
            .ok_or_else(|| format!("{} needs a value", argv[at]).into())
    };
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--trials" => {
                trials = next(i)?.parse()?;
                i += 2;
            }
            "--seed" => {
                seed = u64::from_str_radix(next(i)?.trim_start_matches("0x"), 16)?;
                i += 2;
            }
            "--absent" => {
                absent = next(i)?.parse()?;
                i += 2;
            }
            "--rebuild" => {
                rebuild = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}").into()),
        }
    }
    if trials == 0 {
        return Err("--trials 0 measures nothing".into());
    }

    println!(
        "blocklist_sim: load {:.3} = {} keys in {} slots, {} buckets of {}, {} build, \
         seed {seed:#018x}",
        OA_MAX_KEYS as f64 / OA_SLOTS as f64,
        OA_MAX_KEYS,
        OA_SLOTS,
        CUCKOO_BUCKETS,
        CUCKOO_LANES,
        if cfg!(debug_assertions) {
            "unoptimised"
        } else {
            "release"
        },
    );

    for shape in [Shape::Scattered, Shape::Blocks] {
        run(shape, trials, seed, absent);
    }

    if rebuild {
        time_a_rebuild();
    }
    Ok(())
}

/// How a key set is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// Scattered `/32`, which is the pessimistic draw and the one the dossier's PSL figures
    /// were taken on.
    Scattered,
    /// Whole `/24` blocks, which is what the builder emits when one exception inside a short
    /// prefix forces the other 255 addresses to be written out.
    Blocks,
}

impl Shape {
    const fn name(self) -> &'static str {
        match self {
            Self::Scattered => "scattered /32",
            Self::Blocks => "whole /24 blocks",
        }
    }
}

/// xorshift64, so a draw is a function of its seed and of nothing else. Not a cryptographic
/// generator and it does not need to be: what is being measured is a hash's behaviour on
/// arbitrary keys, and a reproducible arbitrary is worth more here than an unpredictable one.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u32
    }
}

/// One key set at exactly the maximum load, deduplicated.
fn keyset(seed: u64, shape: Shape) -> Vec<u32> {
    let mut rng = Rng(seed | 1);
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(OA_MAX_KEYS);
    match shape {
        Shape::Scattered => {
            while keys.len() < OA_MAX_KEYS {
                let key = rng.next();
                if seen.insert(key) {
                    keys.push(key);
                }
            }
        }
        Shape::Blocks => {
            while keys.len() < OA_MAX_KEYS {
                let base = rng.next() & 0xffff_ff00;
                for offset in 0..256u32 {
                    let key = base | offset;
                    if keys.len() < OA_MAX_KEYS && seen.insert(key) {
                        keys.push(key);
                    }
                }
            }
        }
    }
    keys
}

/// Robin Hood, unbounded. Returns the maximum probe sequence length in the finished table.
///
/// Read off the finished table and not off what each insertion reported: a key displaced by a
/// later insertion sits further from home than its own insertion ever saw, and the gap is not
/// hypothetical — the builder's own test finds 10 by the first method and 11 by the second on
/// the same key set.
fn robin_hood_worst(keys: &[u32]) -> u32 {
    let mut table = vec![OaSlot::default(); OA_SLOTS];
    for &key in keys {
        insert_unbounded(&mut table, key);
    }
    table
        .iter()
        .filter(|slot| oa_occupied(slot.tag))
        .map(|slot| u32::from(oa_psl(slot.tag)))
        .max()
        .unwrap_or(0)
}

/// [`oa_insert`](lorica_common::blocklist::oa_insert) with the `OA_PROBES` refusal removed and
/// the probe length stored in full.
///
/// The tag's probe field is eight bits, which is far above anything a load factor of 0.5
/// reaches, so nothing here has to widen it.
fn insert_unbounded(table: &mut [OaSlot], key: u32) {
    let mut index = oa_index(key);
    let mut distance = 0u32;
    let mut carried_key = key;
    loop {
        let at = (index & OA_INDEX_MASK) as usize;
        let slot = table[at];
        let displace = u32::from(oa_psl(slot.tag));
        if !oa_occupied(slot.tag) || displace < distance {
            table[at] = OaSlot {
                key: carried_key,
                tag: oa_tag(carried_key, Action::Drop, distance as u8),
            };
            if !oa_occupied(slot.tag) {
                return;
            }
            carried_key = slot.key;
            distance = displace;
        }
        index = oa_step(index);
        distance += 1;
    }
}

/// What one cuckoo fill cost.
struct CuckooRun {
    table: Vec<CuckooBucket>,
    failures: u32,
    worst_kicks: u32,
    sig_evictions: u64,
    /// Occupied lanes whose signature another occupied lane of the same bucket also holds. The
    /// invariant says zero, and the branchless decode is only correct while it is.
    invariant_breaks: u32,
}

fn cuckoo_fill(keys: &[u32], seed: u64) -> CuckooRun {
    let mut table = vec![CuckooBucket::EMPTY; CUCKOO_BUCKETS];
    let mut rng = Rng(seed ^ 0xdead_beef_dead_beef | 1);
    let mut random = || rng.next();
    let mut run = CuckooRun {
        table: Vec::new(),
        failures: 0,
        worst_kicks: 0,
        sig_evictions: 0,
        invariant_breaks: 0,
    };
    for &key in keys {
        match lorica_common::blocklist::cuckoo::cuckoo_insert(
            &mut table,
            key,
            Action::Drop,
            &mut random,
        ) {
            Ok(cost) => {
                run.worst_kicks = run.worst_kicks.max(cost.kicks);
                run.sig_evictions += u64::from(cost.sig_evictions);
            }
            Err(_) => run.failures += 1,
        }
    }

    // The invariant, checked over the whole table rather than trusted. It is O(buckets), which
    // is the cheapest part of a rebuild, and it is the property the eBPF decode is compiled
    // against: two identical signatures in one bucket make the lowest-set-bit decode answer
    // for the wrong lane.
    for bucket in &table {
        let mut seen = [0u8; CUCKOO_LANES];
        let mut count = 0usize;
        for lane in 0..CUCKOO_LANES {
            let sig = (bucket.sigs >> (8 * lane)) as u8;
            if sig == 0 {
                continue;
            }
            if seen[..count].contains(&sig) {
                run.invariant_breaks += 1;
            }
            seen[count] = sig;
            count += 1;
        }
    }
    run.table = table;
    run
}

/// Absent keys whose signature matched a lane of one of their two buckets, which costs a key
/// comparison and nothing else.
///
/// Reported as a rate because it is the runtime price of eight bits rather than sixteen, and
/// the alternative — sixteen-bit signatures — would halve the lanes per cache line.
fn signature_false_hits(
    table: &[CuckooBucket],
    present: &BTreeSet<u32>,
    probes: usize,
    seed: u64,
) -> (u64, u64) {
    let mut rng = Rng(seed ^ 0x5157_5157_5157_5157 | 1);
    let mut hits = 0u64;
    let mut probed = 0u64;
    while probed < probes as u64 {
        let key = rng.next();
        if present.contains(&key) {
            continue;
        }
        probed += 1;
        let hash = cuckoo_hash(key);
        let sig = cuckoo_sig(hash);
        let home = lorica_common::blocklist::cuckoo::cuckoo_home(hash);
        let alt = lorica_common::blocklist::cuckoo::cuckoo_alt(
            home,
            lorica_common::blocklist::cuckoo::cuckoo_delta(key),
        );
        for bucket in [home, alt] {
            if cuckoo_lane(cuckoo_match(table[bucket as usize].sigs, sig)).is_some() {
                hits += 1;
            }
        }
        // And the lookup itself must still miss: a false hit that turned into a verdict would
        // be the one failure this whole design cannot have.
        assert_eq!(
            cuckoo_lookup(table, key),
            None,
            "an absent key {key:#010x} came back with a verdict"
        );
    }
    (hits, probed)
}

fn run(shape: Shape, trials: u64, seed: u64, absent: usize) {
    let mut psl = BTreeMap::new();
    let mut failures = 0u32;
    let mut worst_kicks = 0u32;
    let mut sig_evictions = 0u64;
    let mut invariant_breaks = 0u32;
    let mut false_hits = 0u64;
    let mut probed = 0u64;
    let mut lanes_used = 0u64;

    let started = Instant::now();
    for trial in 0..trials {
        let draw = seed ^ trial.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let keys = keyset(draw, shape);

        *psl.entry(robin_hood_worst(&keys)).or_insert(0u64) += 1;

        let run = cuckoo_fill(&keys, draw);
        failures += run.failures;
        worst_kicks = worst_kicks.max(run.worst_kicks);
        sig_evictions += run.sig_evictions;
        invariant_breaks += run.invariant_breaks;
        lanes_used += run
            .table
            .iter()
            .map(|bucket| u64::from(cuckoo_occupancy(bucket.sigs)))
            .sum::<u64>();

        if absent > 0 {
            let present: BTreeSet<u32> = keys.iter().copied().collect();
            let (hits, count) = signature_false_hits(&run.table, &present, absent, draw);
            false_hits += hits;
            probed += count;
        }
    }
    let elapsed = started.elapsed();

    let total: u64 = psl.values().sum();
    println!("--- {} ({trials} trials, {elapsed:.1?}) ---", shape.name());
    println!(
        "  robin hood, worst probe sequence length per trial: {:?}",
        psl
    );
    // The figure the whole `OA_PROBES` question turns on, stated for every candidate K rather
    // than for the one somebody proposed: a K is refusable if this is not zero.
    for k in [8u32, 10, 12, 14, 16] {
        let over: u64 = psl.range(k..).map(|(_, n)| n).sum();
        println!(
            "  P(worst >= {k:>2}) = {:>7.3} %   ({over} of {total} trials would be refused at \
             OA_PROBES = {k})",
            100.0 * over as f64 / total as f64
        );
    }
    println!(
        "  cuckoo 2x{CUCKOO_LANES}: {failures} insertion failures, worst displacement chain \
         {worst_kicks}, {sig_evictions} evictions forced by the signature invariant \
         ({:.4} per key), {invariant_breaks} invariant breaks in the finished tables",
        sig_evictions as f64 / (trials * OA_MAX_KEYS as u64) as f64,
    );
    println!(
        "  cuckoo occupancy: {lanes_used} of {} lanes filled ({:.4} of capacity)",
        trials * (CUCKOO_BUCKETS * CUCKOO_LANES) as u64,
        lanes_used as f64 / (trials * (CUCKOO_BUCKETS * CUCKOO_LANES) as u64) as f64,
    );
    if probed > 0 {
        println!(
            "  signature false hits: {false_hits} over {probed} absent keys ({:.4} per lookup, \
             {:.4} expected for 8 bits over two buckets at this occupancy)",
            false_hits as f64 / probed as f64,
            2.0 * (lanes_used as f64 / (trials * CUCKOO_BUCKETS as u64) as f64) / 255.0,
        );
    }
}

/// One full rebuild through the real builder, at the load the format permits.
///
/// The dossier's reference is 142 ms for 1 048 576 keys in release, exhaustive round trip
/// included, and the question the cuckoo variant raises is whether a second hash and the
/// signature invariant push it past 150. This is the Robin Hood side of that comparison, taken
/// through `lorica_policy::blocklist::build` so it is the shipped path and not a fixture.
fn time_a_rebuild() {
    // Contiguous `/25` blocks, which is what `blocklist_build.rs` uses for the same figure: two
    // keys per line of configuration and the maximum load reached exactly.
    let prefixes: Vec<(u32, u32, Action)> = (0..OA_MAX_KEYS / 128)
        .map(|i| ((i as u32) << 7, 25u32, Action::Drop))
        .collect();

    let started = Instant::now();
    let snapshot = build(&prefixes, usize::MAX).expect("the maximum load builds");
    let elapsed = started.elapsed();
    println!(
        "--- rebuild ({} build) ---",
        if cfg!(debug_assertions) {
            "unoptimised"
        } else {
            "release"
        }
    );
    println!(
        "  robin hood, through lorica_policy::blocklist::build: {} keys, worst psl {}, \
         {:.1} ms",
        snapshot.keys,
        snapshot.worst_psl,
        elapsed.as_secs_f64() * 1e3
    );
}
