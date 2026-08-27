//! The cuckoo lookup against the Robin Hood one it would replace, verdict for verdict.
//!
//! **Why this and not a list of cases.** The candidate structure changes the *shape* of the
//! answer, not the answer: a key is in one of two buckets instead of somewhere in a probe run,
//! the signature filters before the key is read, and the Robin Hood early exit disappears
//! entirely. A divergence therefore lives in a combination — a signature collision inside a
//! bucket that also happens to be full, a key whose two buckets are adjacent, an address
//! whose signature is the forced-nonzero one — and not in any single line somebody could think
//! to write down. So the two are loaded with the same key set and asked the same questions,
//! which is what `lorica-dataplane/tests/blocklist_equivalence.rs` does for the flat tables
//! against the trie.
//!
//! **What "exhaustive" means here, precisely.** Every key of the set, both directions; every
//! neighbour of every key at ±1, which is where a bucket or probe boundary lives; and a seeded
//! sweep of absent keys. With `LORICA_SIM_EXHAUSTIVE=1` it is instead all 2^32 addresses, which
//! is the honest whole and takes minutes rather than seconds — the default is what a `cargo
//! test` run can afford and the flag is what a release is checked with. The counts of each are
//! printed, because an equivalence proved on a corpus that never reached the table would be a
//! green result about nothing.
//!
//! **Where the two are allowed to differ, and it is nowhere.** Both structures resolve
//! longest-prefix-match at construction and both compare the key exactly, so neither can answer
//! for an address it does not hold. There is no refusal to except: the load factor ceiling
//! belongs to the builder above both of them.

use std::collections::BTreeMap;

use lorica_common::{
    Action,
    blocklist::{
        OA_MAX_KEYS, OA_SLOTS, OaSlot,
        cuckoo::{CUCKOO_LANES, CuckooBucket, cuckoo_lookup},
        oa_insert, oa_lookup,
    },
};
use lorica_policy::blocklist::cuckoo_from;

/// Written down so a failure is reproducible. A seed taken from the clock turns one divergence
/// into a story nobody can re-run.
const SEED: u64 = 0xc0c0_0a15_5eed_0001;

/// Keys the corpus carries. Half the slot count, which is the maximum load the format permits
/// and therefore the load a divergence is most likely at: the deeper the probe runs and the
/// fuller the buckets, the more of both structures a lookup has to walk.
const KEYS: usize = OA_MAX_KEYS;

/// Absent keys swept in the default run.
const ABSENT: usize = 4_000_000;

/// xorshift64. Deterministic, which is the only property a corpus generator needs here.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u32
    }
}

/// A verdict per key, and every one of the five is used: a structure that only ever stored
/// `Drop` would agree with anything about the three verdicts the later stages own.
fn verdict(index: usize) -> Action {
    match index % 5 {
        0 => Action::Drop,
        1 => Action::Allow,
        2 => Action::RateLimit,
        3 => Action::Mark,
        _ => Action::Continue,
    }
}

struct Corpus {
    keys: BTreeMap<u32, Action>,
    robin_hood: Vec<OaSlot>,
    cuckoo: Vec<CuckooBucket>,
}

fn corpus() -> Corpus {
    let mut rng = Rng(SEED | 1);
    let mut keys = BTreeMap::new();
    // Three quarters scattered and one quarter in whole `/24` blocks, so the corpus carries
    // both the pessimistic draw and the one the builder actually emits when an exception
    // inside a short prefix forces a block fill.
    while keys.len() < KEYS * 3 / 4 {
        let key = rng.next();
        let index = keys.len();
        keys.entry(key).or_insert_with(|| verdict(index));
    }
    while keys.len() < KEYS {
        let base = rng.next() & 0xffff_ff00;
        for offset in 0..256u32 {
            if keys.len() >= KEYS {
                break;
            }
            let index = keys.len();
            keys.entry(base | offset).or_insert_with(|| verdict(index));
        }
    }

    let mut robin_hood = vec![OaSlot::default(); OA_SLOTS];
    for (&key, &action) in &keys {
        oa_insert(&mut robin_hood, key, action)
            .unwrap_or_else(|| panic!("the Robin Hood table refused {key:#010x} at this load"));
    }

    // Filled through the same function a measurement would use, and from the finished Robin
    // Hood table rather than from the key map: that is what makes the two structures hold the
    // same keys with the same verdicts by construction instead of by two agreeing loops.
    let cuckoo = cuckoo_from(&robin_hood)
        .unwrap_or_else(|err| panic!("the cuckoo table refused this key set: {err}"));

    Corpus {
        keys,
        robin_hood,
        cuckoo,
    }
}

/// The invariant the branchless decode rests on, checked over the finished table.
///
/// Two occupied lanes of one bucket carrying the same signature would make the lowest-set-bit
/// decode answer for whichever of them is lower, so one of the two keys becomes unreachable.
/// The builder maintains it by choosing the victim; this is the check that says it did.
#[test]
fn no_bucket_holds_two_lanes_with_the_same_signature() {
    let corpus = corpus();
    let mut occupied = 0u64;
    for (index, bucket) in corpus.cuckoo.iter().enumerate() {
        let mut seen = [0u8; CUCKOO_LANES];
        let mut count = 0usize;
        for lane in 0..CUCKOO_LANES {
            let sig = (bucket.sigs >> (8 * lane)) as u8;
            if sig == 0 {
                continue;
            }
            occupied += 1;
            assert!(
                !seen[..count].contains(&sig),
                "bucket {index} carries signature {sig} twice, so the branchless decode cannot \
                 reach one of the two keys it belongs to"
            );
            seen[count] = sig;
            count += 1;
        }
    }
    assert_eq!(
        occupied, KEYS as u64,
        "the table holds {occupied} keys and the corpus has {KEYS}"
    );
}

#[test]
fn the_two_structures_answer_the_same_thing() {
    let corpus = corpus();
    let exhaustive = std::env::var("LORICA_SIM_EXHAUSTIVE").is_ok_and(|v| v != "0");

    let mut compared = 0u64;
    let mut reached = 0u64;
    let check = |key: u32, compared: &mut u64, reached: &mut u64| {
        let expected = corpus.keys.get(&key).copied();
        let from_rh = oa_lookup(&corpus.robin_hood, key);
        let from_cuckoo = cuckoo_lookup(&corpus.cuckoo, key);
        assert_eq!(
            from_rh, expected,
            "the Robin Hood table disagrees with the corpus about {key:#010x}, so the \
             comparison below would be between two wrong answers"
        );
        assert_eq!(
            from_cuckoo, from_rh,
            "the two structures disagree about {key:#010x}: cuckoo says {from_cuckoo:?}, \
             Robin Hood says {from_rh:?}"
        );
        *compared += 1;
        if expected.is_some() {
            *reached += 1;
        }
    };

    if exhaustive {
        for key in 0..=u32::MAX {
            check(key, &mut compared, &mut reached);
        }
        println!("cuckoo-equivalence: all {compared} addresses, {reached} of them in the table");
        return;
    }

    // Every key, and every neighbour of every key: the boundary between two buckets and the
    // step of a probe run are both at ±1, and an address one away from a member is the one a
    // sampled sweep is least likely to draw.
    for &key in corpus.keys.keys() {
        check(key, &mut compared, &mut reached);
        check(key.wrapping_sub(1), &mut compared, &mut reached);
        check(key.wrapping_add(1), &mut compared, &mut reached);
    }
    let present_and_neighbours = compared;

    let mut rng = Rng(SEED ^ 0x5157_5157_5157_5157 | 1);
    for _ in 0..ABSENT {
        check(rng.next(), &mut compared, &mut reached);
    }

    println!(
        "cuckoo-equivalence: {compared} addresses compared ({present_and_neighbours} keys and \
         their neighbours, {ABSENT} drawn), {reached} of them in the table. Set \
         LORICA_SIM_EXHAUSTIVE=1 to sweep all 2^32 instead."
    );
    assert!(
        reached >= KEYS as u64,
        "every key of the corpus has to have been asked for, got {reached} of {KEYS}"
    );
}
