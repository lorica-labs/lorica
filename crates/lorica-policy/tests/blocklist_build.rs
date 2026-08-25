//! What a snapshot has to be true of before the builder is allowed to hand it over.
//!
//! Every case here is a refusal the builder owes the operator or an invariant the packet
//! path is compiled against. The probe count is the second kind: `lorica-ebpf` unrolls
//! `OA_PROBES` steps and cannot loop further, so a snapshot whose worst probe sequence
//! reaches that number is unreadable rather than slow.

use std::time::Instant;

use lorica_common::Action;
use lorica_common::blocklist::{
    CLASS24_PREFIX_BITS, Class24, OA_MAX_KEYS, OA_PROBES, OA_SLOTS, OaSlot, class24_get, oa_insert,
    oa_lookup, oa_occupied, oa_psl,
};
use lorica_policy::blocklist::{BuildError, build};

fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

/// One `/25` per 128 addresses from `10.0.0.0` up, which is [`OA_MAX_KEYS`] keys exactly.
///
/// The full permitted load and not a tenth of it, because a probe count measured at a tenth
/// of the load would agree with any constant somebody chose to compile in.
fn full_load() -> Vec<(u32, u32, Action)> {
    (0..(OA_MAX_KEYS / 128) as u32)
        .map(|i| {
            let action = if i % 3 == 0 {
                Action::Allow
            } else {
                Action::Drop
            };
            (v4(10, 0, 0, 0) + i * 128, 25, action)
        })
        .collect()
}

/// A million scattered `/32`, which is what a bought blocklist looks like.
///
/// Contiguous `/25` blocks and scattered hosts are not the same load on the hash: the probe
/// count has to cover the worse of the two, so both are measured.
fn scattered_load() -> Vec<(u32, u32, Action)> {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut keys = Vec::with_capacity(OA_MAX_KEYS);
    for i in 0..OA_MAX_KEYS {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let action = if i % 3 == 0 {
            Action::Allow
        } else {
            Action::Drop
        };
        keys.push(((state >> 32) as u32, 32, action));
    }
    keys.sort_unstable_by_key(|&(key, _, _)| key);
    keys.dedup_by_key(|&mut (key, _, _)| key);
    keys
}

/// The number the compiled probe count has to cover, taken off the finished table.
///
/// The second half is the trap this test exists to hold shut. `oa_insert` reports the
/// distance the key it was given ended up at, but a later insertion can displace that key
/// further from home, and the larger number is the one an unrolled lookup has to reach.
/// Reading the return values instead of the table under-reports the worst case.
#[test]
fn the_worst_probe_sequence_is_read_off_the_finished_table() {
    let scattered = scattered_load();
    let snapshot = build(&scattered, 0).expect("a million literal /32 need no expansion");

    let mut table = vec![OaSlot::default(); OA_SLOTS];
    let mut reported = 0u8;
    for &(key, _, action) in &scattered {
        reported = reported.max(oa_insert(&mut table, key, action).expect("within the count"));
    }
    println!(
        "oa-psl-scattered keys={} load={:.3} scanned={} reported_by_insert={reported}",
        snapshot.keys,
        snapshot.keys as f64 / OA_SLOTS as f64,
        snapshot.worst_psl
    );
    assert!(
        reported <= snapshot.worst_psl,
        "the return values cannot exceed the finished table"
    );
    assert!(
        (snapshot.worst_psl as u32) < OA_PROBES,
        "worst probe sequence {} against a compiled {OA_PROBES}",
        snapshot.worst_psl
    );

    let snapshot = build(&full_load(), usize::MAX).expect("the full permitted load builds");

    let scanned = snapshot
        .oa
        .iter()
        .filter(|slot| oa_occupied(slot.tag))
        .map(|slot| oa_psl(slot.tag))
        .max()
        .expect("the table is not empty");
    assert_eq!(scanned, snapshot.worst_psl);
    assert!(
        (snapshot.worst_psl as u32) < OA_PROBES,
        "worst probe sequence {} against a compiled {OA_PROBES}",
        snapshot.worst_psl
    );

    // The same keys, inserted again, keeping only what each insertion reported about itself.
    let mut table = vec![OaSlot::default(); OA_SLOTS];
    let mut reported = 0u8;
    for i in 0..(OA_MAX_KEYS / 128) as u32 {
        let base = v4(10, 0, 0, 0) + i * 128;
        for key in base..base + 128 {
            let psl = oa_insert(&mut table, key, Action::Drop).expect("within the probe count");
            reported = reported.max(psl);
        }
    }
    println!(
        "oa-psl keys={} load={:.3} scanned={} reported_by_insert={reported} compiled={OA_PROBES}",
        snapshot.keys,
        snapshot.keys as f64 / OA_SLOTS as f64,
        snapshot.worst_psl
    );
    assert!(
        reported <= snapshot.worst_psl,
        "the return values cannot exceed the finished table"
    );
}

/// The load factor ceiling is in the format, so the builder refuses past it instead of
/// handing back a table whose average miss costs five probes instead of 1.33.
#[test]
fn a_load_factor_over_a_half_is_refused() {
    let mut prefixes = full_load();
    assert_eq!(prefixes.len() * 128, OA_MAX_KEYS);
    prefixes.push((v4(203, 0, 113, 1), 32, Action::Drop));

    match build(&prefixes, usize::MAX) {
        Err(BuildError::TooManyKeys { keys, limit }) => {
            assert_eq!(keys, OA_MAX_KEYS + 1);
            assert_eq!(limit, OA_MAX_KEYS);
        }
        other => panic!("expected a refusal past the load factor, got {other:?}"),
    }
}

/// The tag carries a verdict and not membership, so the `/32` wins with the opposite one.
///
/// And the `/8` does not evaporate for the rest of that `/24`: `Table` replaces the code of
/// the whole block, so the builder writes the `/8`'s answer out for the 255 addresses that
/// have nowhere else to keep it.
#[test]
fn a_deny_eight_and_an_allow_thirty_two_carry_opposite_verdicts() {
    let snapshot = build(
        &[
            (v4(10, 0, 0, 0), 8, Action::Drop),
            (v4(10, 1, 2, 3), 32, Action::Allow),
        ],
        1024,
    )
    .expect("builds");

    assert_eq!(
        class24_get(&snapshot.class24, v4(10, 1, 2, 3)),
        Class24::Table
    );
    assert_eq!(
        oa_lookup(&snapshot.oa, v4(10, 1, 2, 3)),
        Some(Action::Allow)
    );
    assert_eq!(oa_lookup(&snapshot.oa, v4(10, 1, 2, 4)), Some(Action::Drop));

    // Every other /24 of the /8 answers from CLASS24 and never reaches the table.
    assert_eq!(
        class24_get(&snapshot.class24, v4(10, 9, 9, 9)),
        Class24::Deny
    );
    assert_eq!(oa_lookup(&snapshot.oa, v4(10, 9, 9, 9)), None);
    assert_eq!(snapshot.keys, 256);
}

/// Declaration order settles nothing. The `/25` is written second and still loses.
#[test]
fn an_expansion_does_not_rewrite_an_explicit_thirty_two() {
    let snapshot = build(
        &[
            (v4(10, 0, 0, 5), 32, Action::Allow),
            (v4(10, 0, 0, 0), 25, Action::Drop),
        ],
        1024,
    )
    .expect("builds");

    assert_eq!(
        oa_lookup(&snapshot.oa, v4(10, 0, 0, 5)),
        Some(Action::Allow)
    );
    assert_eq!(oa_lookup(&snapshot.oa, v4(10, 0, 0, 6)), Some(Action::Drop));
    assert_eq!(snapshot.keys, 128);
}

/// A truncated expansion is a rule that half applies, which is the failure nobody can see
/// from the configuration file. The bound refuses.
#[test]
fn the_expansion_bound_refuses_instead_of_truncating() {
    let one_slash_25 = [(v4(10, 0, 0, 0), 25, Action::Drop)];

    match build(&one_slash_25, 127) {
        Err(BuildError::ExpansionBudget { wanted, budget }) => {
            assert_eq!(wanted, 128);
            assert_eq!(budget, 127);
        }
        other => panic!("expected a refusal on the expansion bound, got {other:?}"),
    }

    let snapshot = build(&one_slash_25, 128).expect("128 keys inside a budget of 128");
    assert_eq!(snapshot.keys, 128);
    assert_eq!(snapshot.expanded, 128);
}

/// Exhaustive and not sampled: the builder runs this itself before it returns, and what is
/// here is the same check from outside, so a bug that skipped it inside would still show.
#[test]
fn every_inserted_key_round_trips() {
    let prefixes = full_load();

    let started = Instant::now();
    let snapshot = build(&prefixes, usize::MAX).expect("builds");
    let elapsed = started.elapsed();

    assert_eq!(snapshot.keys, OA_MAX_KEYS);
    for &(base, _, action) in &prefixes {
        for key in base..base + 128 {
            assert_eq!(
                oa_lookup(&snapshot.oa, key),
                Some(action),
                "key {key:#010x}"
            );
        }
    }
    println!(
        "oa-rebuild keys={} bytes={} millis={:.1}",
        snapshot.keys,
        snapshot.class24.len() + snapshot.oa.len() * std::mem::size_of::<OaSlot>(),
        elapsed.as_secs_f64() * 1e3
    );
}

/// `0.0.0.0` is `key == 0` and a fresh table is all zeroes, so the address every
/// misconfigured source uses is the one a builder can lose without noticing.
#[test]
fn the_zero_address_stays_representable() {
    // The floor of a rebuild: 20 MiB allocated and zeroed with nothing in it, which is what
    // separates the cost of the tables from the cost of the keys.
    let started = Instant::now();
    let virgin = build(&[], 0).expect("an empty configuration builds");
    println!(
        "oa-rebuild-floor keys=0 millis={:.1}",
        started.elapsed().as_secs_f64() * 1e3
    );

    assert_eq!(class24_get(&virgin.class24, 0), Class24::None);
    assert_eq!(oa_lookup(&virgin.oa, 0), None);
    assert_eq!(virgin.keys, 0);

    let snapshot = build(&[(0, 32, Action::Drop)], 0).expect("builds");
    assert_eq!(class24_get(&snapshot.class24, 0), Class24::Table);
    assert_eq!(oa_lookup(&snapshot.oa, 0), Some(Action::Drop));
    assert_eq!(oa_lookup(&snapshot.oa, v4(0, 0, 0, 1)), None);
}

/// The reason there is no trie: every prefix at least this short is resolved by one access,
/// whatever its length, and the table stays untouched.
#[test]
fn a_prefix_no_longer_than_a_slash_twenty_four_answers_from_class24_alone() {
    let snapshot = build(
        &[
            (v4(10, 0, 0, 0), 8, Action::Drop),
            (v4(10, 90, 1, 0), 24, Action::Allow),
            (v4(192, 168, 0, 0), 16, Action::Drop),
        ],
        0,
    )
    .expect("builds");

    assert_eq!(
        class24_get(&snapshot.class24, v4(10, 90, 1, 200)),
        Class24::Allow
    );
    assert_eq!(
        class24_get(&snapshot.class24, v4(10, 90, 2, 200)),
        Class24::Deny
    );
    assert_eq!(
        class24_get(&snapshot.class24, v4(192, 168, 255, 1)),
        Class24::Deny
    );
    assert_eq!(
        class24_get(&snapshot.class24, v4(203, 0, 113, 1)),
        Class24::None
    );

    assert_eq!(snapshot.keys, 0);
    assert!(
        snapshot.oa.iter().all(|slot| !oa_occupied(slot.tag)),
        "a configuration of prefixes no longer than /{CLASS24_PREFIX_BITS} leaves the table empty"
    );
}

/// Host bits outside the prefix are refused here too, and for the same reason they are
/// refused in `compile::lpm`: masking them would accept the line and mean something else.
#[test]
fn a_prefix_carrying_host_bits_is_refused() {
    assert!(matches!(
        build(&[(v4(10, 90, 1, 7), 24, Action::Drop)], 0),
        Err(BuildError::PrefixHasHostBits { .. })
    ));
    assert!(matches!(
        build(&[(v4(10, 0, 0, 0), 33, Action::Drop)], 0),
        Err(BuildError::PrefixTooLong { .. })
    ));
}

/// `CLASS24` has two bits and four codes, two of which are verdicts. A rule the block table
/// cannot spell is refused rather than rounded to the nearest verdict.
#[test]
fn a_verdict_the_block_table_cannot_spell_is_refused() {
    assert!(matches!(
        build(&[(v4(10, 0, 0, 0), 16, Action::RateLimit)], 0),
        Err(BuildError::ShortPrefixAction { .. })
    ));
    // The tag has three bits, so the same verdict on a /32 is fine.
    let snapshot = build(&[(v4(10, 0, 0, 1), 32, Action::RateLimit)], 0).expect("builds");
    assert_eq!(
        oa_lookup(&snapshot.oa, v4(10, 0, 0, 1)),
        Some(Action::RateLimit)
    );
}
