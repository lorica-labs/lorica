//! The frozen format of the two blocklist tables.
//!
//! The builder in `lorica-policy` writes these bytes through `mmap` and the eBPF program
//! reads them with hand-written shifts and an unrolled probe sequence. Neither side can see
//! the other, so what keeps them equivalent is this file plus the round-trip the builder runs
//! before publishing a snapshot.

use lorica_common::blocklist::{
    CLASS24_BYTES, CLASS24_ENTRIES, Class24, OA_MAX_KEYS, OA_PROBES, OA_SLOTS, OaSlot, class24_get,
    class24_index, class24_set, oa_action, oa_fingerprint, oa_index, oa_insert, oa_lookup,
    oa_occupied, oa_psl, oa_tag, oa_tag_fingerprint,
};
use lorica_common::wire::Action;

fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

#[test]
fn the_index_is_the_top_twenty_four_bits() {
    assert_eq!(class24_index(v4(0, 0, 0, 0)), 0);
    assert_eq!(class24_index(v4(0, 0, 0, 255)), 0);
    assert_eq!(class24_index(v4(0, 0, 1, 0)), 1);
    assert_eq!(class24_index(v4(255, 255, 255, 255)), CLASS24_ENTRIES - 1);
}

#[test]
fn four_adjacent_blocks_share_a_byte_without_disturbing_each_other() {
    let mut table = vec![0u8; CLASS24_BYTES];
    let codes = [Class24::None, Class24::Deny, Class24::Allow, Class24::Table];

    // 10.0.0.0/24 through 10.0.3.0/24 are entries 4i..4i+3 of one byte.
    for (i, code) in codes.iter().enumerate() {
        class24_set(&mut table, v4(10, 0, i as u8, 7), *code);
    }
    for (i, code) in codes.iter().enumerate() {
        assert_eq!(class24_get(&table, v4(10, 0, i as u8, 200)), *code);
    }

    // Overwriting the middle one leaves the other three alone: the mask, not the byte.
    class24_set(&mut table, v4(10, 0, 1, 0), Class24::Allow);
    assert_eq!(class24_get(&table, v4(10, 0, 0, 0)), Class24::None);
    assert_eq!(class24_get(&table, v4(10, 0, 1, 0)), Class24::Allow);
    assert_eq!(class24_get(&table, v4(10, 0, 2, 0)), Class24::Allow);
    assert_eq!(class24_get(&table, v4(10, 0, 3, 0)), Class24::Table);
}

#[test]
fn the_tag_round_trips_every_verdict_and_every_reachable_psl() {
    let actions = [
        Action::Continue,
        Action::Allow,
        Action::Drop,
        Action::RateLimit,
        Action::Mark,
    ];
    // Four fields in one word, so the round trip has to cover the key as well: a fingerprint
    // that bled into the probe length would pass a test that only asked about three of them.
    // 0.0.0.0 is in the set because it is the key a zeroed table already holds.
    let keys = [0u32, 1, 0x0a00_0001, 0xffff_ffff, 0x8000_0000, 0x7f00_0001];
    for action in actions {
        for psl in 0..=OA_PROBES as u8 {
            for key in keys {
                let tag = oa_tag(key, action, psl);
                assert!(oa_occupied(tag));
                assert_eq!(oa_action(tag), Some(action));
                assert_eq!(oa_psl(tag), psl);
                assert_eq!(oa_tag_fingerprint(tag), oa_fingerprint(key));
            }
        }
    }
}

/// The self-validating slot: the failure it exists for, produced deliberately.
///
/// Publishing a snapshot is one copy over a live 20 MiB value, so the packet path can read an
/// eight-byte slot whose key came from the new snapshot and whose tag came from the old one.
/// Before the fingerprint, that pair answered with the old verdict — a `Drop` nobody had
/// decided, which is the one failure direction this design refuses. Now it answers `None`,
/// which under a `Table` code is no verdict at all.
///
/// The 1/256 that gets through is asserted too, because a guard whose limit is undocumented is
/// a guard somebody will later believe is total.
#[test]
fn a_slot_torn_between_two_snapshots_reads_as_no_verdict() {
    let mut table = vec![OaSlot::default(); OA_SLOTS];

    let old_key = v4(203, 0, 113, 7);
    let new_key = v4(198, 51, 100, 42);
    oa_insert(&mut table, old_key, Action::Drop).expect("the old snapshot places its key");
    assert_eq!(oa_lookup(&table, old_key), Some(Action::Drop));

    // The tear: the new key written over the old one while the old tag survives. Nothing about
    // this pair is reachable through `oa_insert`, which is the point — it is what a half-copied
    // map value looks like.
    let torn_at = table
        .iter()
        .position(|slot| slot.key == old_key)
        .expect("the key is somewhere");
    table[torn_at].key = new_key;

    assert_eq!(
        oa_lookup(&table, new_key),
        None,
        "a torn slot answered with the previous snapshot's verdict, which is a drop nobody \
         decided"
    );
    assert_eq!(
        oa_lookup(&table, old_key),
        None,
        "the old key is no longer in the table and must not be found"
    );

    // And the residual window, exhibited rather than asserted about. Eight bits detect 255 of
    // 256 tears; the 256th is a surviving tag whose fingerprint happens to be the incoming
    // key's, and it is built directly here because what it documents is the limit and not a
    // particular pair of addresses.
    let queried = v4(192, 0, 2, 99);
    let sharing = (0..=u32::MAX)
        .find(|&key| key != queried && oa_fingerprint(key) == oa_fingerprint(queried))
        .expect("one key in 256 shares a fingerprint");
    let elsewhere = (0..=u32::MAX)
        .find(|&key| oa_fingerprint(key) != oa_fingerprint(queried))
        .expect("255 keys in 256 do not");

    let home = (oa_index(queried) & lorica_common::blocklist::OA_INDEX_MASK) as usize;

    // The tear the fingerprint catches: the surviving tag belongs to a key with a different
    // fingerprint, so the slot is inconsistent and reads as nothing.
    table[home] = OaSlot {
        key: queried,
        tag: oa_tag(elsewhere, Action::Drop, 0),
    };
    assert_eq!(
        oa_lookup(&table, queried),
        None,
        "a slot whose tag was written for another key must not answer for this one"
    );

    // The tear it does not catch: the same construction where the two fingerprints agree. The
    // slot is still a pair neither snapshot held, and it is indistinguishable from one that was.
    table[home] = OaSlot {
        key: queried,
        tag: oa_tag(sharing, Action::Drop, 0),
    };
    assert_eq!(
        oa_lookup(&table, queried),
        Some(Action::Drop),
        "the residual window is a torn slot whose two keys share a fingerprint, and this design \
         documents it rather than closing it"
    );
}

/// The guard, shown failing on the version that lacks it.
///
/// A `.bss` table is all zeroes, and `0.0.0.0` is `key == 0`. Without the occupancy bit the
/// two are one bit pattern and every free slot answers for the address every misconfigured
/// source uses. The second half of this test reads the same slots the way a tag without an
/// occupancy bit would have to — key equality alone — and shows it answering on an empty
/// table.
#[test]
fn an_empty_slot_and_the_zero_address_are_not_the_same_pattern() {
    let empty = vec![OaSlot::default(); OA_SLOTS];
    assert_eq!(oa_lookup(&empty, 0), None);

    let mut table = empty.clone();
    let home = oa_index(0) as usize;
    table[home] = OaSlot {
        key: 0,
        tag: oa_tag(0, Action::Drop, 0),
    };
    assert_eq!(oa_lookup(&table, 0), Some(Action::Drop));

    // What the broken version does: membership by key equality, no occupancy bit.
    let membership_only = |slots: &[OaSlot], key: u32| slots[oa_index(key) as usize].key == key;
    assert!(
        membership_only(&empty, 0),
        "the version without an occupancy bit answers for 0.0.0.0 on an empty table"
    );
    assert!(!membership_only(&empty, v4(203, 0, 113, 1)));
}

#[test]
fn the_reference_lookup_finds_every_key_a_correct_insertion_placed() {
    // At the full permitted load, because the number this produces is what justifies the
    // compiled probe count: a tenth of the load would agree with any constant.
    let count = OA_MAX_KEYS;
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let action = if i % 3 == 0 {
            Action::Allow
        } else {
            Action::Drop
        };
        keys.push(((state >> 32) as u32, action));
    }
    keys.sort_unstable_by_key(|&(key, _)| key);
    keys.dedup_by_key(|&mut (key, _)| key);

    let mut table = vec![OaSlot::default(); OA_SLOTS];
    for &(key, action) in &keys {
        oa_insert(&mut table, key, action)
            .unwrap_or_else(|| panic!("key {key:#010x} ran past the compiled probe count"));
    }

    // Read the maximum off the finished table and not off the return values. A key that gets
    // displaced by a later insertion ends up further from home than the distance its own
    // insertion reported, and that larger number is the one an unrolled lookup has to reach.
    let worst = table
        .iter()
        .filter(|slot| oa_occupied(slot.tag))
        .map(|slot| oa_psl(slot.tag))
        .max()
        .expect("the table is not empty");
    println!(
        "oa-psl keys={} slots={OA_SLOTS} load={:.3} worst_psl={worst} compiled_probes={OA_PROBES}",
        keys.len(),
        keys.len() as f64 / OA_SLOTS as f64
    );
    assert!(
        (worst as u32) < OA_PROBES,
        "measured maximum probe sequence length {worst} against a compiled {OA_PROBES}"
    );

    for &(key, action) in &keys {
        assert_eq!(oa_lookup(&table, key), Some(action), "key {key:#010x}");
    }

    // And a miss stays a miss. Keys absent by construction: the low bit of every inserted key
    // is whatever the generator gave, so check against the sorted set rather than assuming.
    let mut misses = 0;
    for probe in 0u32..10_000 {
        if keys.binary_search_by_key(&probe, |&(key, _)| key).is_err() {
            assert_eq!(oa_lookup(&table, probe), None);
            misses += 1;
        }
    }
    assert!(misses > 9_000, "only {misses} of 10 000 probes were misses");
}
