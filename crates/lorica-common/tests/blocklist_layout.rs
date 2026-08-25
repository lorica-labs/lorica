//! The frozen format of the two blocklist tables.
//!
//! The builder in `lorica-policy` writes these bytes through `mmap` and the eBPF program
//! reads them with hand-written shifts and an unrolled probe sequence. Neither side can see
//! the other, so what keeps them equivalent is this file plus the round-trip the builder runs
//! before publishing a snapshot.

use lorica_common::blocklist::{
    CLASS24_BYTES, CLASS24_ENTRIES, Class24, OA_MAX_KEYS, OA_PROBES, OA_SLOTS, OaSlot, class24_get,
    class24_index, class24_set, oa_action, oa_index, oa_lookup, oa_occupied, oa_psl, oa_step,
    oa_tag,
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
    for action in actions {
        for psl in 0..=OA_PROBES as u8 {
            let tag = oa_tag(action, psl);
            assert!(oa_occupied(tag));
            assert_eq!(oa_action(tag), Some(action));
            assert_eq!(oa_psl(tag), psl);
        }
    }
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
        tag: oa_tag(Action::Drop, 0),
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

/// Robin Hood insertion, written here and only here.
///
/// The builder owns the real one; this is what proves the frozen [`oa_lookup`] finds what a
/// correct insertion placed. Returns the maximum probe sequence length reached.
fn insert_all(table: &mut [OaSlot], keys: &[(u32, Action)]) -> u32 {
    let mut worst = 0;
    for &(key, action) in keys {
        let mut index = oa_index(key);
        let mut distance = 0u32;
        let mut carried = OaSlot {
            key,
            tag: oa_tag(action, 0),
        };
        loop {
            let slot = table[index as usize];
            if !oa_occupied(slot.tag) {
                carried.tag = oa_tag(oa_action(carried.tag).unwrap(), distance as u8);
                table[index as usize] = carried;
                worst = worst.max(distance);
                break;
            }
            if (oa_psl(slot.tag) as u32) < distance {
                carried.tag = oa_tag(oa_action(carried.tag).unwrap(), distance as u8);
                table[index as usize] = carried;
                worst = worst.max(distance);
                carried = slot;
                distance = oa_psl(slot.tag) as u32;
            }
            index = oa_step(index);
            distance += 1;
            assert!(distance < OA_SLOTS as u32, "the table is full");
        }
    }
    worst
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
    let worst = insert_all(&mut table, &keys);
    println!(
        "oa-psl keys={} slots={OA_SLOTS} load={:.3} worst_psl={worst} compiled_probes={OA_PROBES}",
        keys.len(),
        keys.len() as f64 / OA_SLOTS as f64
    );
    assert!(
        worst < OA_PROBES,
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
