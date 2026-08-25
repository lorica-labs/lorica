//! Stage 3, the flat half: two `.bss` tables, no helper call, and the trie only when the
//! configuration needs one.
//!
//! Every fixture here is built with `class24_set` and `oa_insert`, which is the point of the
//! format being frozen: a test that wrote its own slots would be asserting against a table
//! the policy compiler cannot produce.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{Action, Class24, Deadline, LpmKey, LpmValue};
use support::{Blocklist, PktBuilder, XdpAction, program_with_blocklist};

const GAME_PORT: u16 = 30_120;

fn udp_from(src: [u8; 4]) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(1111, GAME_PORT)
        .build()
}

fn run(blocklist: &Blocklist, src: [u8; 4]) -> XdpAction {
    program_with_blocklist(lorica_common::DEFAULT_SETTINGS, blocklist).run(&udp_from(src))
}

/// The claim the whole layout rests on: a `/24` nobody marked is one access and the second
/// table is never touched.
///
/// It is proved by *contradiction in the table*, because a verdict alone cannot show which
/// memory was read. The open-addressed table holds a deny for this exact address and the
/// `/24` code is `None`; a program that probed anyway would answer `Drop`. A helper count
/// cannot show it — the whole design of the stage is that neither access is a helper call.
#[test]
fn an_unmarked_slash_24_never_reaches_the_second_table() {
    let blocklist = Blocklist::empty().key([203, 0, 113, 1], Action::Drop);
    assert_eq!(
        run(&blocklist, [203, 0, 113, 1]),
        XdpAction::Pass,
        "the table was consulted for a /24 marked None, so the common case costs two accesses"
    );
}

/// Every prefix at or shorter than a `/24` is resolved by the first table alone, which is
/// what removes the need for a trie rather than merely filtering ahead of one.
#[test]
fn a_prefix_no_longer_than_a_slash_24_is_answered_in_one_access() {
    let denied = Blocklist::empty().class([10, 90, 1, 0], Class24::Deny);
    assert_eq!(run(&denied, [10, 90, 1, 5]), XdpAction::Drop);
    assert_eq!(run(&denied, [10, 90, 2, 5]), XdpAction::Pass);

    let allowed = Blocklist::empty().class([10, 90, 1, 0], Class24::Allow);
    assert_eq!(run(&allowed, [10, 90, 1, 5]), XdpAction::Pass);
}

#[test]
fn a_slash_32_inside_a_marked_slash_24_is_answered_by_the_table() {
    let blocklist = Blocklist::empty()
        .class([10, 90, 1, 0], Class24::Table)
        .key([10, 90, 1, 7], Action::Drop);
    assert_eq!(run(&blocklist, [10, 90, 1, 7]), XdpAction::Drop);
}

/// The miss that costs the probe run. Robin Hood stops it at the first free slot or at the
/// first slot closer to its home than we have walked, which is why sixteen unrolled steps
/// bound it whatever the load factor is.
#[test]
fn a_miss_inside_a_marked_slash_24_probes_and_carries_on() {
    let blocklist = Blocklist::empty()
        .class([10, 90, 1, 0], Class24::Table)
        .key([10, 90, 1, 7], Action::Drop);
    assert_eq!(run(&blocklist, [10, 90, 1, 8]), XdpAction::Pass);
}

/// The bug the tag exists to prevent, and it exists in production elsewhere: `deny
/// 10.0.0.0/8` with `allow 10.1.2.3/32` inside it. The table carries a *verdict* and not a
/// membership bit, so the longer prefix wins with the opposite answer and nothing in the
/// packet path compares prefix lengths to get there.
///
/// **Marking a `/24` `Table` destroys the only copy of the `/8`'s verdict for the 255 other
/// addresses in it**, so the builder writes those 255 keys with the `/8`'s `Drop`. That is
/// why a miss in a marked `/24` falls back on *nothing*: every address carrying a verdict has
/// a key, and the packet path neither re-reads the `/24` code nor probes a second time.
///
/// Three addresses, and the third is the one that earns its place: `10.9.9.9` is answered by
/// `CLASS24` alone, which shows the filling did not spill outside the `/24` that needed it.
/// It is proved the same way as the unmarked case — the table holds an `Allow` for it, so a
/// program that probed a `Deny`-coded `/24` would answer `Pass`.
#[test]
fn an_allow_exception_beats_the_deny_that_contains_it() {
    let blocklist = Blocklist::empty()
        .class([10, 9, 9, 0], Class24::Deny)
        .class([10, 1, 2, 0], Class24::Table)
        .key([10, 1, 2, 3], Action::Allow)
        .key([10, 1, 2, 4], Action::Drop)
        .key([10, 9, 9, 9], Action::Allow);

    assert_eq!(
        run(&blocklist, [10, 1, 2, 3]),
        XdpAction::Pass,
        "the /32 allow has to win over the /8 deny around it"
    );
    assert_eq!(
        run(&blocklist, [10, 1, 2, 4]),
        XdpAction::Drop,
        "one of the 255 filling keys, and it has to be read as a key and not as a fallback"
    );
    assert_eq!(
        run(&blocklist, [10, 9, 9, 9]),
        XdpAction::Drop,
        "a Deny-coded /24 was probed, so the /8 verdict is not being answered in one access"
    );
}

/// A `/31` is two keys, because the table stores full addresses and nothing else. The
/// expansion is the builder's; what is asserted here is that the packet path reads it as two
/// keys and answers nothing at all for the third address.
#[test]
fn a_slash_31_is_two_keys_and_the_next_address_is_not_one() {
    let blocklist = Blocklist::empty()
        .class([10, 5, 0, 0], Class24::Table)
        .key([10, 5, 0, 0], Action::Drop)
        .key([10, 5, 0, 1], Action::Drop);

    assert_eq!(run(&blocklist, [10, 5, 0, 0]), XdpAction::Drop);
    assert_eq!(run(&blocklist, [10, 5, 0, 1]), XdpAction::Drop);
    assert_eq!(run(&blocklist, [10, 5, 0, 2]), XdpAction::Pass);
}

/// `0.0.0.0` is the address a zeroed table would answer for if occupancy lived in the key,
/// so it gets its own case in both directions: a key when the builder placed one, a free slot
/// when it did not.
#[test]
fn the_zero_address_is_a_key_only_when_one_was_placed() {
    let empty = Blocklist::empty().class([0, 0, 0, 0], Class24::Table);
    assert_eq!(
        run(&empty, [0, 0, 0, 0]),
        XdpAction::Pass,
        "an empty slot answered for 0.0.0.0, so OA_TAG_OCCUPIED is not being read"
    );

    let placed = empty.key([0, 0, 0, 0], Action::Drop);
    assert_eq!(run(&placed, [0, 0, 0, 0]), XdpAction::Drop);
}

/// IPv6 is asked neither table: `CLASS24` indexes 24 bits of a 32-bit address and a slot key
/// is a `u32`. So an IPv6 source falls through to the trie, which is most of what the trie is
/// for now, and the fall-through is asserted rather than assumed.
#[test]
fn an_ipv6_source_falls_through_to_the_trie() {
    let blocklist = Blocklist::empty();
    let mut prog = program_with_blocklist(lorica_common::DEFAULT_SETTINGS, &blocklist);
    let mut value = LpmValue::zeroed();
    value.deadline = Deadline::never();
    value.action = Action::Drop;
    prog.insert(
        LpmKey::v6(
            [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        value,
    );

    let v6 = PktBuilder::eth().ipv6().udp(1111, GAME_PORT).build();
    assert_eq!(prog.run(&v6), XdpAction::Drop);
}

/// The pruning claim, measured on the translated length and not on a count of instructions
/// from a tool that cannot load this object.
///
/// A cleared `BLOCKLIST_TRIE` is not a run-time skip: the verifier reads `.rodata` as constant
/// and removes the lookup, the deadline comparison, the scope walk and the four counter bumps
/// before the program is JITed. The two lengths are printed because the difference is the
/// measurement and a bare assertion would hide it.
#[test]
fn the_trie_leaves_the_program_when_the_configuration_has_no_real_prefix() {
    let armed = program_with_blocklist(lorica_common::DEFAULT_SETTINGS, &Blocklist::empty());
    let pruned = program_with_blocklist(
        lorica_common::DEFAULT_SETTINGS,
        &Blocklist::empty().without_trie(),
    );

    let (with, without) = (armed.translated_len(), pruned.translated_len());
    println!("translated: {with} bytes with the trie, {without} without");
    assert!(
        without < with,
        "the trie word cleared left the program the same size, {without} against {with}, \
         so the stage is being skipped at run time and not removed"
    );

    // And the pruned program still answers on the tables, which is what makes the removal a
    // configuration and not a broken load.
    assert_eq!(
        program_with_blocklist(
            lorica_common::DEFAULT_SETTINGS,
            &Blocklist::empty()
                .without_trie()
                .class([10, 90, 1, 0], Class24::Deny),
        )
        .run(&udp_from([10, 90, 1, 5])),
        XdpAction::Drop
    );
}

/// The whole point of the layout, in the units the per-packet budget is written in: a verdict
/// out of either table costs **no helper call at all**, so a deny leaves the pipeline having
/// read the clock and nothing else.
#[cfg(feature = "count-helpers")]
#[test]
fn a_verdict_from_either_table_costs_no_helper_call() {
    let blocklist = Blocklist::empty()
        .class([10, 90, 1, 0], Class24::Deny)
        .class([10, 1, 2, 0], Class24::Table)
        .key([10, 1, 2, 3], Action::Drop);

    let code = program_with_blocklist(lorica_common::DEFAULT_SETTINGS, &blocklist);
    assert_eq!(code.run(&udp_from([10, 90, 1, 5])), XdpAction::Drop);
    let counts = code.helper_counts();
    assert_eq!(
        counts.map_lookups, 0,
        "a deny answered by CLASS24 spent a lookup, got {counts:?}"
    );
    assert_eq!(counts.clock_reads, 1);

    let table = program_with_blocklist(lorica_common::DEFAULT_SETTINGS, &blocklist);
    assert_eq!(table.run(&udp_from([10, 1, 2, 3])), XdpAction::Drop);
    let counts = table.helper_counts();
    assert_eq!(
        counts.map_lookups, 0,
        "a deny answered by the probe run spent a lookup, got {counts:?}"
    );

    // And the steady state is unchanged: the two lookups the budget already allowed, with
    // this stage adding none.
    let clean = program_with_blocklist(lorica_common::DEFAULT_SETTINGS, &Blocklist::empty());
    assert_eq!(clean.run(&udp_from([203, 0, 113, 1])), XdpAction::Pass);
    let counts = clean.helper_counts();
    assert_eq!(
        counts.map_lookups, 2,
        "expected the list lookup and the bucket bank, got {counts:?}"
    );
}
