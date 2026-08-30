//! Which unified-list entry owns which counter slot.
//!
//! **This pairing is the whole reason a per-entry counter is evidence.** `Confirmation::ExactKey`
//! means "this key's own slot is rising", and *own* is the load-bearing word: a shared counter
//! is a state a second source can move, and a refusal resting on one refuses whoever else was
//! counted there. The kernel side only increments an index; the policy compiler is the only
//! thing that knows which key that index belongs to. So the pairing lives here, built once from
//! the compiled policy, and nothing else reconstructs it.
//!
//! **What a drift in it would do, which is why it is a type and not a convention.** If the
//! roster said slot 40 belonged to `10.0.0.1` while the compiler had given slot 40 to
//! `10.0.0.2`, the detector would confirm a rise on one address and write a refusal for the
//! other — a false positive with a complete and entirely wrong audit trail. The counter map's
//! own tests exist to stop the compiler and the program disagreeing about a slot; this stops
//! the agent and the compiler disagreeing about a key.
//!
//! Built from `Compiled::entries`, so it carries exactly what the trie was filled with and in
//! the order the compiler allocated. A recompiled policy produces a new roster, and the
//! detector notices because the length changes — see `Engine::hottest_entry`, which drops its
//! history rather than reinterpret deltas across two different allocations.

use lorica_common::{CounterId, LpmKey, LpmValue};

/// One entry and the slot the compiler gave it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seat {
    pub key: LpmKey,
    pub slot: u32,
}

/// The pairing, in slot order.
#[derive(Default)]
pub struct Roster {
    seats: Vec<Seat>,
}

impl Roster {
    /// Reads the pairing off the compiled entries.
    ///
    /// Sorted by slot and not left in the compiler's order, so a caller walking a sweep can go
    /// forward through both at once. Entries whose slot is at or below the named counters are
    /// dropped: those slots belong to the named catalogue, and a rule pointed at one would make
    /// a stage counter read as one source's traffic. The policy compiler refuses to emit one —
    /// `an_entry_pointed_at_a_named_counter_is_refused` — so this is a second check on an
    /// invariant that already holds, kept because the cost is a comparison and the failure it
    /// would catch is silent.
    pub fn from_entries(entries: &[(LpmKey, LpmValue)]) -> Self {
        let mut seats: Vec<Seat> = entries
            .iter()
            .filter(|(_, value)| value.counter_idx >= CounterId::COUNT)
            .map(|(key, value)| Seat {
                key: *key,
                slot: value.counter_idx,
            })
            .collect();
        seats.sort_unstable_by_key(|seat| seat.slot);
        Self { seats }
    }

    pub fn seats(&self) -> &[Seat] {
        &self.seats
    }

    pub fn len(&self) -> usize {
        self.seats.len()
    }
}

#[cfg(test)]
mod tests {
    use lorica_common::{Action, Deadline};

    use super::*;

    fn entry(addr: u8, slot: u32) -> (LpmKey, LpmValue) {
        let mut value = LpmValue::zeroed();
        value.action = Action::Drop;
        value.counter_idx = slot;
        value.deadline = Deadline::never();
        (LpmKey::host_v4([10, 0, 0, addr]), value)
    }

    /// The order the sweep is walked in, whatever order the compiler emitted.
    #[test]
    fn seats_come_out_in_slot_order() {
        let roster = Roster::from_entries(&[
            entry(3, CounterId::COUNT + 2),
            entry(1, CounterId::COUNT),
            entry(2, CounterId::COUNT + 1),
        ]);
        let slots: Vec<u32> = roster.seats().iter().map(|s| s.slot).collect();
        assert_eq!(
            slots,
            vec![CounterId::COUNT, CounterId::COUNT + 1, CounterId::COUNT + 2]
        );
        assert_eq!(roster.seats()[0].key, LpmKey::host_v4([10, 0, 0, 1]));
    }

    /// A slot inside the named catalogue is not an entry's to own, and taking it would make a
    /// stage counter read as one source's traffic.
    #[test]
    fn a_seat_on_a_named_slot_is_refused() {
        let roster = Roster::from_entries(&[entry(1, 0), entry(2, CounterId::COUNT)]);
        assert_eq!(roster.len(), 1, "only the entry above the named slots");
        assert_eq!(roster.seats()[0].slot, CounterId::COUNT);
    }

    /// **The pairing survives a reload because it is rebuilt from the reload, never carried
    /// across it.**
    ///
    /// This is the invariant that keeps a confirmed refusal pointed at the right address. The
    /// compiler allocates slots by position among the entries it emits, so inserting a rule
    /// renumbers everything after it: a roster kept from the previous compile would say slot 41
    /// belongs to the address that now owns slot 42, and the detector would confirm a rise on
    /// one address and write a refusal for another — a false positive with a complete and
    /// entirely wrong audit trail.
    ///
    /// The test is written against the renumbering rather than against a fixed table, because
    /// the property is not "the slots do not move" — they do — it is "the roster always names
    /// the compile it came from".
    #[test]
    fn a_reload_repairs_the_pairing_rather_than_inheriting_it() {
        let first = [entry(1, CounterId::COUNT), entry(2, CounterId::COUNT + 1)];
        let before = Roster::from_entries(&first);
        assert_eq!(before.seats()[0].key, LpmKey::host_v4([10, 0, 0, 1]));

        // A rule inserted ahead of the others: every slot after it now belongs to a different
        // address than it did.
        let second = [
            entry(9, CounterId::COUNT),
            entry(1, CounterId::COUNT + 1),
            entry(2, CounterId::COUNT + 2),
        ];
        let after = Roster::from_entries(&second);

        assert_eq!(
            after.seats()[0].key,
            LpmKey::host_v4([10, 0, 0, 9]),
            "the reloaded roster still names the old owner of the first slot"
        );
        assert_eq!(
            after.seats()[1].key,
            LpmKey::host_v4([10, 0, 0, 1]),
            "the address that moved slot is not followed to its new one"
        );
        assert_ne!(
            before.seats()[0].key,
            after.seats()[0].key,
            "the fixture did not actually renumber anything, so it proves nothing"
        );
    }
}
