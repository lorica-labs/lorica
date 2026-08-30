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

use lorica_common::{Action, CounterId, LpmKey, LpmValue};

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
    /// forward through both at once. Two kinds of entry are dropped rather than seated.
    ///
    /// **Slots at or below the named counters**, because those belong to the named catalogue and
    /// a rule pointed at one would make a stage counter read as one source's traffic. The policy
    /// compiler refuses to emit one — `an_entry_pointed_at_a_named_counter_is_refused` — so this
    /// is a second check on an invariant that already holds, kept because the cost is a
    /// comparison and the failure it would catch is silent.
    ///
    /// **Entries whose action is [`Action::Allow`]**, and this one is not a second check on
    /// anything: without it the detector blackholes a `/24` around an allow-listed source. Every
    /// dropping rung is gated on `Confirmation::ExactKey`, which asks for a seated key whose own
    /// slot is rising above `entry_per_sec`; `Engine::hottest_entry` takes the maximum over the
    /// seats and has no way to ask what the operator decided about one, because a `Seat` is a key
    /// and a slot. So a carrier-grade NAT gateway, a reverse proxy or a partner network — all
    /// ordinary, all busier than a per-source rate an attacker is caught at — became the evidence
    /// for refusing themselves. Measured before the filter, at the shipped defaults: **11 090 000
    /// legitimate packets refused on `legit_staircase`, at rung 4**, and the same shape on
    /// `legit_noisy`. See `docs/mesures/14-frontiere-reactivite-faux-positifs.md` in the agent
    /// tree, and `the_defect_this_filter_exists_for_is_real` in `pulse_replay.rs`, which fails if
    /// the filter is removed.
    ///
    /// **Only `Allow`, and the other four stay.** `Continue`, `RateLimit` and `Mark` all leave the
    /// packet flowing through the later stages — they are the entries that decided nothing or
    /// decided to mitigate, and a source under a mitigation that is not working is exactly what
    /// the rung above is for. `Drop` is already refused and widening it is the point of
    /// `DropBroad`. `Allow` is the only action that means *the operator has answered this
    /// question*, and it is the only one whose counter can never be evidence.
    ///
    /// The counter slot itself is still allocated by the compiler for an allow rule, deliberately
    /// — a single global counter would not say *which* allow-listed source traversed the
    /// pipeline. Nothing here changes that: the slot exists and is counted, it is simply never
    /// offered to the detector as a reason to refuse a packet.
    pub fn from_entries(entries: &[(LpmKey, LpmValue)]) -> Self {
        let mut seats: Vec<Seat> = entries
            .iter()
            .filter(|(_, value)| {
                value.counter_idx >= CounterId::COUNT && value.action != Action::Allow
            })
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
    use lorica_common::Deadline;

    use super::*;

    fn entry(addr: u8, slot: u32) -> (LpmKey, LpmValue) {
        acting(addr, slot, Action::Drop)
    }

    fn acting(addr: u8, slot: u32, action: Action) -> (LpmKey, LpmValue) {
        let mut value = LpmValue::zeroed();
        value.action = action;
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

    /// **An allow-listed source is never seated, whatever its counter does.**
    ///
    /// The seat is what makes a key confirmable, and a confirmed key is what unlocks the rungs
    /// that drop. An `Allow` entry that gets one turns a busy legitimate source — a CGNAT
    /// gateway, a reverse proxy — into the evidence for refusing it, and the widening at rung 4
    /// takes a `/24` of its neighbours with it.
    ///
    /// Written against the action and not against a rate, because the property is not "an allow
    /// rule is never busy enough" — it is often busier than an attacker — it is "an allow rule is
    /// never evidence".
    #[test]
    fn an_allow_listed_entry_is_never_seated() {
        let roster = Roster::from_entries(&[
            acting(1, CounterId::COUNT, Action::Allow),
            acting(2, CounterId::COUNT + 1, Action::Drop),
            acting(3, CounterId::COUNT + 2, Action::Allow),
        ]);
        assert_eq!(roster.len(), 1, "an allow rule took a seat");
        assert_eq!(roster.seats()[0].key, LpmKey::host_v4([10, 0, 0, 2]));
    }

    /// The other four actions keep their seat, and each for its own reason.
    ///
    /// `Drop` is already refused and widening it is what rung 4 is for. `RateLimit` and `Mark`
    /// are mitigations, and a source under a mitigation that is not reducing its rate is the
    /// exact case `insufficient_ticks` measures. `Continue` decided nothing and leaves the packet
    /// to the later stages, so it is not exculpatory either. Excluding any of them would make the
    /// ladder unable to escalate on the sources it was built to escalate on.
    #[test]
    fn every_action_but_allow_keeps_its_seat() {
        let kept = [
            Action::Continue,
            Action::Drop,
            Action::RateLimit,
            Action::Mark,
        ];
        for (i, action) in kept.into_iter().enumerate() {
            let roster =
                Roster::from_entries(&[acting(i as u8, CounterId::COUNT + i as u32, action)]);
            assert_eq!(roster.len(), 1, "{action:?} lost its seat");
        }
    }

    /// Slot order survives the filter: the seats a caller walks against a sweep must still be
    /// ascending after an allow rule is removed from the middle of the run.
    #[test]
    fn removing_an_allow_entry_leaves_the_rest_in_slot_order() {
        let roster = Roster::from_entries(&[
            acting(3, CounterId::COUNT + 2, Action::Drop),
            acting(1, CounterId::COUNT, Action::Drop),
            acting(2, CounterId::COUNT + 1, Action::Allow),
        ]);
        let slots: Vec<u32> = roster.seats().iter().map(|s| s.slot).collect();
        assert_eq!(slots, vec![CounterId::COUNT, CounterId::COUNT + 2]);
    }
}
