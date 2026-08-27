//! The cuckoo table filled from a finished Robin Hood one, for the measurement that decides
//! whether the two swap.
//!
//! **Why it converts instead of building.** The keys a snapshot holds are whatever the prefix
//! expansion produced, and re-deriving them here would be a second expansion to keep in step
//! with the first — the restatement failure this tree has a name for. A finished
//! [`OaSlot`] table already *is* the key set, one occupied slot at a time, so the conversion
//! reads it back. That also makes the comparison exact by construction: both structures hold
//! the same keys with the same verdicts, which is the only condition under which a cycle count
//! for one is a cycle count against the other.
//!
//! **Nothing in the agent calls this.** It exists so `lorica-ebpf` built with
//! `--features blocklist-cuckoo` can be handed a filled table, and so the equivalence test has
//! one place that fills one. If the cuckoo variant ever becomes the default, this file is
//! deleted and `build` emits the table directly; keeping a second expansion alive in the
//! meantime would be paying for a migration nobody has decided on.

use lorica_common::blocklist::{
    OaSlot,
    cuckoo::{CUCKOO_BUCKETS, CuckooBucket, cuckoo_insert},
    oa_action, oa_occupied,
};

use super::BuildError;

/// The displacement walk's random stream.
///
/// Written down rather than drawn, because a table whose shape depends on the clock is a table
/// a failed measurement cannot be re-run against. xorshift64: not a cryptographic generator and
/// it does not need to be — what it decides is which of eight occupied lanes gets displaced, and
/// the only property that matters is that the walk does not retrace its own steps.
const WALK_SEED: u64 = 0xc0c0_0a15_0000_0001;

/// Fills a fresh cuckoo table with every key a finished Robin Hood table holds.
///
/// Fails rather than degrading, and the failure is the one Robin Hood does not have: a
/// displacement chain that reaches [`CUCKOO_MAX_KICKS`](lorica_common::blocklist::cuckoo::CUCKOO_MAX_KICKS)
/// without finding a lane. The simulation measures zero of those over 2.1 billion insertions at
/// the maximum load — `tests/blocklist_sim.rs` — so an error here is worth reporting as a
/// surprise and not as a routine refusal.
pub fn cuckoo_from(oa: &[OaSlot]) -> Result<Vec<CuckooBucket>, BuildError> {
    let mut table = vec![CuckooBucket::EMPTY; CUCKOO_BUCKETS];
    let mut state = WALK_SEED;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 32) as u32
    };

    for slot in oa.iter().filter(|slot| oa_occupied(slot.tag)) {
        // A tag whose three verdict bits decode to no `Action` is a corrupt source table, not a
        // configuration choice, and the same refusal the round trip of `robin_hood` makes.
        let action = oa_action(slot.tag).ok_or(BuildError::RoundTrip {
            key: slot.key,
            expected: lorica_common::Action::Continue,
            found: None,
        })?;
        cuckoo_insert(&mut table, slot.key, action, &mut random)
            .map_err(|_| BuildError::ProbeSequenceTooLong { key: slot.key })?;
    }
    Ok(table)
}
