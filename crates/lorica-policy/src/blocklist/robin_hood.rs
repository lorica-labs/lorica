//! The table filled with [`oa_insert`] and then read back with [`oa_lookup`], exhaustively.
//!
//! **Not a reimplementation, and that is the whole point.** Insertion decides where a key
//! lands, so a builder that wrote its own would agree with the packet path about the format
//! and disagree with it about the table — the failure that produces a correct-looking 16 MiB
//! nothing can read. The reference insertion lives in `lorica_common::blocklist` and the
//! dataplane fixtures fill themselves with the same function. What belongs here is the policy
//! around it: the ceiling, the measurement and the refusal.
//!
//! **Why the maximum is read off the finished table.** [`oa_insert`] reports the distance the
//! key it was handed ended up at, and a later insertion can displace that key further from
//! home. Taking the maximum of the return values under-reports the worst case, and the gap is
//! not hypothetical: `tests/blocklist_build.rs` at 1 048 450 scattered `/32` and a load factor
//! of 0.500 reports **10** from the return values and finds **11** in the finished table.
//! Eleven is what the unrolled lookup has to reach, so eleven is what gets compared against
//! [`OA_PROBES`]. The same test at the same load with contiguous `/25` blocks measures 10 by
//! either method, which is the reason the gap has to be looked for on more than one key set
//! rather than assumed absent from one run.
//!
//! **Why the round trip is exhaustive and not sampled.** [`OA_PROBES`] is compiled into the
//! program as an unrolled constant, so a snapshot with one unreachable key is not slightly
//! wrong, it is silently wrong for that address forever. A sample of a million keys that
//! misses the one displaced key costs one address of policy and reports success. Reading every
//! key back costs one pass over 16 MiB, which is the cheapest part of the rebuild.

use std::collections::BTreeMap;

use lorica_common::Action;
use lorica_common::blocklist::{
    OA_PROBES, OA_SLOTS, OaSlot, oa_insert, oa_lookup, oa_occupied, oa_psl,
};

use super::BuildError;

/// Fills a fresh table and returns it with the worst probe sequence length in it.
///
/// A refusal leaves nothing behind: the table is local until it is returned, so a snapshot
/// that fails any of these checks is dropped whole and whatever is published stays published.
/// That is also why a failed [`oa_insert`] needs no unwinding — it abandons a carried key in
/// a table that is about to cease to exist.
pub fn fill(keys: &BTreeMap<u32, Action>) -> Result<(Vec<OaSlot>, u8), BuildError> {
    let mut table = vec![OaSlot::default(); OA_SLOTS];
    for (&key, &action) in keys {
        oa_insert(&mut table, key, action).ok_or(BuildError::ProbeSequenceTooLong { key })?;
    }

    let worst = table
        .iter()
        .filter(|slot| oa_occupied(slot.tag))
        .map(|slot| oa_psl(slot.tag))
        .max()
        .unwrap_or(0);
    if worst as u32 >= OA_PROBES {
        // Unreachable through `oa_insert`, which refuses at that distance itself. Checked
        // anyway, because this is the assertion the packet path is compiled against and it
        // costs one comparison per rebuild to state it here rather than trust it.
        return Err(BuildError::ProbeSequenceTooLong {
            key: table
                .iter()
                .find(|slot| oa_psl(slot.tag) == worst)
                .map_or(0, |slot| slot.key),
        });
    }

    for (&key, &action) in keys {
        let found = oa_lookup(&table, key);
        if found != Some(action) {
            return Err(BuildError::RoundTrip {
                key,
                expected: action,
                found,
            });
        }
    }
    Ok((table, worst))
}
