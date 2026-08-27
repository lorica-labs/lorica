//! The operator's prefix list into the two tables the packet path reads, resolved here so
//! that the packet path only reads.
//!
//! **What this replaces, and the number that pays for it.** The obvious alternative is to
//! keep the published tables and edit them: insert the new prefixes, delete the withdrawn
//! ones, leave the rest alone. Two things rule it out. Open addressing has no clean deletion
//! without a tombstone, and a tombstone lengthens every probe sequence that crosses it until
//! something rebuilds the table anyway — which is the one cost
//! [`OA_PROBES`](lorica_common::blocklist::OA_PROBES) cannot absorb, because it is compiled
//! into the program as an unrolled constant. And editing live slots publishes every
//! transient state to a packet path that is reading them at that instant, with no way to
//! tell it to wait. What is here instead builds a whole snapshot from nothing every time,
//! and the price is measured rather than assumed: **2.9 ms** for the 20 MiB with nothing in
//! them and **142 ms** for the same 20 MiB carrying 1 048 576 keys, exhaustive round trip
//! included, in release on the machine the test ran on — 1 273 ms unoptimised, which is the
//! number to quote if the agent is ever shipped without a release profile.
//! `tests/blocklist_build.rs` prints both, on the `oa-rebuild-floor` and `oa-rebuild` lines.
//! So the tables themselves are nearly free and the keys are the whole cost; a configuration
//! change pays it once and nothing else in the agent sits on that path.
//!
//! # Longest prefix wins, and it is settled here
//!
//! [`Class24`] resolves every prefix at most `/24` long by itself, so the block table is
//! painted in ascending order of prefix length and the longest writer is simply the last
//! one. Prefixes from `/25` to `/32` become individual `/32` keys in the same order, which
//! is what makes "an expansion never rewrites an explicit `/32`" a property of the ordering
//! rather than a special case somebody has to remember.
//!
//! # Why one exception costs a whole block
//!
//! [`Class24::Table`] replaces the code of the entire `/24`, so the moment one `/32` inside a
//! denied `/8` needs the opposite verdict, the `/8`'s answer for the other 255 addresses has
//! nowhere left to live: the block table now says "consult the table" for all of them, and a
//! table miss is not a verdict. The builder writes those 255 keys out. One exception inside
//! a short prefix therefore costs a full block, which is exactly why `expansion_budget`
//! counts them alongside the `/25`-to-`/31` expansions.
//!
//! # A miscomputed probe length loses verdicts and never invents one
//!
//! [`oa_lookup`](lorica_common::blocklist::oa_lookup) compares the key exactly at every step,
//! so no probe length — right or wrong — can make a slot answer for an address it does not
//! hold. A wrong length can only make the Robin Hood exit fire early, and stopping early
//! returns `None`. `None` under a `Table` code is *no verdict*, which is what the address had
//! before any of this existed: the packet goes on to the rest of the pipeline.
//!
//! So a deny this code mislays lets hostile traffic through — a false negative, and the
//! failure mode this design accepts. An allow it mislays does not turn into a drop; it turns
//! into the absence of an exemption, and that source faces the generic mitigation it would
//! have faced had nobody written a rule for it. Neither outcome is the blocklist dropping
//! traffic it was told to pass. That asymmetry is what lets a single round trip stand between
//! a miscomputed table and production: what it guards against degrades toward doing nothing,
//! not toward doing harm.
//!
//! # What is refused
//!
//! Every refusal is a whole-snapshot refusal. There is no partial publication and no
//! truncation: the caller keeps the snapshot it already had, which is the older answer and
//! not a wrong one.

mod class24;
mod cuckoo;
mod expand;
mod robin_hood;

pub use cuckoo::cuckoo_from;

use std::collections::BTreeSet;

use lorica_common::Action;
use lorica_common::blocklist::{
    CLASS24_BYTES, CLASS24_PREFIX_BITS, Class24, OA_MAX_KEYS, OA_PROBES, OaSlot, class24_get,
    class24_index, class24_set,
};

/// The two tables, ready for the `mmap` that publishes them. Nothing here interprets
/// anything further; `loricad` writes these bytes at the two `.bss` symbols.
#[derive(Debug)]
pub struct Snapshot {
    /// [`CLASS24_BYTES`] bytes, two bits per `/24`.
    pub class24: Vec<u8>,
    /// [`OA_SLOTS`](lorica_common::blocklist::OA_SLOTS) slots, eight bytes each.
    pub oa: Vec<OaSlot>,
    /// Keys the table holds. The load factor is this over the slot count.
    pub keys: usize,
    /// Keys no line of the configuration named literally: `/25`-to-`/31` expansions plus the
    /// block fills. What `expansion_budget` bounds.
    pub expanded: usize,
    /// Worst probe sequence length in the finished table, read off the occupied slots and not
    /// off what each insertion reported about itself. A key displaced by a later insertion
    /// sits further from home than its own insertion ever saw.
    pub worst_psl: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("a {len}-bit prefix has more bits than an IPv4 address")]
    PrefixTooLong { len: u32 },

    #[error(
        "{prefix:#010x}/{len} has bits set outside its prefix; masking them here would \
         accept the line and mean something else"
    )]
    PrefixHasHostBits { prefix: u32, len: u32 },

    #[error(
        "{action:?} on {prefix:#010x}/{len} cannot be spelled in the two bits a /{CLASS24_PREFIX_BITS} \
         carries, which are nothing, deny, allow and consult-the-table; rounding it to the \
         nearest verdict would silently change what the rule does"
    )]
    ShortPrefixAction {
        prefix: u32,
        len: u32,
        action: Action,
    },

    #[error(
        "expanding this configuration asks for {wanted} keys the operator did not write and \
         the bound is {budget}; raise the bound or write shorter prefixes, because a \
         truncated expansion is a rule that half applies and nothing in the configuration \
         file shows which half"
    )]
    ExpansionBudget { wanted: usize, budget: usize },

    #[error(
        "this configuration needs {keys} keys and the format permits {limit}; past a load \
         factor of one half the average miss goes from 1.33 probes to about five, so the \
         builder refuses instead of degrading quietly"
    )]
    TooManyKeys { keys: usize, limit: usize },

    #[error(
        "{key:#010x} needs a probe sequence of at least {OA_PROBES}, which is the length the \
         packet path unrolls; the snapshot is not published and the previous one stays in \
         place"
    )]
    ProbeSequenceTooLong { key: u32 },

    #[error(
        "{key:#010x} was inserted as {expected:?} and reads back as {found:?}; the round trip \
         is what makes the compiled probe count an invariant rather than an expectation, so \
         this snapshot is not published"
    )]
    RoundTrip {
        key: u32,
        expected: Action,
        found: Option<Action>,
    },
}

/// Builds a snapshot from `(prefix, length, verdict)` triples, in host byte order.
///
/// `expansion_budget` bounds the keys the operator did not write: a `/25` is 128 of them and
/// a mistyped prefix length is the cheapest way to ask for a million. **There is no measured
/// value for it** — the cost of a key is a slot, and the slot count is already bounded by
/// [`OA_MAX_KEYS`] — so it is a policy dial the caller states rather than a constant here
/// pretending to be a measurement.
///
/// Order of declaration means nothing. Two rules on the same prefix are the policy compiler's
/// refusal (`CompileError::DuplicatePrefix`), and if one reaches here the later triple wins.
pub fn build(
    prefixes: &[(u32, u32, Action)],
    expansion_budget: usize,
) -> Result<Snapshot, BuildError> {
    let mut short = Vec::new();
    let mut long = Vec::new();
    for &(prefix, len, action) in prefixes {
        if len > 32 {
            return Err(BuildError::PrefixTooLong { len });
        }
        if len < 32 && prefix & (u32::MAX >> len) != 0 {
            return Err(BuildError::PrefixHasHostBits { prefix, len });
        }
        if len <= CLASS24_PREFIX_BITS {
            short.push((prefix, len, action));
        } else {
            long.push((prefix, len, action));
        }
    }

    // Ascending prefix length, stably, in both halves: the longest writer is then simply the
    // last one, in the block table and in the key map alike.
    short.sort_by_key(|&(_, len, _)| len);
    long.sort_by_key(|&(_, len, _)| len);

    let mut class24 = vec![0u8; CLASS24_BYTES];
    class24::paint(&mut class24, &short)?;

    let mut keys = expand::Keys::new(expansion_budget);
    for &(prefix, len, action) in &long {
        keys.expand(prefix, len, action)?;
    }

    // Read the covering verdict out of the block before overwriting the block's code with
    // `Table`, which is the only place that verdict still exists.
    let blocks: BTreeSet<usize> = keys.addresses().map(class24_index).collect();
    for block in blocks {
        let base = (block as u32) << (32 - CLASS24_PREFIX_BITS);
        match class24_get(&class24, base) {
            Class24::Deny => keys.fill_block(base, Action::Drop)?,
            Class24::Allow => keys.fill_block(base, Action::Allow)?,
            Class24::None | Class24::Table => {}
        }
        class24_set(&mut class24, base, Class24::Table);
    }

    if keys.map.len() > OA_MAX_KEYS {
        return Err(BuildError::TooManyKeys {
            keys: keys.map.len(),
            limit: OA_MAX_KEYS,
        });
    }

    let (oa, worst_psl) = robin_hood::fill(&keys.map)?;
    Ok(Snapshot {
        class24,
        oa,
        keys: keys.map.len(),
        expanded: keys.expanded,
        worst_psl,
    })
}
