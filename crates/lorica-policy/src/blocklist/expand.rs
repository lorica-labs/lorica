//! Prefixes longer than a `/24` into the `/32` keys the table stores, under a bound that
//! refuses rather than truncates.
//!
//! **Why a map and not a list of insertions.** Feeding
//! [`oa_insert`](lorica_common::blocklist::oa_insert) straight from the prefix list would let
//! a `/25` overwrite a `/32` it contains, because open addressing has no notion of which
//! writer was more specific — it takes the last one. Resolving in a
//! [`BTreeMap`] first, with the prefixes walked in ascending order of length, makes "the
//! longest prefix wins" the ordering of the writes and costs 8 bytes per key of transient
//! agent memory. Sorted rather than hashed so a snapshot is reproducible: the same
//! configuration inserts in the same order and produces the same 16 MiB.
//!
//! **What the bound is for.** A `/25` is 128 keys and a `/9` mistyped as a `/29` is eight;
//! one digit is the difference between a rule the operator meant and a rule that eats the
//! table. The bound counts keys nobody wrote — expansions and block fills — and refuses past
//! them. It never truncates: a half-applied rule is the one failure the configuration file
//! cannot show.

use std::collections::BTreeMap;

use lorica_common::Action;
use lorica_common::blocklist::CLASS24_PREFIX_BITS;

use super::BuildError;

/// Addresses to verdicts, with the expansions charged against a budget as they are written.
pub struct Keys {
    pub map: BTreeMap<u32, Action>,
    /// Keys the operator did not name literally.
    pub expanded: usize,
    budget: usize,
}

impl Keys {
    pub fn new(budget: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            expanded: 0,
            budget,
        }
    }

    /// Writes every `/32` of one prefix between `/25` and `/32`.
    ///
    /// Unconditional insertion, which is the point: called in ascending order of prefix
    /// length, the last writer is the most specific one and no comparison is needed.
    pub fn expand(&mut self, base: u32, len: u32, action: Action) -> Result<(), BuildError> {
        debug_assert!((CLASS24_PREFIX_BITS + 1..=32).contains(&len));
        let span = 1u32 << (32 - len);
        if len < 32 {
            self.charge(span as usize)?;
        }
        for key in base..=(base | (span - 1)) {
            self.map.insert(key, action);
        }
        Ok(())
    }

    /// Writes the verdict a `/24` carried into the addresses of that `/24` still without one.
    ///
    /// Called once per block the expansion touched, because marking the block
    /// [`Table`](lorica_common::blocklist::Class24::Table) is what destroys the only copy of
    /// that verdict. `or_insert`, never `insert`: what is already here came from a longer
    /// prefix.
    pub fn fill_block(&mut self, base: u32, action: Action) -> Result<(), BuildError> {
        for key in base..=(base | (u32::MAX >> CLASS24_PREFIX_BITS)) {
            if !self.map.contains_key(&key) {
                self.charge(1)?;
                self.map.insert(key, action);
            }
        }
        Ok(())
    }

    pub fn addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.map.keys().copied()
    }

    fn charge(&mut self, count: usize) -> Result<(), BuildError> {
        let wanted = self.expanded + count;
        if wanted > self.budget {
            return Err(BuildError::ExpansionBudget {
                wanted,
                budget: self.budget,
            });
        }
        self.expanded = wanted;
        Ok(())
    }
}
