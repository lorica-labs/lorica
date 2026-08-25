//! The block table, painted range by range.
//!
//! **What this replaces, and the number.** The alternative is to keep the prefixes and
//! resolve the length at lookup time, which is a trie, which is the structure this whole
//! format exists to remove: **414 ns** on the legitimate path at one million entries against
//! a flat table that costs the same at one entry as at ten million. So the resolution is paid
//! here instead, once per configuration change, and the shape of the payment is that a short
//! prefix writes every `/24` it covers — a `/8` is 65 536 two-bit writes and a `/0` is 16.7
//! million. That is the worst this can cost and it is bounded by the table, not by the
//! configuration.
//!
//! Ascending prefix length, so a `/24` written after the `/8` containing it simply lands
//! later on the same byte. There is no comparison and no precedence table; the order of the
//! writes *is* the precedence.

use lorica_common::Action;
use lorica_common::blocklist::{CLASS24_PREFIX_BITS, Class24, class24_set};

use super::BuildError;

/// Paints every prefix at most [`CLASS24_PREFIX_BITS`] long, in the order given.
pub fn paint(table: &mut [u8], prefixes: &[(u32, u32, Action)]) -> Result<(), BuildError> {
    for &(prefix, len, action) in prefixes {
        debug_assert!(len <= CLASS24_PREFIX_BITS);
        // Two bits hold four codes and two of them are verdicts. A rule the block table
        // cannot spell is refused here rather than rounded to whichever verdict is nearer.
        let code = match action {
            Action::Allow => Class24::Allow,
            Action::Drop => Class24::Deny,
            Action::Continue | Action::RateLimit | Action::Mark => {
                return Err(BuildError::ShortPrefixAction {
                    prefix,
                    len,
                    action,
                });
            }
        };

        let first = prefix >> (32 - CLASS24_PREFIX_BITS);
        let blocks = 1u32 << (CLASS24_PREFIX_BITS - len);
        for block in first..first + blocks {
            class24_set(table, block << (32 - CLASS24_PREFIX_BITS), code);
        }
    }
    Ok(())
}
