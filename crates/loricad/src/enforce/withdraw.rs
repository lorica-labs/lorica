//! Taking a refusal back before its deadline.
//!
//! **Why this exists next to a mechanism that already expires entries.** The deadline is
//! the net: it answers the 1 failure nothing else can — the agent is gone — and it answers
//! it late, after as many seconds as the TTL the ladder wrote. At the ladder's default
//! that is 600 of them, ten minutes of refusing a source whose reason stopped being true
//! on the first descent. So the TTL is not the policy: the policy is that a rung the
//! engine has left withdraws its key, and the TTL catches only the case where nobody is
//! left to do it.

use std::{io, os::fd::BorrowedFd};

use lorica_common::LpmKey;
use lorica_dataplane::maps::lpm;

/// Removes the entry `key`, and answers `Ok` when there was none.
///
/// Idempotent on purpose. An entry can be gone for reasons that are not failures — a
/// reloaded list that no longer carries it, a withdrawal replayed after a restart — and a
/// descent that had to distinguish them would have to hold state about a map that is
/// itself the state.
pub fn withdraw(list: BorrowedFd<'_>, key: LpmKey) -> io::Result<()> {
    match lpm::remove(list, key) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
