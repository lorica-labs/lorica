//! A rung of the ladder as an entry of the unified list, and the way back out.
//!
//! **What reaches a map, and what deliberately does not.** Only the rungs for which
//! [`Tier::drops`](lorica_detect::Tier::drops) holds — 3 of the 7 — and each of them
//! writes the one exact key its reason was confirmed on. Rung 1 marks, which is
//! scheduling and lives on the TC egress path; rung 2 is the bank, whose arming is a bit
//! of the policy word the operator wrote and not something this agent adds; rung 5 asks an
//! upstream and refuses nothing here. Rung 6 does both — the announcement is
//! `lorica-escalate`'s, the local refusal of the announced prefix is this module's.
//!
//! **The alternative, with its number, and it is 1 024.** The cheap way to make a rung
//! refuse traffic is to arm the bank and let the data path drop whatever bucket is over
//! budget: no key, no map write, no withdrawal. It is not that, because
//! `DEFAULT_BANK_BUCKETS` is 1 024 and any realistic number of active sources shares them
//! by the pigeonhole principle — no quality of hashing changes that — so a bucket's level
//! is a state a second source can move, and a refusal resting on it refuses whoever else
//! hashed there. An exact key is unshareable, which is also what makes the deadline
//! sufficient rather than merely reassuring: an exact key expires, a bucket level does
//! not. `lorica-dataplane/tests/candidate_verdicts.rs` is the same statement from the
//! kernel's side, and a rung wanting to refuse "bucket 412" has no spelling in
//! `lorica-detect::tier::ladder` on purpose.
//!
//! **The honest scope of rung 1, which is a published limit and not an internal note.**
//! Marking is scheduling; scheduling happens on egress; a host schedules its own egress
//! and can do nothing about the congested upstream link a pulse wave fills. In front of a
//! fleet, as a gateway, rung 1 is fully useful — the link it schedules is the one its
//! clients are behind. On the host it protects, it is essentially observational: it can
//! reorder what this machine sends, and the packets that hurt have already arrived.

// Nothing in the agent's loop calls this yet — the tick that will is a separate change,
// and this module is reached from the tests by path. Without the allow, `mod enforce;` in
// a binary crate makes both re-exports below unused and every function here dead, and the
// build fails on -D warnings.
#![allow(dead_code, unused_imports)]

mod apply;
mod withdraw;

pub use apply::{Applied, apply};
pub use withdraw::withdraw;
