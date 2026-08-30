//! The jump-table backend. A skeleton, and it matches nothing today.
//!
//! The cascade next door decides each vector with a compare-and-branch, so its cost is
//! the length of the catalogue: ten vectors is ten tests a packet that matches none of
//! them still pays. A table would collapse that into one indexed jump, and a table
//! needs an indirect jump.
//!
//! eBPF has no indirect jump the verifier accepts before `gotox`, which lands in 6.19.
//! Emulating one with a bounded loop over an array puts the whole cost back and adds the
//! masked index the verifier refuses to trust. So this file states the shape and returns
//! nothing, which is a claim the compiler checks — `backend/mod.rs` holds it to the trait on
//! every build — rather than a `todo!()` that is a debt with a nicer name.
//!
//! **The blocker is the compiler and not the kernel, which is the opposite of what this file
//! used to say.** Asked on 30 August 2026: a 7.0.0-30 kernel carries `gotox` — it is in
//! `/proc/kallsyms` — and LLVM 21 cannot emit it. `llc -march=bpf -mcpu=help` offers v1 to v4
//! and nothing above, and the string does not appear in `libLLVM` at all. So raising this
//! project's kernel floor would not unblock the jump table; a newer LLVM with a fifth ISA
//! level is what would, and that is somebody else's release to make.
//!
//! Which is worth knowing before anyone plans around it: the cascade next door is 19 % of the
//! per-packet budget, and the only lever available on it today is a cheaper dispatch written
//! in the instructions that exist.
//!
//! It becomes worth writing when a measurement says the cascade is the cost, on a
//! kernel that has `gotox`. Not before: a table over ten vectors would be slower than
//! ten compares on this floor.

use lorica_common::PacketView;

use crate::stage::signature::{backend::SignatureBackend, catalog::VectorId};

pub struct Dfa;

impl SignatureBackend for Dfa {
    fn classify(_view: &PacketView) -> Option<VectorId> {
        None
    }
}
