//! How a packet is matched against the catalogue. Two answers are planned and the
//! choice between them is made at compile time.
//!
//! **The trait names a signature and nothing dispatches through it, on purpose.** eBPF
//! has no method table: there is no vtable in the instruction set and none the verifier
//! would accept, so `dyn SignatureBackend` cannot exist and no amount of restructuring
//! will make it. `classify` therefore takes no `&self` and the selection below is a
//! `#[cfg]` alias, which costs nothing at run time because there is nothing to select
//! at run time. The trait is here so that both backends are held to one signature by
//! the compiler rather than by a reader comparing two files — that is the entire
//! justification for an abstraction over what is currently one implementation, and it
//! is not a pattern to copy elsewhere in this tree.

pub mod branch;
pub mod dfa;

use lorica_common::PacketView;

use crate::stage::signature::catalog::VectorId;

pub trait SignatureBackend {
    /// The first vector of the catalogue the packet matches, or nothing.
    fn classify(view: &PacketView) -> Option<VectorId>;
}

/// The skeleton is held to the shared signature here rather than by being called: it
/// is compiled on every build, so it cannot drift out of the trait unnoticed while
/// waiting for the kernel that makes it worth writing.
const _: fn(&PacketView) -> Option<VectorId> = <dfa::Dfa as SignatureBackend>::classify;

#[cfg(not(feature = "signature-dfa"))]
pub use branch::Branch as Selected;
#[cfg(feature = "signature-dfa")]
pub use dfa::Dfa as Selected;
