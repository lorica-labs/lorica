//! Shared surface of the kernel tests. Cited by every stage test of every phase, so
//! it changes by addition.

// Every test target compiles this module and uses a part of its surface, so whatever
// another target uses looks dead from here.
#![allow(dead_code, unused_imports)]

pub mod pkt;
pub mod run;

pub use pkt::PktBuilder;
pub use run::{TestProg, XdpAction};

/// The name of the program under test, as it appears in the ELF.
pub const PROGRAM: &str = "carapace_xdp";

pub fn program() -> TestProg {
    TestProg::load(PROGRAM)
}

pub fn program_with(settings: u32) -> TestProg {
    TestProg::load_with(PROGRAM, settings)
}
