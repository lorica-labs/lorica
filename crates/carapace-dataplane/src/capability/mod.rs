//! Which kernel capabilities this machine has, and the reference path each absent one
//! falls back to without changing the response tier that is reached.

pub mod matrix;
pub mod probe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    CpumapGro,
    BpfQdisc,
    XdpPullData,
    MultiByteMeta,
    RehashFlows,
    BpfArena,
    QueueLeasing,
}

#[derive(Clone, Copy, Debug)]
pub struct Detected {
    pub cap: Capability,
    pub available: bool,
    pub fallback: &'static str,
}

impl Capability {
    /// The row is reached through an exhaustive match on purpose: a capability added
    /// without a reference path stops compiling here. That is stronger than a test,
    /// because nobody can forget to run the compiler.
    pub const fn row(self) -> &'static matrix::Entry {
        &matrix::ROWS[match self {
            Self::CpumapGro => 0,
            Self::BpfQdisc => 1,
            Self::XdpPullData => 2,
            Self::MultiByteMeta => 3,
            Self::RehashFlows => 4,
            Self::BpfArena => 5,
            Self::QueueLeasing => 6,
        }]
    }
}
