//! Upstream escalation: one trait, and the guardrails every connector is forced through.
//!
//! **Why the local data path is not enough.** A rule in the kernel of the machine under
//! attack protects the machine's CPU and nothing else: the packets still arrive, so the
//! link still saturates and the VPS is still unreachable. The only actor that can stop
//! traffic before the link is the party upstream of it. That is what this crate asks for.
//!
//! **Why an interface with a single implementation is not over-design here, stated so a
//! reviewer can hold it against the code.** The second implementation is specified, not
//! imagined: FlowSpec and RTBH announced over BGP to the transit provider, which is how
//! an operator with their own AS does this and is strictly better than a vendor API. It
//! is absent today because the Rust BGP daemons are not mature enough to sit in the
//! failure path of a mitigation, and adopting one now would be the largest dependency in
//! the tree for a feature nobody can run yet. The alternative was to drop the trait and
//! call the webhook client directly: it costs the four guardrails of [`guard`] — declared
//! prefix, administration prefix, port range, rule bound — one hand-written copy per
//! connector, and that is exactly the code that must not be duplicated, because the copy
//! that gets a check wrong is the one that blackholes the operator's own address. So: one
//! trait, one implementation, and the next connector inherits the guardrails instead of
//! reimplementing them.

pub mod guard;

pub use lorica_common::{LpmKey, Scope};

/// What an upstream is asked to filter: a destination prefix and the transport scope
/// inside it.
///
/// [`LpmKey`] and [`Scope`] are the shapes the data path already speaks, IPv4 carried in
/// the mapped range of one key space. Escalation announces the same prefix the local rule
/// covers, so re-encoding it into an escalation-only address type would only create a
/// second place for the mapped-prefix offset to be applied twice.
#[derive(Clone, Copy, Debug)]
pub struct Announce {
    pub dest: LpmKey,
    pub scope: Scope,
}

/// What the upstream gave back, and the only thing [`Escalator::withdraw`] needs.
///
/// Opaque on purpose: a provider ticket is a provider string, and giving it a structure
/// here would invent one the next provider does not have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EscalateError {
    #[error("destination {0:?} is not inside any declared prefix")]
    Undeclared(LpmKey),
    /// The one refusal that exists because of a defect in this project rather than a
    /// mistake by the operator: a detector that misfires on the management address would
    /// otherwise ask the upstream to cut the operator off from their own machine.
    #[error("destination {0:?} is inside an administration prefix")]
    Administration(LpmKey),
    #[error("ports {lo}-{hi} are outside the permitted range")]
    PortRange { lo: u16, hi: u16 },
    #[error("{live} rules already announced, the bound is {bound}")]
    RuleBound { live: usize, bound: usize },
    /// Distinct from success by construction: a dry run returns an error, so a caller
    /// that ignores the distinction cannot report a mitigation that was never emitted.
    #[error("dry run: the request passed the guard and was not emitted")]
    DryRun,
    #[error("upstream answered HTTP {0}")]
    Status(u16),
    #[error("upstream returned no usable ticket")]
    NoTicket,
    #[error("transport")]
    Transport(#[from] std::io::Error),
}

pub trait Escalator {
    fn announce(&self, req: &Announce) -> Result<Ticket, EscalateError>;
    fn withdraw(&self, ticket: &Ticket) -> Result<(), EscalateError>;
}
