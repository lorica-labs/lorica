//! Everything that must hold before one byte leaves for the upstream.
//!
//! **Why the checks are here and not in the client.** An escalation is the only action in
//! this project that a third party executes on our behalf, at a scale we cannot undo and
//! on an infrastructure we do not own. A detection defect that reaches the upstream is
//! therefore not a false positive, it is an outage we paid someone else to cause. The
//! alternative was to validate inside the webhook client, next to the code that already
//! holds the endpoint and the token: it was rejected because it leaves the payload builder
//! reachable from any caller, and the count that matters is how many ways there are to
//! emit without being checked — one, in that design, and zero here.
//!
//! **How zero is obtained.** [`Admitted`] wraps the request in a private field, so the
//! only expression in the crate that produces one is the tail of [`Guard::admit`], and the
//! function that builds the request body takes an `&Admitted`. There is no constructor to
//! forget to call: a connector that skips the guard has nothing to serialise.

use std::ops::RangeInclusive;

use crate::{Announce, EscalateError, LpmKey};

/// The bounds an operator sets on what may ever be escalated.
///
/// The fields are public and carry no defaults because every one of them is a decision
/// only the operator can make, and a default would be this crate guessing which of their
/// prefixes it may hand to a third party. They are supplied by the caller: the policy
/// configuration does not carry them yet.
pub struct Guard {
    /// Prefixes this deployment is allowed to ask an upstream about, normally the
    /// addresses the operator actually holds. Anything else is either a detection defect
    /// or an attempt to use our credentials to blackhole a stranger.
    pub declared: Vec<LpmKey>,
    /// Prefixes that must never be escalated even though they are declared: management,
    /// the address SSH answers on, the out-of-band link. Checked first, so an overlap with
    /// [`Self::declared`] resolves as a refusal.
    pub administration: Vec<LpmKey>,
    pub ports: RangeInclusive<u16>,
    /// Ceiling on rules held upstream at once. A retry loop or a flapping detector turns
    /// an unbounded connector into a request amplifier against the provider's API, and the
    /// provider answers that by rate-limiting the account that will need it next.
    pub rule_bound: usize,
    pub dry_run: bool,
}

/// A request that has passed every check, and the only argument the emitter accepts.
///
/// Borrows rather than copies the request so that the value emitted is the value checked,
/// with no window in which a caller could edit a copy after admission.
#[derive(Debug)]
pub struct Admitted<'a>(&'a Announce);

impl Admitted<'_> {
    pub fn request(&self) -> &Announce {
        self.0
    }
}

impl Guard {
    /// `live` is the number of rules the connector currently holds upstream.
    ///
    /// The dry-run refusal comes last on purpose: a request that is both malformed and dry
    /// reports what is wrong with it, so an operator rehearsing a mitigation learns that
    /// the port range is wrong now rather than the first time they run for real.
    pub fn admit<'a>(&self, req: &'a Announce, live: usize) -> Result<Admitted<'a>, EscalateError> {
        if self.administration.iter().any(|p| covers(p, &req.dest)) {
            return Err(EscalateError::Administration(req.dest));
        }
        if !self.declared.iter().any(|p| covers(p, &req.dest)) {
            return Err(EscalateError::Undeclared(req.dest));
        }
        let (lo, hi) = (req.scope.port_lo, req.scope.port_hi);
        if lo > hi || !self.ports.contains(&lo) || !self.ports.contains(&hi) {
            return Err(EscalateError::PortRange { lo, hi });
        }
        if live >= self.rule_bound {
            return Err(EscalateError::RuleBound {
                live,
                bound: self.rule_bound,
            });
        }
        if self.dry_run {
            return Err(EscalateError::DryRun);
        }
        Ok(Admitted(req))
    }
}

/// Whether `outer` contains `inner`, both in the unified key space where IPv4 sits behind
/// `::ffff:0:0/96`.
///
/// One `u128` comparison rather than a byte loop, and it is the mapped range that makes
/// the two families safe to mix: an IPv4 declaration cannot accidentally contain an IPv6
/// destination, because RFC 4291 reserves those 96 bits and no real IPv6 prefix lives
/// there. A prefix longer than the key it is compared against never contains it, which is
/// the case that keeps a `/32` declaration from covering a `/24` announcement.
fn covers(outer: &LpmKey, inner: &LpmKey) -> bool {
    if outer.prefix_len > 128 || inner.prefix_len < outer.prefix_len {
        return false;
    }
    let mask = match outer.prefix_len {
        0 => 0,
        bits => u128::MAX << (128 - bits),
    };
    u128::from_be_bytes(outer.addr) & mask == u128::from_be_bytes(inner.addr) & mask
}
