//! The order of the pipeline lives here and nowhere else.
//!
//! ICMP policy, unified LPM list, fragment policy, role-conditional uRPF, signatures,
//! leaky buckets, SYN cookies, counters. A stage never calls the next one: it returns
//! and this function decides, so the order is one readable list rather than a chain to
//! reconstruct.
//!
//! Sanity was the first of them and no longer is. Its three checks are comparisons on
//! fields the parse has just loaded, so they are made there, in `parse::refuse`, and the
//! four counters they bump keep their names. What is left in this list is every stage
//! that needs something the parse does not have: a map, the clock, or a policy word read
//! against more than one field.

pub mod bucket;
pub mod fragment;
pub mod icmp;
pub mod lpm;
pub mod signature;
pub mod urpf;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};

use crate::{helpers, parse};

/// What a stage returns.
///
/// `Continue` is not a verdict, it is the absence of one. A stage that has nothing
/// to say says so and costs a compare.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Continue,
    Pass,
    Drop,
    /// Stage 6 only, and not a verdict. The chain of the spec writes
    /// `DROP / RATE-LIMIT` for the signatures, and rate-limiting is a routing decision:
    /// the packet goes on to the buckets and is charged against the tighter of the two
    /// budgets. The pipeline routes this variant rather than returning it, which is why
    /// `decide!` does not handle it.
    //
    // `expect` and not `allow`: the day the signature stage constructs this variant the
    // expectation goes unfulfilled and the build says so, which removes the attribute
    // instead of leaving it to be noticed.
    #[expect(dead_code)]
    RateLimit,
    /// Stage 7 only. Over budget, and the operator asked for the excess to reach the
    /// stack tagged rather than to be dropped.
    ///
    /// Reachable only when the loader found the metadata capability, since marking in XDP
    /// means writing into `xdp_md` metadata for the stack to read. On the kernel floor of
    /// the project that capability answers no, so the stage answers `Drop` and the verdict
    /// stays in the data plane — which is the reference path the capability matrix names,
    /// and the same response tier either way.
    #[expect(dead_code)]
    Mark,
}

impl Outcome {
    pub const fn action(self) -> u32 {
        match self {
            // Marking wrote the metadata before returning, so what is left to do is let
            // the packet through.
            Self::Pass | Self::Continue | Self::Mark => xdp_action::XDP_PASS,
            Self::Drop => xdp_action::XDP_DROP,
            // Stage 6 is the only producer and the pipeline consumes it there, so this
            // arm is not reachable. It passes rather than drops: of the two ways to be
            // wrong about a packet no stage decided on, dropping is the one that cannot
            // be taken back.
            Self::RateLimit => xdp_action::XDP_PASS,
        }
    }
}

/// Which of the two fixed budgets the buckets charge a packet against.
///
/// This phase applies budgets that come from the configuration and never varies them.
/// What stage 6 chooses here is which of the two applies, not how large either one is:
/// varying a budget from an attack state is the next phase.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    Normal,
    Suspect,
}

/// Returns the outcome of a stage unless it has nothing to say.
macro_rules! decide {
    ($outcome:expr) => {
        match $outcome {
            Outcome::Continue => {}
            settled => return settled.action(),
        }
    };
}

/// Ends the walk here when the measurement asked for a pipeline this long.
///
/// The cost of one stage is the difference between two whole-path measurements, which is
/// the only reading that comes out in nanoseconds: each stage does have its own JIT
/// symbol, but four of them are named `run`, and on this hardware a third of the samples
/// of a profile land in the XDP dispatcher trampoline rather than in the program.
#[cfg(feature = "stage-cutoff")]
macro_rules! cut {
    ($stages:expr) => {
        if crate::settings::stage_cutoff() == $stages {
            return xdp_action::XDP_PASS;
        }
    };
}

/// Absent from the object that ships, so the pipeline it measures is one compare per
/// stage away from the pipeline that runs. That difference is itself measured, by
/// comparing the deepest cutoff against the plain object.
#[cfg(not(feature = "stage-cutoff"))]
macro_rules! cut {
    ($stages:expr) => {};
}

pub fn run(ctx: &XdpContext) -> u32 {
    let view = match parse::parse(ctx) {
        Ok(view) => view,
        Err(err) => {
            let (action, counter) = err.outcome();
            helpers::bump(counter);
            return action;
        }
    };

    #[cfg(feature = "parse-probe")]
    helpers::probe(&view);

    cut!(1);

    // Read once, passed down. The TTL comparison and, from the next phase, the leaky
    // buckets share this reading: taking it twice would double the one helper call
    // the per-packet budget allows outside the lookups.
    let now_ns = helpers::now_ns();

    cut!(2);
    decide!(icmp::run(&view));
    cut!(3);
    decide!(lpm::run(&view, now_ns));
    cut!(4);
    decide!(fragment::run(&view));
    cut!(5);
    decide!(urpf::run(&view));
    cut!(6);

    // Stage 6 has three answers and only two of them end the walk. Rate-limiting is not a
    // verdict, so it is routed here and not returned: the packet reaches the buckets
    // carrying which budget it is charged against.
    let budget = match signature::run(&view) {
        Outcome::Continue => Budget::Normal,
        Outcome::RateLimit => Budget::Suspect,
        settled => return settled.action(),
    };

    cut!(7);
    decide!(bucket::run(&view, now_ns, budget));
    cut!(8);

    // The SYN cookie stage sits here, between the buckets and the counters. It is a
    // separate module on a higher kernel floor and is not part of this program.

    xdp_action::XDP_PASS
}
