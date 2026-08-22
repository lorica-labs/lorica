//! The order of the pipeline lives here and nowhere else.
//!
//! sanity, ICMP policy, unified LPM list, fragment policy, role-conditional uRPF,
//! signatures, leaky buckets, SYN cookies, counters. A stage never calls the next
//! one: it returns and this function decides, so the order is one readable list
//! rather than a chain to reconstruct.

pub mod bucket;
pub mod fragment;
pub mod icmp;
pub mod lpm;
pub mod sanity;
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
}

impl Outcome {
    pub const fn action(self) -> u32 {
        match self {
            Self::Pass | Self::Continue => xdp_action::XDP_PASS,
            Self::Drop => xdp_action::XDP_DROP,
        }
    }
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
    decide!(sanity::run(&view));
    cut!(3);
    decide!(icmp::run(&view));
    cut!(4);
    decide!(lpm::run(&view, now_ns));
    cut!(5);
    decide!(fragment::run(&view));
    cut!(6);
    decide!(urpf::run(&view));
    cut!(7);
    decide!(signature::run(&view));
    cut!(8);
    decide!(bucket::run(&view, now_ns));
    cut!(9);

    // The SYN cookie stage sits here, between the buckets and the counters. It is a
    // separate module on a higher kernel floor and is not part of this program.

    xdp_action::XDP_PASS
}
