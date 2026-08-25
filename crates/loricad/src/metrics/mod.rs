//! `/metrics`, where the only hard problem is cardinality.
//!
//! **Where the cost actually is.** Nothing in this module runs in the tick. Every series is
//! written out of [`Snapshot`] at the moment a scrape arrives, so the steady-state cost on
//! the agent is zero and the measured cost of a scrape is 30 µs at 200 series. The number
//! that goes wrong is on the other side: at 100 000 series a PromQL query over four days
//! does not return inside the 60 s timeout. The budget being spent by a label is the
//! operator's time-series database, not this process, which is why no amount of
//! agent-side cleverness is the answer.
//!
//! **The rule, and it is testable.** If the number of possible values is not known while
//! the code is being written, it is not a metric. No label here takes a value chosen by
//! whoever sends the packet — source address, source port, flow identifier, observed ASN.
//! An adversary who rotates their sources would otherwise grow the defender's TSDB on
//! demand, which makes the metric an indirect denial of service against the very thing the
//! agent was installed to protect. `tests/series_cap.rs` counts the rendered series and
//! reads the rendered label names back, so the rule is enforced by the exposition and not
//! by a comment.
//!
//! **Why not OpenTelemetry**, and the reason is not the cost of its SDK. The Rust SDK
//! enforces a cardinality limit of 2 000 attribute sets per instrument, enabled by
//! default, and everything past it is folded into a single `otel.metric.overflow` series.
//! On the day of an attack that is precisely backwards: the first 2 000 addresses keep
//! their detail and every one after them disappears without a diagnostic. A bound that
//! silently drops the tail is worse than no bound, because it looks like data. A client
//! who needs OTLP gets a collector alongside the agent that scrapes this endpoint, where
//! the aggregation is visible and configured by them.
//!
//! **Why no HTTP framework.** `/metrics` is a GET that returns text. The response written
//! by hand in [`serve`] onto a tokio `TcpStream` is shorter than the code that would
//! configure a router, and `loricad` already carries tokio with `net` and `io-util`. A
//! framework would be worth a measured binary-size and dependency argument, not a
//! preference; there is none to make here because there is no routing to do.

pub mod collector;
pub mod exemplar;
pub mod registry;
pub mod serve;

use crate::control::Snapshot;

pub use collector::Exporter;
pub use exemplar::{Talker, Talkers};

/// Everything one scrape renders from.
///
/// Borrowed rather than owned: the caller already holds the snapshot it built for the
/// control socket, and a scrape that copied it would allocate on a path whose whole claim
/// is that it does not.
pub struct Source<'a> {
    pub snapshot: &'a Snapshot,
    /// Per-stage totals, indexed by `CounterId::index()`. A slice shorter than
    /// `CounterId::ALL` renders the stages it does not cover as zero, which is what a
    /// counter that has not fired should read; dropping the series instead would leave
    /// `rate()` undefined across the gap.
    ///
    /// Empty when the agent calls this today. [`Snapshot`] carries `counted` and
    /// `named_counted`, which are sums, and the sweep discards the per-slot totals it has
    /// already read out of the map. Filling this slice needs the sweep to keep the vector
    /// it reads, or the snapshot to carry it — neither is decided here.
    pub stages: &'a [u64],
    /// The bounded ring of recent top talkers. Their addresses reach the exposition as
    /// exemplars and never as label values; see [`exemplar`].
    pub talkers: &'a Talkers,
}
