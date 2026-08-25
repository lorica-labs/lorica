//! Snapshots to tiers: hysteresis, descent, cardinality.
//!
//! No I/O and no clock: the tick reads the maps and hands the time down. See
//! [`window`] for why there are two cadences and [`tier::ladder`] for what a rung that
//! refuses packets is allowed to rest on.

pub mod cardinality;
pub mod snapshot;
pub mod tier;
pub mod window;

pub use cardinality::{Params, PrefixCardinality, Verdict};
pub use snapshot::{BucketView, CounterView, EntryCounter, Snapshot};
pub use tier::hysteresis::Hysteresis;
pub use tier::ladder::{Confirmation, Decision, Reason, Tier};
pub use tier::{Config, Engine, Metrics};
pub use window::{FAST_PERIOD_NS, SLOW_PERIOD_NS, Window};
