//! Declarative configuration compiled into map entries, validated before it is
//! emitted.
//!
//! Every refusal in this crate is a refusal at compile time. A rule the data path
//! cannot honour has to reach the operator while they are reading the file, not fail
//! silently under attack.

pub mod blocklist;
pub mod compile;
pub mod config;
pub mod profile;

pub use blocklist::{BuildError, Snapshot, build};
pub use compile::{CompileError, Compiled, Warning, compile};
pub use config::Config;
pub use profile::{MapSizes, MemlockModel, ProfileKind, REFERENCE_CPUS};
