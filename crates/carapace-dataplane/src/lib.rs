//! Loading, attaching, maps, batch operations and kernel capability detection.
//!
//! The module list is complete here from the start, stubs included. Three tasks fill
//! these modules in parallel and a shared file is the one thing they cannot share, so
//! this one is written once and then left alone.

pub mod capability;
pub mod loader;
pub mod maps;
