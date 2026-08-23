//! Whether strict reverse-path filtering decides anything on an interface, and whether
//! that answer has moved since the program was loaded.

pub mod criterion;
pub mod netlink;

pub use criterion::{Discrimination, Family, Route, discriminates};
pub use netlink::{DEFAULT_HOLD, RouteWatcher};
