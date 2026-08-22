//! Native attach only, and an explicit refusal naming the program already on the hook.
//!
//! Detach lives here too, and not as a test convenience. The attach-tax measurement put
//! a permanently attached program at 58 % of the receive throughput while a hot attach
//! opens no window wider than about 7 ms, so the design is detached by default and
//! attached on detection: coming and going is the production path.

pub mod attach;
pub mod hook_probe;

pub use attach::{AttachError, attach_native, detach};
pub use hook_probe::{AttachMode, HookState, Occupant};
