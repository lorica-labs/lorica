//! Types crossing the kernel and userspace boundary, and all per-packet arithmetic.
//!
//! Compiled identically into the eBPF program and into the tests, so the code under
//! test is the code that runs in the kernel. No dependency, no `std`, and no
//! knowledge of aya or of the kernel.

#![no_std]

pub mod hash;
pub mod ttl;
pub mod wire;

pub use hash::SipHasher24;
pub use ttl::Deadline;
pub use wire::{
    Action, CounterId, DEFAULT_SETTINGS, EventHeader, Family, FragState, LpmKey, LpmValue,
    PacketView, SCOPE_MAX, SETTINGS_SYMBOL, Scope, V4_MAPPED_PREFIX_BITS, anomaly, setting,
};
