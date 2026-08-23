//! Types crossing the kernel and userspace boundary, and all per-packet arithmetic.
//!
//! Compiled identically into the eBPF program and into the tests, so the code under
//! test is the code that runs in the kernel. No dependency, no `std`, and no
//! knowledge of aya or of the kernel.

#![no_std]

pub mod bucket;
pub mod hash;
pub mod ttl;
pub mod wire;

pub use bucket::{
    BANK_SLOT_BYTES, BURST_MAX, BankLayout, Bucket, Charge, DEFAULT_BANK_BUCKETS, Drain, Rate,
    SHARE_SCALE, UNITS_PER_BYTE,
};
pub use hash::{MultiplyShift, SipHasher24, fast_hash, key_words};
pub use ttl::{Clock, Deadline};
pub use wire::{
    Action, BUCKET_KEY_SYMBOLS, BUCKET_RATE_SYMBOLS, CounterId, DEFAULT_SETTINGS, EventHeader,
    Family, FragState, LpmKey, LpmValue, MAX_OFFSET, NO_CUTOFF, PacketView, SCOPE_MAX,
    SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL, STAGE_CUTOFF_SHIFT, Scope,
    V4_MAPPED_PREFIX_BITS, anomaly, setting,
};
