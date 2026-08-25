//! Types crossing the kernel and userspace boundary, and all per-packet arithmetic.
//!
//! Compiled identically into the eBPF program and into the tests, so the code under
//! test is the code that runs in the kernel. No dependency, no `std`, and no
//! knowledge of aya or of the kernel.

#![no_std]

pub mod blocklist;
pub mod bucket;
pub mod hash;
pub mod ttl;
pub mod wire;

pub use blocklist::{
    BLOCKLIST_TRIE_SYMBOL, CLASS24_BYTES, CLASS24_SYMBOL, Class24, OA_BYTES, OA_MAX_KEYS,
    OA_PROBES, OA_SLOTS, OA_TABLE_SYMBOL, OaSlot,
};
pub use bucket::{
    BANK_SLOT_BYTES, BURST_MAX, BankLayout, Bucket, Charge, DEFAULT_BANK_BUCKETS,
    DRAIN_FRACTION_BITS, Drain, Rate, SHARE_SCALE, UNITS_PER_BYTE,
};
pub use hash::{MultiplyShift, SipHasher24, fast_hash, key_words};
pub use ttl::{Clock, Deadline};
pub use wire::{
    Action, BUCKET_KEY_SYMBOLS, BUCKET_RATE_SYMBOLS, BUCKET_STALL_SYMBOL, CounterId,
    DEFAULT_SETTINGS, EventHeader, Family, FragState, LpmKey, LpmValue, MAX_OFFSET, NO_CUTOFF,
    PacketView, SCOPE_MAX, SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL,
    STAGE_CUTOFF_SHIFT, Scope, V4_MAPPED_PREFIX_BITS, anomaly, setting,
};
