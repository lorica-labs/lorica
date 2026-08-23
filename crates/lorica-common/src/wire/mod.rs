//! Everything that crosses the kernel and userspace boundary.

mod counters;
mod event;
mod keys;
mod packet;
mod settings;
mod verdict;

pub use counters::CounterId;
pub use event::EventHeader;
pub use keys::{LpmKey, V4_MAPPED_PREFIX_BITS};
pub use packet::{Family, FragState, MAX_OFFSET, PacketView, anomaly};
pub use settings::{
    BUCKET_KEY_SYMBOLS, BUCKET_RATE_SYMBOLS, BUCKET_STALL_SYMBOL, DEFAULT_SETTINGS, NO_CUTOFF,
    SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL, STAGE_CUTOFF_SHIFT, setting,
};
pub use verdict::{Action, LpmValue, SCOPE_MAX, Scope};

use core::mem::{align_of, size_of};

// These types are a shared in-memory structure, not an ABI: the eBPF program and
// the agent each compile their own view of it and nothing checks them against each
// other at run time. Asserting here fails the build of both the moment one drifts.
const _: () = assert!(size_of::<Scope>() == 6);
const _: () = assert!(align_of::<Scope>() == 2);
const _: () = assert!(size_of::<LpmValue>() == 48);
const _: () = assert!(align_of::<LpmValue>() == 8);
const _: () = assert!(size_of::<LpmKey>() == 20);
const _: () = assert!(align_of::<LpmKey>() == 4);
const _: () = assert!(size_of::<EventHeader>() == 16);
const _: () = assert!(align_of::<EventHeader>() == 8);
const _: () = assert!(size_of::<PacketView>() == 56);
const _: () = assert!(align_of::<PacketView>() == 8);
