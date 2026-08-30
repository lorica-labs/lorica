//! Everything that crosses the kernel and userspace boundary.

mod counters;
mod event;
mod keys;
mod packet;
mod settings;
mod verdict;

pub use counters::{
    COUNTER_STRIPE_SLOTS, COUNTER_STRIPE_SYMBOL, CounterId, CounterLayout, MAX_CPUS,
};
pub use event::EventHeader;
pub use keys::{LpmKey, V4_MAPPED_PREFIX_BITS};
pub use packet::{Family, FragState, MAX_OFFSET, PacketView, anomaly};
pub use settings::{
    BUCKET_KEY_SYMBOLS, BUCKET_RATE_SYMBOLS, BUCKET_STALL_SYMBOL, DEFAULT_SETTINGS, NO_CUTOFF,
    OPERATOR_SETTINGS, SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL,
    STAGE_CUTOFF_SHIFT, setting, settings_word,
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
// Forty bytes and two-aligned, and it was fifty-six and eight-aligned while it carried the
// two packet pointers. Losing them lost the `u64` that set the alignment, and nothing needs
// the old one: a map value is page-aligned whatever this says, and the eight bytes of padding
// the struct used to carry were eight bytes the entry point held live across seven stage
// calls with ten registers to do it in.
const _: () = assert!(size_of::<PacketView>() == 40);
const _: () = assert!(align_of::<PacketView>() == 2);
