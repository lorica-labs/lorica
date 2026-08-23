//! The policy word, patched by the loader before verification.
//!
//! A `.rodata` global rather than a map. A map read is a helper call, and it would be
//! paid by every packet that reaches a stage with a knob; a load-time global is a
//! direct memory access the verifier turns into an immediate, so it costs nothing at
//! all. The bits and their meanings live in `lorica_common::wire::settings`.

use lorica_common::{BURST_MAX, Rate, SipHasher24, setting};

#[unsafe(no_mangle)]
static SETTINGS: u32 = 0;

/// The 128-bit key the bucket index is hashed with, in two halves because `u64` is
/// unambiguously `aya::Pod` and a patched struct would need a layout both sides agree on
/// for no gain. The loader draws it from `/dev/urandom` at every load: two source
/// addresses an attacker found sharing a bucket do not share one after the next load.
#[unsafe(no_mangle)]
static BUCKET_KEY0: u64 = 0;
#[unsafe(no_mangle)]
static BUCKET_KEY1: u64 = 0;

/// The two budgets, four words. Globals and not a map because a map read is a helper call
/// and the per-packet budget has no room for one here.
///
/// The initialisers are the *unconfigured* budget and not a strict one on purpose. Zero
/// means refuse everything in this arithmetic, so a load that forgot to patch these would
/// count every packet in the program as excess; leaving nothing enforced until an operator
/// says otherwise is the same default the policy word takes.
#[unsafe(no_mangle)]
static BUCKET_NORMAL_RATE: u64 = u64::MAX;
#[unsafe(no_mangle)]
static BUCKET_NORMAL_BURST: u64 = BURST_MAX;
#[unsafe(no_mangle)]
static BUCKET_SUSPECT_RATE: u64 = u64::MAX;
#[unsafe(no_mangle)]
static BUCKET_SUSPECT_BURST: u64 = BURST_MAX;

/// Same `read_volatile` as the policy word and for the same reason: a folded read would
/// compile the initialiser into the program the loader is about to patch.
#[inline(always)]
fn word(global: &u64) -> u64 {
    // SAFETY: a plain aligned read of a static in this program own read-only data.
    unsafe { core::ptr::read_volatile(global) }
}

/// `read_volatile` so the zero initialiser is not constant-folded away: the loader
/// rewrites this word before the program is verified, and a folded read would compile
/// the default into every branch.
#[inline(always)]
fn flags() -> u32 {
    // SAFETY: a plain aligned read of a static in this program own read-only data.
    unsafe { core::ptr::read_volatile(&SETTINGS) }
}

#[inline(always)]
pub fn accept_ip_options() -> bool {
    flags() & setting::ACCEPT_IP_OPTIONS != 0
}

#[inline(always)]
pub fn drop_icmp_echo() -> bool {
    flags() & setting::DROP_ICMP_ECHO != 0
}

#[inline(always)]
pub fn drop_icmp_other() -> bool {
    flags() & setting::DROP_ICMP_OTHER != 0
}

#[inline(always)]
pub fn allow_later_fragments() -> bool {
    flags() & setting::ALLOW_LATER_FRAGMENTS != 0
}

#[inline(always)]
pub fn urpf_enforce() -> bool {
    flags() & setting::URPF_ENFORCE != 0
}

#[inline(always)]
pub fn enforce_signatures() -> bool {
    flags() & setting::ENFORCE_SIGNATURES != 0
}

#[inline(always)]
pub fn enforce_buckets() -> bool {
    flags() & setting::ENFORCE_BUCKETS != 0
}

#[inline(always)]
pub fn mark_over_budget() -> bool {
    flags() & setting::MARK_OVER_BUDGET != 0
}

#[inline(always)]
pub fn bucket_hasher() -> SipHasher24 {
    SipHasher24::new([word(&BUCKET_KEY0), word(&BUCKET_KEY1)])
}

#[inline(always)]
pub fn bucket_normal_rate() -> Rate {
    Rate {
        per_sec: word(&BUCKET_NORMAL_RATE),
        burst: word(&BUCKET_NORMAL_BURST),
    }
}

#[inline(always)]
pub fn bucket_suspect_rate() -> Rate {
    Rate {
        per_sec: word(&BUCKET_SUSPECT_RATE),
        burst: word(&BUCKET_SUSPECT_BURST),
    }
}

/// Where the pipeline stops, for the per-stage cost measurement and nowhere else.
///
/// Only compiled into the measurement object, so the object that ships has no cutoff to
/// read and pays nothing for one. Zero runs the whole pipeline.
#[cfg(feature = "stage-cutoff")]
#[inline(always)]
pub fn stage_cutoff() -> u32 {
    flags() >> lorica_common::STAGE_CUTOFF_SHIFT
}
