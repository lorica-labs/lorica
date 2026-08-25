//! The policy word, patched by the loader before verification.
//!
//! A `.rodata` global rather than a map. A map read is a helper call, and it would be
//! paid by every packet that reaches a stage with a knob; a load-time global is a
//! direct memory access the verifier turns into an immediate, so it costs nothing at
//! all. The bits and their meanings live in `lorica_common::wire::settings`.

use lorica_common::{BURST_MAX, Drain, MultiplyShift, Rate, setting};

#[unsafe(no_mangle)]
static SETTINGS: u32 = 0;

/// The two multipliers the bucket index is hashed with, in two globals because `u64` is
/// unambiguously `aya::Pod` and a patched struct would need a layout both sides agree on
/// for no gain. The loader draws them from `/dev/urandom` at every load: two source
/// addresses an attacker found sharing a bucket do not share one after the next load.
///
/// Patched as drawn. `MultiplyShift::new` forces them odd, which is where that belongs: an
/// even multiplier breaks 2-universality silently and half of all random words are even.
#[unsafe(no_mangle)]
static BUCKET_KEY0: u64 = 0;
#[unsafe(no_mangle)]
static BUCKET_KEY1: u64 = 0;

/// The two budgets, four words. Globals and not a map because a map read is a helper call
/// and the per-packet budget has no room for one here.
///
/// The two rate words are `Drain` and **not** bytes per second: this program hands
/// `Bucket::charge` the jiffy counter, so the byte rate has to be scaled by the width of a
/// jiffy, and that conversion is the loader's — once per load, in userspace, off the packet
/// path. The kernel does not know `CONFIG_HZ` and could not do it here anyway.
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

/// The catalogue stage 6 was loaded with, one bit per vector in catalogue order.
///
/// Zero, and the loader patches what the configuration asks for, so a program nobody
/// configured carries no vector — the same choice the budgets above make. The point of the
/// global is that the verifier reads `.rodata` as constant and *removes* the branch of
/// every vector the bit is clear for, so the cascade costs the configuration and not the
/// catalogue.
#[unsafe(no_mangle)]
static SIGNATURE_VECTORS: u32 = 0;

/// Whether the `LPM_TRIE` stage stays in the program at all.
///
/// The two flat tables answer every IPv4 prefix, so what is left for the trie is IPv6 and
/// the exact keys the detection loop writes with a deadline. A configuration carrying
/// neither needs no trie, and this word is what removes it: the verifier reads `.rodata` as
/// constant and takes the branch out before the JIT, the same way it takes out an unarmed
/// signature vector. The legitimate path then pays one access and nothing else.
///
/// **One, and not zero like the two words above.** Their unconfigured value enforces
/// nothing, which is the safe direction for a budget. Here zero would mean *ignoring*
/// entries an operator listed, so an unpatched load has to keep the trie: a loader that
/// forgot this word must fail loud in the size assertion rather than quiet in the verdict.
#[unsafe(no_mangle)]
static BLOCKLIST_TRIE: u32 = 1;

/// Dead words the bucket update reads while it holds the bucket open, so the leak of the
/// bank can be measured against the width of its read-modify-write window.
///
/// Zero everywhere but in a measurement load, and zero costs nothing rather than little:
/// the verifier reads `.rodata` as constant, so it removes the loop before the program is
/// JITed exactly as it removes an unarmed signature vector. Not a cargo feature, because a
/// feature would mean the object the campaign measures is not the object that ships.
#[unsafe(no_mangle)]
static BUCKET_STALL: u32 = 0;

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

/// `read_volatile` for the same reason as the policy word: the loader rewrites this after
/// the compiler has seen it and before the verifier does.
#[inline(always)]
pub fn signature_vectors() -> u32 {
    // SAFETY: a plain aligned read of a static in this program own read-only data.
    unsafe { core::ptr::read_volatile(&SIGNATURE_VECTORS) }
}

/// `read_volatile` for the same reason as the policy word, and the reason it matters more
/// here: a folded read would compile the initialiser into the branch the loader is patching
/// precisely in order to delete it.
#[inline(always)]
pub fn blocklist_trie() -> bool {
    // SAFETY: a plain aligned read of a static in this program own read-only data.
    unsafe { core::ptr::read_volatile(&BLOCKLIST_TRIE) != 0 }
}

/// One read of the stall word. Volatile, and every iteration of the window takes its own:
/// a volatile access is a side effect the optimiser may neither remove nor hoist out of the
/// loop, which is what makes the dead work dead and still present.
#[inline(always)]
pub fn bucket_stall() -> u32 {
    // SAFETY: a plain aligned read of a static in this program own read-only data.
    unsafe { core::ptr::read_volatile(&BUCKET_STALL) }
}

#[inline(always)]
pub fn bucket_hasher() -> MultiplyShift {
    MultiplyShift::new([word(&BUCKET_KEY0), word(&BUCKET_KEY1)])
}

#[inline(always)]
pub fn bucket_normal_rate() -> Rate {
    Rate {
        drain: Drain::from_raw(word(&BUCKET_NORMAL_RATE)),
        burst: word(&BUCKET_NORMAL_BURST),
    }
}

#[inline(always)]
pub fn bucket_suspect_rate() -> Rate {
    Rate {
        drain: Drain::from_raw(word(&BUCKET_SUSPECT_RATE)),
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
