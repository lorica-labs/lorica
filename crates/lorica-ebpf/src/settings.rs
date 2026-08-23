//! The policy word, patched by the loader before verification.
//!
//! A `.rodata` global rather than a map. A map read is a helper call, and it would be
//! paid by every packet that reaches a stage with a knob; a load-time global is a
//! direct memory access the verifier turns into an immediate, so it costs nothing at
//! all. The bits and their meanings live in `lorica_common::wire::settings`.

use lorica_common::setting;

#[unsafe(no_mangle)]
static SETTINGS: u32 = 0;

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

/// Where the pipeline stops, for the per-stage cost measurement and nowhere else.
///
/// Only compiled into the measurement object, so the object that ships has no cutoff to
/// read and pays nothing for one. Zero runs the whole pipeline.
#[cfg(feature = "stage-cutoff")]
#[inline(always)]
pub fn stage_cutoff() -> u32 {
    flags() >> lorica_common::STAGE_CUTOFF_SHIFT
}
