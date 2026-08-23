#![no_std]
#![no_main]

mod helpers;
mod maps;
mod parse;
mod settings;
mod stage;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn lorica_xdp(ctx: XdpContext) -> u32 {
    stage::run(&ctx)
}

/// The clock probe. The agent runs it twice, a known interval apart, and reads
/// `CONFIG_HZ` off the jiffies between the two readings.
///
/// It publishes through a map and not through the return value, which
/// `BPF_PROG_TEST_RUN` reports as 32 bits: the low half of the counter alone would put
/// every deadline built from it up to 2^32 jiffies in the past, and already expired is
/// the direction that costs an `Allow` entry. Nothing attaches this program, it exists
/// to be run.
#[xdp]
pub fn lorica_clock(_ctx: XdpContext) -> u32 {
    if let Some(slot) = maps::CLOCK_PROBE.get_ptr_mut(0) {
        // SAFETY: the pointer comes from a successful array lookup, and the agent runs
        // this program one invocation at a time.
        unsafe { *slot = helpers::now_jiffies() }
    }
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable by construction: the program is built with panic = "abort" and
    // every bound is checked explicitly, so no path panics. A loop here would be a
    // verifier rejection if it ever became reachable, which is the failure mode we
    // want over a silent infinite loop in softirq context.
    unsafe { core::hint::unreachable_unchecked() }
}
