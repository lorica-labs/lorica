#![no_std]
#![no_main]

mod helpers;
mod maps;
mod parse;
mod settings;
mod stage;

use aya_ebpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn carapace_xdp(ctx: XdpContext) -> u32 {
    stage::run(&ctx)
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
