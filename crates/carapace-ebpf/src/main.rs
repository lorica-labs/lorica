#![no_std]
#![no_main]

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects unreachable code paths that loop forever, but this
    // handler is never reached: the program is built with panic = "abort" and
    // every bound is checked explicitly.
    unsafe { core::hint::unreachable_unchecked() }
}
