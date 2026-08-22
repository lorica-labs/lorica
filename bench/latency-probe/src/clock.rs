//! The measuring instrument, and the reasons not to trust it.
//!
//! Two honesty rules from the plan live here. The target has no hardware
//! timestamping — virtio exposes only the RSS hash — so the probe times packets
//! in userspace against a calibrated TSC and asks the kernel for its own software
//! receive timestamp. And when the TSC is not trustworthy the run is marked
//! degraded rather than allowed to produce a silently wrong number.

use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// Above this, the two clocks disagree by more than rounding: 1 % of a 500 us
/// p99 is 5 us, which is the size of the effects this probe has to resolve.
const MAX_CALIBRATION_ERROR_PPM: i64 = 10_000;

#[derive(Clone)]
pub struct Clock {
    inner: quanta::Clock,
    pub facts: ClockFacts,
}

#[derive(Clone, Debug)]
pub struct ClockFacts {
    pub clocksource: String,
    pub constant_tsc: bool,
    pub nonstop_tsc: bool,
    pub resolution_ns: u64,
    pub calibration_error_ppm: i64,
    /// Some(reason) means every number from this run is suspect and says so.
    pub degraded: Option<String>,
    pub caveats: Vec<String>,
}

impl Clock {
    /// Calibrates against the system clock and inspects what the kernel says about
    /// the TSC. Costs one 50 ms sleep, paid once per run.
    pub fn calibrated() -> Self {
        let inner = quanta::Clock::new();
        let clocksource = fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let flags = cpu_flags();
        let constant_tsc = flags.iter().any(|f| f == "constant_tsc");
        let nonstop_tsc = flags.iter().any(|f| f == "nonstop_tsc");

        let mut caveats = Vec::new();
        let mut degraded = None;

        let (resolution_ns, monotonic) = probe_resolution(&inner);
        let calibration_error_ppm = calibration_error_ppm(&inner);

        // quanta does not expose whether it took the TSC path or its fallback, so
        // the conditions that make the TSC unusable are checked instead. This is a
        // proxy, and it is written down as one.
        if clocksource != "tsc" {
            degraded = Some(format!("clocksource is {clocksource}, not tsc"));
        } else if !constant_tsc {
            degraded = Some("no constant_tsc: the counter changes rate with frequency".to_string());
        } else if !monotonic {
            degraded = Some("the clock went backwards during calibration".to_string());
        } else if calibration_error_ppm.abs() > MAX_CALIBRATION_ERROR_PPM {
            degraded = Some(format!("tsc disagrees with the system clock by {calibration_error_ppm} ppm"));
        }

        if !nonstop_tsc {
            // Observed on the lab target: an E5-2683 v3 guest has constant_tsc but
            // not nonstop_tsc. tsc=reliable on the command line is what makes the
            // kernel keep it, and that is an assertion by the operator, not a
            // property the guest can verify.
            caveats.push("no nonstop_tsc: the counter may stop in deep C-states, tsc=reliable is asserted".to_string());
        }
        caveats.push("no hardware timestamping on virtio: userspace TSC and kernel software timestamps only".to_string());

        Self {
            inner,
            facts: ClockFacts {
                clocksource,
                constant_tsc,
                nonstop_tsc,
                resolution_ns,
                calibration_error_ppm,
                degraded,
                caveats,
            },
        }
    }

    pub fn raw(&self) -> u64 {
        self.inner.raw()
    }

    pub fn delta_ns(&self, start: u64, end: u64) -> u64 {
        if end <= start {
            return 0;
        }
        self.inner.delta(start, end).as_nanos() as u64
    }
}

fn cpu_flags() -> Vec<String> {
    let Ok(text) = fs::read_to_string("/proc/cpuinfo") else {
        return Vec::new();
    };
    text.lines()
        .find(|l| l.starts_with("flags"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, f)| f.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Returns the smallest non-zero step the clock reports, and whether it ever
/// went backwards. The resolution is recorded rather than asserted: on this
/// hardware both the TSC and the vDSO fallback land in the tens of nanoseconds,
/// so it identifies the clock for the record without proving which one it is.
fn probe_resolution(clock: &quanta::Clock) -> (u64, bool) {
    let mut previous = clock.raw();
    let mut smallest = u64::MAX;
    let mut monotonic = true;
    for _ in 0..2_000 {
        let now = clock.raw();
        if now < previous {
            monotonic = false;
            previous = now;
            continue;
        }
        let step = clock.delta(previous, now).as_nanos() as u64;
        if step > 0 && step < smallest {
            smallest = step;
        }
        previous = now;
    }
    (if smallest == u64::MAX { 0 } else { smallest }, monotonic)
}

fn calibration_error_ppm(clock: &quanta::Clock) -> i64 {
    let reference_start = Instant::now();
    let tsc_start = clock.raw();
    std::thread::sleep(Duration::from_millis(50));
    let tsc_ns = clock.delta(tsc_start, clock.raw()).as_nanos() as i128;
    let reference_ns = reference_start.elapsed().as_nanos() as i128;
    if reference_ns == 0 {
        return 0;
    }
    (((tsc_ns - reference_ns) * 1_000_000) / reference_ns) as i64
}

// --- kernel software receive timestamps ---------------------------------------

const SOF_TIMESTAMPING_RX_SOFTWARE: libc::c_int = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: libc::c_int = 1 << 4;

/// Asks the kernel to stamp incoming packets. Failure is not fatal: the run keeps
/// its application RTT and loses only the ability to prove the load generator was
/// not itself the source of a latency spike.
pub fn request_rx_timestamps(fd: RawFd) -> io::Result<()> {
    let flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &flags as *const _ as *const libc::c_void,
            std::mem::size_of_val(&flags) as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// CLOCK_REALTIME now, on the same timeline as the kernel's receive timestamp.
pub fn realtime_ns() -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// A recvmsg that also returns the kernel's software receive timestamp when one
/// is attached. The timestamp is CLOCK_REALTIME, so it is only ever compared to
/// [`realtime_ns`], never to the TSC.
pub fn recv_timestamped(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<i128>)> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut control = [0u8; 256];
    let mut stamp = None;

    let received = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPING {
                // scm_timestamping is three timespecs; the software one is first.
                let software = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::timespec);
                if software.tv_sec != 0 || software.tv_nsec != 0 {
                    stamp = Some(software.tv_sec as i128 * 1_000_000_000 + software.tv_nsec as i128);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        n as usize
    };

    Ok((received, stamp))
}
