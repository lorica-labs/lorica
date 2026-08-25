//! `CONFIG_HZ` and the current jiffy, measured rather than assumed.
//!
//! The data path compares deadlines against `bpf_jiffies64`, so userspace has to build
//! them in jiffies, and the kernel exports neither the rate nor the counter: `CONFIG_HZ`
//! is a compile-time constant with no reliable interface, and `/proc/timer_list` is root
//! only and configuration dependent. What is reachable is the counter itself, through a
//! program that reads it. So the rate is a measurement: two readings a known interval
//! apart, and the jiffies between them divided by the seconds between them.

use std::{
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::{Array, MapData, MapError},
    programs::{ProgramError, TestRun as _, TestRunOptions, Xdp},
};
use lorica_common::Clock;

/// The probe, as `lorica-ebpf` declares it.
const PROGRAM: &str = "lorica_clock";
const MAP: &str = "CLOCK_PROBE";

/// The rates the kernel can be built with. `CONFIG_HZ` is a choice among these four, so a
/// reading near none of them is a bad measurement rather than an exotic kernel — and a
/// wrong rate would be wrong in every deadline the agent ever writes.
const KNOWN_HZ: [u32; 4] = [100, 250, 300, 1000];

/// How far a reading may sit from the nearest of the four, in percent. 250 and 300 are
/// 20 % apart, so a tenth is the widest tolerance that still names one rate instead of
/// two.
const TOLERANCE_PERCENT: u64 = 10;

/// Long enough that the jiffy the counter is quantised to is small: 30 jiffies at 100 Hz,
/// so 3 % on the slowest kernel, a third of the tolerance. Short enough to sit in a
/// startup, which is where it happens — once, and off the tick.
const INTERVAL: Duration = Duration::from_millis(300);

/// The shortest packet `BPF_PROG_TEST_RUN` accepts for an XDP program: the kernel refuses
/// anything below an Ethernet header. The probe never looks at it.
const MIN_PACKET: [u8; 14] = [0; 14];

#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    #[error("the object carries no {PROGRAM} program, so the jiffy rate cannot be measured")]
    NoProbe,

    #[error("the object carries no {MAP} map, so the probe has nowhere to publish")]
    NoSlot,

    #[error("running {PROGRAM} failed: {0}")]
    Run(#[from] ProgramError),

    #[error("reading {MAP} failed: {0}")]
    Read(#[from] MapError),

    #[error(
        "the jiffy counter did not move in {0:?}, so either the probe never ran or the \
         reading is not a clock"
    )]
    Stopped(Duration),

    #[error(
        "the jiffy counter ran at {raw} Hz over {elapsed:?}, and the kernel only builds \
         {KNOWN_HZ:?}; refusing rather than carrying a rate nobody recognises into every \
         deadline"
    )]
    Unrecognised { raw: u64, elapsed: Duration },
}

/// The rate and one reading of the counter.
///
/// Loads the probe, which is also what makes a later [`read`] possible. It sleeps for
/// [`INTERVAL`], so it belongs to a startup and not to a tick.
pub fn calibrate(ebpf: &mut Ebpf) -> Result<Clock, ClockError> {
    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM)
        .ok_or(ClockError::NoProbe)?
        .try_into()?;
    program.load()?;

    let first = read(ebpf)?;
    let start = Instant::now();
    thread::sleep(INTERVAL);
    let elapsed = start.elapsed();
    let second = read(ebpf)?;

    let ticks = second.saturating_sub(first);
    if ticks == 0 {
        return Err(ClockError::Stopped(elapsed));
    }
    // Integer throughout: a rate is a ratio of two counts, and the rounding below is the
    // only place an approximation is allowed to matter.
    let raw = (u128::from(ticks) * 1_000_000_000 / elapsed.as_nanos()) as u64;
    let hz = nearest_hz(raw).ok_or(ClockError::Unrecognised { raw, elapsed })?;

    Ok(Clock {
        hz,
        jiffies: second,
    })
}

/// One reading of the counter, at the cost of one program run.
///
/// The probe has to be loaded, which [`calibrate`] does. Read rather than derived from
/// the startup reading and the time since: deadline arithmetic an operator cannot see is
/// deadline arithmetic nobody can debug, and a jiffy counter that has stopped moving is
/// exactly the failure a derived number would hide.
pub fn read(ebpf: &Ebpf) -> Result<u64, ClockError> {
    let program: &Xdp = ebpf
        .program(PROGRAM)
        .ok_or(ClockError::NoProbe)?
        .try_into()?;
    program.test_run(TestRunOptions {
        data_in: Some(&MIN_PACKET),
        ..Default::default()
    })?;

    let map = ebpf.map(MAP).ok_or(ClockError::NoSlot)?;
    let slot: Array<&MapData, u64> = Array::try_from(map)?;
    Ok(slot.get(&0, 0)?)
}

/// The rate the kernel was built with, or `None` when the reading names none of them.
fn nearest_hz(raw: u64) -> Option<u32> {
    let nearest = KNOWN_HZ
        .into_iter()
        .min_by_key(|hz| u64::from(*hz).abs_diff(raw))
        .expect("KNOWN_HZ is not empty");
    (u64::from(nearest).abs_diff(raw) * 100 <= u64::from(nearest) * TOLERANCE_PERCENT)
        .then_some(nearest)
}

#[cfg(test)]
mod tests {
    use super::nearest_hz;

    #[test]
    fn a_reading_beside_one_of_the_four_rates_is_that_rate() {
        assert_eq!(nearest_hz(996), Some(1_000));
        assert_eq!(nearest_hz(1_004), Some(1_000));
        assert_eq!(nearest_hz(252), Some(250));
        assert_eq!(nearest_hz(291), Some(300));
        assert_eq!(nearest_hz(97), Some(100));
    }

    #[test]
    fn a_reading_beside_none_of_them_is_refused() {
        // 500 Hz is not a rate the kernel builds, and it sits between two that it does.
        // Rounded to either one, every deadline would be out by a factor approaching two;
        // refused, the operator hears about it at startup.
        assert_eq!(nearest_hz(500), None);
        assert_eq!(nearest_hz(0), None);
        assert_eq!(nearest_hz(150), None);
    }
}
