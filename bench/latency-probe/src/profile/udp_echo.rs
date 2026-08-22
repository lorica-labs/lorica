//! FiveM shape: unacknowledged datagrams at a steady cadence, echoed verbatim.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::clock::{self, Clock};
use crate::gap::GapDetector;
use crate::profile::{DRAIN, LoadArgs, RECV_TIMEOUT, decode, encode, send_paced};
use crate::report::Report;

pub fn serve(bind: SocketAddr) -> io::Result<()> {
    serve_socket(UdpSocket::bind(bind)?)
}

pub fn serve_socket(socket: UdpSocket) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf)?;
        socket.send_to(&buf[..n], from)?;
    }
}

pub fn load(args: &LoadArgs, clock: &Clock) -> io::Result<Report> {
    let profile = super::Profile::UdpEcho;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(args.target)?;
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;

    let mut report = Report::new(profile, args.rate_pps, args.duration_s);
    for caveat in &clock.facts.caveats {
        report.add_caveat(caveat.clone());
    }
    if let Some(reason) = &clock.facts.degraded {
        report.set_degraded(reason.clone());
    }
    if let Some(env) = &args.env_file {
        report.set_env_file(env.clone());
    }
    if let Err(e) = clock::request_rx_timestamps(socket.as_raw_fd()) {
        report.add_caveat(format!("no kernel receive timestamps: {e}"));
    }

    let done = Arc::new(AtomicBool::new(false));
    let reader_socket = socket.try_clone()?;
    let reader_clock = clock.clone();
    let reader_done = Arc::clone(&done);
    let payload_len = profile.payload_len();
    let mut detector = args
        .gap_detect
        .then(|| GapDetector::for_rate(args.rate_pps, args.gap_multiple));
    let run_start = clock.raw();

    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; payload_len.max(2048)];
        let mut samples: Vec<(u64, u64, u64, Option<u64>)> = Vec::new();
        loop {
            match clock::recv_timestamped(reader_socket.as_raw_fd(), &mut buf) {
                Ok((n, stamp)) => {
                    let arrival = reader_clock.raw();
                    let user_realtime = clock::realtime_ns();
                    let Some((seq, tick)) = decode(&buf[..n]) else { continue };
                    let kernel_delay = stamp
                        .filter(|k| user_realtime >= *k)
                        .map(|k| (user_realtime - k) as u64);
                    samples.push((
                        seq,
                        reader_clock.delta_ns(tick, arrival),
                        reader_clock.delta_ns(run_start, arrival),
                        kernel_delay,
                    ));
                }
                Err(e) if would_block(&e) => {
                    if reader_done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // A queued ICMP port-unreachable surfaces here as ECONNREFUSED; it
                // refers to an earlier datagram, not a dead socket, so keep reading.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(_) => break,
            }
        }
        samples
    });

    // A UDP send can fail with ECONNREFUSED when a queued ICMP port-unreachable
    // from an earlier packet is delivered — a transient at startup or when the
    // path stalls, exactly the moment this probe exists to measure. Dropping the
    // datagram and continuing is correct for a lossy protocol; aborting would turn
    // a measurable outage into no data at all.
    let sent = send_paced(args.rate_pps, args.duration_s, |seq| {
        match socket.send(&encode(seq, clock.raw(), payload_len)) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    })?;

    // Taken before the drain: the silence after the final send is expected, and
    // counting it would put a gap on every clean run.
    let last_send_ns = clock.delta_ns(run_start, clock.raw());

    std::thread::sleep(DRAIN);
    done.store(true, Ordering::Relaxed);
    let samples = reader.join().map_err(|_| io::Error::other("receiver thread panicked"))?;

    report.set_sent(sent);
    for (seq, rtt_ns, since_start_ns, kernel_delay) in samples {
        report.record_rtt(rtt_ns);
        if let Some(delay) = kernel_delay {
            report.record_kernel_delay(delay);
        }
        if let Some(detector) = detector.as_mut() {
            detector.observe(seq, since_start_ns);
        }
    }
    if let Some(detector) = detector {
        report.set_gaps(detector.finish(last_send_ns));
    }
    Ok(report)
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}
