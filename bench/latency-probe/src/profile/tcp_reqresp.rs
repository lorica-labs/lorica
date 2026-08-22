//! Minecraft Java shape: one connection, fixed-size request, fixed-size reply.
//!
//! TCP is a byte stream, so a frame can arrive split. The timestamp kept is the
//! one of the segment that *completed* the frame, which is what the application
//! would have observed anyway.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::clock::{self, Clock};
use crate::gap::GapDetector;
use crate::profile::{DRAIN, LoadArgs, RECV_TIMEOUT, decode, encode, send_paced};
use crate::report::Report;

pub fn serve(bind: SocketAddr) -> io::Result<()> {
    serve_listener(TcpListener::bind(bind)?)
}

pub fn serve_listener(listener: TcpListener) -> io::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_nodelay(true)?;
        // Nagle off and one thread per client: the profile is twenty packets per
        // second, so the cost of a thread is irrelevant next to the cost of
        // coalescing two replies into one segment.
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
    Ok(())
}

pub fn load(args: &LoadArgs, clock: &Clock) -> io::Result<Report> {
    let profile = super::Profile::TcpReqResp;
    let stream = TcpStream::connect(args.target)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(RECV_TIMEOUT))?;

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
    if let Err(e) = clock::request_rx_timestamps(stream.as_raw_fd()) {
        report.add_caveat(format!("no kernel receive timestamps: {e}"));
    }

    let done = Arc::new(AtomicBool::new(false));
    let reader_stream = stream.try_clone()?;
    let reader_clock = clock.clone();
    let reader_done = Arc::clone(&done);
    let payload_len = profile.payload_len();
    let mut detector = args
        .gap_detect
        .then(|| GapDetector::for_rate(args.rate_pps, args.gap_multiple));
    let run_start = clock.raw();

    let reader = std::thread::spawn(move || {
        let mut chunk = vec![0u8; 4096];
        let mut pending: Vec<u8> = Vec::with_capacity(4096);
        let mut samples: Vec<(u64, u64, u64, Option<u64>)> = Vec::new();
        loop {
            match clock::recv_timestamped(reader_stream.as_raw_fd(), &mut chunk) {
                Ok((0, _)) => break,
                Ok((n, stamp)) => {
                    let arrival = reader_clock.raw();
                    let user_realtime = clock::realtime_ns();
                    let kernel_delay = stamp
                        .filter(|k| user_realtime >= *k)
                        .map(|k| (user_realtime - k) as u64);
                    pending.extend_from_slice(&chunk[..n]);
                    while pending.len() >= payload_len {
                        let frame: Vec<u8> = pending.drain(..payload_len).collect();
                        let Some((seq, tick)) = decode(&frame) else { continue };
                        samples.push((
                            seq,
                            reader_clock.delta_ns(tick, arrival),
                            reader_clock.delta_ns(run_start, arrival),
                            kernel_delay,
                        ));
                    }
                }
                Err(e) if would_block(&e) => {
                    if reader_done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        samples
    });

    let mut writer = stream;
    let sent = send_paced(args.rate_pps, args.duration_s, |seq| {
        writer.write_all(&encode(seq, clock.raw(), payload_len))
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
