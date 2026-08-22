//! The two traffic shapes the product claims to protect, and the machinery both
//! of them share.
//!
//! Every frame carries its own sequence number and the raw clock reading taken
//! just before it left. The server echoes the payload untouched, so the round
//! trip is computed from the reply itself and no state has to be kept between
//! the sending and the receiving thread.

pub mod tcp_reqresp;
pub mod udp_echo;

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::clock::Clock;
use crate::report::Report;

/// Sequence number and departure tick.
pub(crate) const HEADER_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    /// Minecraft Java: one TCP connection, small request and small reply.
    #[value(name = "tcp-reqresp")]
    TcpReqResp,
    /// FiveM: unacknowledged UDP datagrams at a steady cadence.
    #[value(name = "udp-echo")]
    UdpEcho,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::TcpReqResp => "tcp-reqresp",
            Profile::UdpEcho => "udp-echo",
        }
    }

    /// Cadences from the two workloads the tier 1 audience actually runs. They are
    /// deliberately low: the point is the tail seen by a client, not throughput.
    pub fn default_rate_pps(self) -> u32 {
        match self {
            Profile::TcpReqResp => 20,
            Profile::UdpEcho => 45,
        }
    }

    pub fn payload_len(self) -> usize {
        match self {
            Profile::TcpReqResp => 64,
            Profile::UdpEcho => 192,
        }
    }
}

pub struct LoadArgs {
    pub target: SocketAddr,
    pub rate_pps: u32,
    pub duration_s: u64,
    pub gap_detect: bool,
    /// How many send intervals of silence count as a hole rather than as jitter.
    pub gap_multiple: u32,
    pub env_file: Option<String>,
}

pub fn serve(profile: Profile, bind: SocketAddr) -> io::Result<()> {
    match profile {
        Profile::TcpReqResp => tcp_reqresp::serve(bind),
        Profile::UdpEcho => udp_echo::serve(bind),
    }
}

pub fn load(profile: Profile, args: &LoadArgs, clock: &Clock) -> io::Result<Report> {
    match profile {
        Profile::TcpReqResp => tcp_reqresp::load(args, clock),
        Profile::UdpEcho => udp_echo::load(args, clock),
    }
}

pub(crate) fn encode(seq: u64, tick: u64, len: usize) -> Vec<u8> {
    let mut frame = vec![0u8; len];
    frame[0..8].copy_from_slice(&seq.to_le_bytes());
    frame[8..16].copy_from_slice(&tick.to_le_bytes());
    frame
}

pub(crate) fn decode(frame: &[u8]) -> Option<(u64, u64)> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let seq = u64::from_le_bytes(frame[0..8].try_into().ok()?);
    let tick = u64::from_le_bytes(frame[8..16].try_into().ok()?);
    Some((seq, tick))
}

/// Sends on an absolute schedule rather than sleeping for a fixed interval, so a
/// slow send does not push every later one back and quietly lower the rate.
pub(crate) fn send_paced<F>(rate_pps: u32, duration_s: u64, mut send: F) -> io::Result<u64>
where
    F: FnMut(u64) -> io::Result<()>,
{
    let rate = rate_pps.max(1) as u64;
    let interval_ns = 1_000_000_000 / rate;
    let total = rate * duration_s;
    let start = Instant::now();

    for seq in 0..total {
        let due = start + Duration::from_nanos(seq * interval_ns);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        send(seq)?;
    }
    Ok(total)
}

/// How long the receiver keeps listening after the last frame has gone out. A
/// reply that arrives during an outage arrives late by definition; cutting the
/// receiver off at the last send would hide exactly the events being measured.
pub(crate) const DRAIN: Duration = Duration::from_secs(2);
pub(crate) const RECV_TIMEOUT: Duration = Duration::from_millis(200);
