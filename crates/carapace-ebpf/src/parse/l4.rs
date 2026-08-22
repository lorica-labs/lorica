use carapace_common::FragState;

use super::{L3, ParseError, Window};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Up to and including the flags byte. Reading the whole twenty-byte header would
/// refuse a packet the pipeline can still judge.
const TCP_PREFIX: usize = 14;
pub const UDP_HDR_LEN: usize = 8;
/// Type and code are all the pipeline reads, but the header is eight bytes and that is
/// what the payload starts after.
const ICMP_PREFIX: usize = 2;
const ICMP_HDR_LEN: usize = 8;
/// The smallest data offset a TCP header can state, in four-byte words.
const TCP_MIN_WORDS: u8 = 5;

pub const TCP_FIN: u8 = 1 << 0;
pub const TCP_SYN: u8 = 1 << 1;
pub const TCP_RST: u8 = 1 << 2;
pub const TCP_ACK: u8 = 1 << 4;

/// From the byte holding the data offset in its upper nibble.
///
/// A data offset below five describes a header shorter than its own fixed part. It is
/// not refused — no verdict has ever been stated on it — but the length is floored, so
/// a payload read can never land back inside the header.
#[inline(always)]
pub const fn tcp_hdr_len(data_offset: u8) -> usize {
    let words = data_offset >> 4;
    let words = if words < TCP_MIN_WORDS {
        TCP_MIN_WORDS
    } else {
        words
    };
    words as usize * 4
}

/// Combinations no endpoint can produce, which makes them scans and not traffic.
///
/// A bare FIN covers more than it looks: FIN without ACK catches the FIN scan, and
/// also FIN together with RST, which has FIN set and ACK clear.
pub const fn flags_are_possible(flags: u8) -> bool {
    if flags == 0 {
        // The null scan.
        return false;
    }
    if flags & TCP_SYN != 0 && flags & TCP_FIN != 0 {
        return false;
    }
    if flags & TCP_SYN != 0 && flags & TCP_RST != 0 {
        return false;
    }
    if flags & TCP_FIN != 0 && flags & TCP_ACK == 0 {
        return false;
    }
    true
}

/// What the transport layer contributes.
pub struct L4 {
    pub sport: u16,
    pub dport: u16,
    pub l4_len: u16,
    pub tcp_flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// Bytes of transport header, which is what places the payload.
    pub hdr_len: usize,
}

impl L4 {
    /// No transport header at all: a later fragment, or a protocol this parser writes
    /// no header for. A zero header length puts the payload offset on the L4 offset,
    /// which is what it means when there is nothing to skip.
    pub(super) const NONE: Self = Self {
        sport: 0,
        dport: 0,
        l4_len: 0,
        tcp_flags: 0,
        icmp_type: 0,
        icmp_code: 0,
        hdr_len: 0,
    };
}

#[cfg_attr(feature = "profiling", inline(never))]
pub fn parse(win: &Window, l3: &L3) -> Result<L4, ParseError> {
    // A later fragment carries no L4 header. Reading one would interpret payload
    // bytes as ports, which is how a fragmented flood walks through a port filter.
    if l3.frag == FragState::Later {
        return Ok(L4::NONE);
    }

    let base = l3.l4_off;
    match l3.proto {
        IPPROTO_TCP => {
            let hdr = win.bytes::<TCP_PREFIX>(base).ok_or(ParseError::Truncated)?;
            Ok(L4 {
                sport: u16::from_be_bytes([hdr[0], hdr[1]]),
                dport: u16::from_be_bytes([hdr[2], hdr[3]]),
                tcp_flags: hdr[13],
                hdr_len: tcp_hdr_len(hdr[12]),
                ..L4::NONE
            })
        }
        IPPROTO_UDP => {
            let hdr = win
                .bytes::<UDP_HDR_LEN>(base)
                .ok_or(ParseError::Truncated)?;
            Ok(L4 {
                sport: u16::from_be_bytes([hdr[0], hdr[1]]),
                dport: u16::from_be_bytes([hdr[2], hdr[3]]),
                l4_len: u16::from_be_bytes([hdr[4], hdr[5]]),
                hdr_len: UDP_HDR_LEN,
                ..L4::NONE
            })
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let hdr = win
                .bytes::<ICMP_PREFIX>(base)
                .ok_or(ParseError::Truncated)?;
            Ok(L4 {
                icmp_type: hdr[0],
                icmp_code: hdr[1],
                hdr_len: ICMP_HDR_LEN,
                ..L4::NONE
            })
        }
        // Any other protocol reaches the list on its address alone. It carries no
        // port, so it can only match an entry with no scope.
        _ => Ok(L4::NONE),
    }
}
