use carapace_common::{FragState, PacketView};

use super::{ParseError, Window};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Up to and including the flags byte. Reading the whole twenty-byte header would
/// refuse a packet the pipeline can still judge.
const TCP_PREFIX: usize = 14;
const UDP_HDR_LEN: usize = 8;
const ICMP_PREFIX: usize = 2;

#[inline(never)]
pub fn parse(win: &Window, view: &mut PacketView) -> Result<(), ParseError> {
    // A later fragment carries no L4 header. Reading one would interpret payload
    // bytes as ports, which is how a fragmented flood walks through a port filter.
    if view.frag() == FragState::Later {
        return Ok(());
    }

    let base = view.l4_off as usize;
    match view.proto {
        IPPROTO_TCP => {
            let hdr = win.bytes::<TCP_PREFIX>(base).ok_or(ParseError::Truncated)?;
            view.sport = u16::from_be_bytes([hdr[0], hdr[1]]);
            view.dport = u16::from_be_bytes([hdr[2], hdr[3]]);
            view.tcp_flags = hdr[13];
        }
        IPPROTO_UDP => {
            let hdr = win
                .bytes::<UDP_HDR_LEN>(base)
                .ok_or(ParseError::Truncated)?;
            view.sport = u16::from_be_bytes([hdr[0], hdr[1]]);
            view.dport = u16::from_be_bytes([hdr[2], hdr[3]]);
            view.l4_len = u16::from_be_bytes([hdr[4], hdr[5]]);
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let hdr = win
                .bytes::<ICMP_PREFIX>(base)
                .ok_or(ParseError::Truncated)?;
            view.icmp_type = hdr[0];
            view.icmp_code = hdr[1];
        }
        // Any other protocol reaches the list on its address alone. It carries no
        // port, so it can only match an entry with no scope.
        _ => {}
    }
    Ok(())
}
