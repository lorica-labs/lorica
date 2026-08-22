use carapace_common::{Family, FragState, PacketView, anomaly};

use super::{ParseError, Window};

const FIXED_HDR_LEN: usize = 40;
/// Every extension header is at least eight bytes, which is what makes one read per
/// header enough to decide its length.
const EXT_HDR_MIN: usize = 8;

/// Hard bound on the extension header chain, identical on every kernel.
///
/// `bpf_xdp_pull_data` (6.18) changes what a deep chain costs, never how deep this
/// parser goes: a depth that varied with the kernel would mean a packet judged
/// differently on two machines running the same configuration. Past the bound the
/// policy is an explicit drop with a counter, which is the bypass the reference
/// selftest leaves open.
pub const MAX_EXT_HEADERS: usize = 4;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_NONE: u8 = 59;
const IPPROTO_DSTOPTS: u8 = 60;

#[inline(never)]
pub fn parse(win: &Window, view: &mut PacketView) -> Result<(), ParseError> {
    let base = view.l3_off as usize;
    let hdr = win
        .bytes::<FIXED_HDR_LEN>(base)
        .ok_or(ParseError::Truncated)?;

    if hdr[0] >> 4 != 6 {
        return Err(ParseError::UnknownEncap);
    }

    view.set_family(Family::V6);
    // IPv6 states the payload length, not the total. The sanity stage compares like
    // with like, so the fixed header is added back here.
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]);
    view.ip_total_len = payload_len.saturating_add(FIXED_HDR_LEN as u16);
    view.src.copy_from_slice(&hdr[8..24]);
    view.dst.copy_from_slice(&hdr[24..40]);

    let mut next = hdr[6];
    let mut off = base + FIXED_HDR_LEN;

    // A bounded loop rather than bpf_loop. bpf_loop is a helper call, and the
    // per-packet helper budget is the binding constraint of the whole design; the
    // verifier has accepted bounded loops since 5.3, well under the floor.
    let mut depth = 0usize;
    while depth < MAX_EXT_HEADERS {
        if next == IPPROTO_NONE {
            // No upper layer at all. Not an error, but nothing left to parse.
            view.proto = IPPROTO_NONE;
            view.l4_off = off as u32;
            return Ok(());
        }
        if !is_extension(next) {
            break;
        }

        let ext = win.bytes::<EXT_HDR_MIN>(off).ok_or(ParseError::Truncated)?;
        let len = match next {
            IPPROTO_FRAGMENT => {
                view.set_frag(frag_state(u16::from_be_bytes([ext[2], ext[3]])));
                EXT_HDR_MIN
            }
            // The authentication header measures itself in four-byte units minus two,
            // unlike every other extension header.
            IPPROTO_AH => (ext[1] as usize + 2) * 4,
            _ => (ext[1] as usize + 1) * 8,
        };

        view.anomalies |= anomaly::IPV6_EXT_PRESENT;
        next = ext[0];
        off += len;
        depth += 1;
    }

    if is_extension(next) {
        return Err(ParseError::DepthExceeded);
    }

    view.proto = next;
    view.l4_off = off as u32;
    Ok(())
}

/// From the offset field of a fragment extension header. The layout differs from
/// IPv4: the offset is the top thirteen bits and the more-fragments flag is bit zero.
const fn frag_state(field: u16) -> FragState {
    let offset = field >> 3;
    let more = field & 1 != 0;
    match (more, offset) {
        (false, 0) => FragState::None,
        (_, 0) => FragState::First,
        _ => FragState::Later,
    }
}

const fn is_extension(proto: u8) -> bool {
    matches!(
        proto,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_AH | IPPROTO_DSTOPTS
    )
}
