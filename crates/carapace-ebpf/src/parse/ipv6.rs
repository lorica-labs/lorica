use carapace_common::{Family, FragState, anomaly};

use super::{L3, ParseError, Window};

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
const IPPROTO_DSTOPTS: u8 = 60;

#[cfg_attr(feature = "profiling", inline(never))]
pub fn parse(win: &Window, base: usize) -> Result<L3, ParseError> {
    let hdr = win
        .bytes::<FIXED_HDR_LEN>(base)
        .ok_or(ParseError::Truncated)?;

    if hdr[0] >> 4 != 6 {
        return Err(ParseError::UnknownEncap);
    }

    let mut next = hdr[6];
    let mut off = base + FIXED_HDR_LEN;
    let mut frag = FragState::None;
    let mut anomalies = 0u8;

    // A bounded loop rather than bpf_loop. bpf_loop is a helper call, and the
    // per-packet helper budget is the binding constraint of the whole design; the
    // verifier has accepted bounded loops since 5.3, well under the floor.
    let mut depth = 0usize;
    while depth < MAX_EXT_HEADERS {
        if !is_extension(next) {
            // `IPPROTO_NONE` leaves the loop here as well: no upper layer at all is
            // not an error, and it needs no arm of its own because it ends the walk
            // exactly where a transport header would, with the same offset.
            break;
        }

        let ext = win.bytes::<EXT_HDR_MIN>(off).ok_or(ParseError::Truncated)?;
        let len = match next {
            IPPROTO_FRAGMENT => {
                frag = frag_state(u16::from_be_bytes([ext[2], ext[3]]));
                EXT_HDR_MIN
            }
            // The authentication header measures itself in four-byte units minus two,
            // unlike every other extension header.
            IPPROTO_AH => (ext[1] as usize + 2) * 4,
            _ => (ext[1] as usize + 1) * 8,
        };

        anomalies |= anomaly::IPV6_EXT_PRESENT;
        next = ext[0];
        off += len;
        depth += 1;
    }

    if is_extension(next) {
        return Err(ParseError::DepthExceeded);
    }

    // IPv6 states the payload length, not the total. The length checks compare like
    // with like, so the fixed header is added back here.
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]);
    Ok(L3 {
        family: Family::V6,
        src: source(&hdr),
        ip_total_len: payload_len.saturating_add(FIXED_HDR_LEN as u16),
        frag,
        proto: next,
        l4_off: off,
        anomalies,
    })
}

/// The source address out of the fixed header, written out rather than sliced: a
/// slice-to-array conversion carries a length check, and a panic path in a program
/// whose handler is `unreachable_unchecked` is not a path worth emitting.
const fn source(hdr: &[u8; FIXED_HDR_LEN]) -> [u8; 16] {
    [
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17],
        hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
    ]
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
