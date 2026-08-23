use lorica_common::{Family, FragState, anomaly};

use super::{L3, ParseError, Window};

/// The header without options.
const FIXED_HDR_LEN: usize = 20;

#[cfg_attr(feature = "profiling", inline(never))]
pub fn parse(win: &Window, base: usize) -> Result<L3, ParseError> {
    let hdr = win
        .bytes::<FIXED_HDR_LEN>(base)
        .ok_or(ParseError::Truncated)?;

    if hdr[0] >> 4 != 4 {
        return Err(ParseError::UnknownEncap);
    }

    let ihl_words = (hdr[0] & 0x0f) as usize;
    if ihl_words < FIXED_HDR_LEN / 4 {
        // A header shorter than its own fixed part. Parseable bytes, impossible
        // packet: the L4 offset it implies would point inside the IP header.
        return Err(ParseError::IpLength);
    }
    // IHL is four bits, so the header is at most sixty bytes and no bound on the
    // option area needs stating.
    let hdr_len = ihl_words * 4;

    // The option chain is deliberately not walked.
    //
    // Walking it would buy exactly one thing, a counter distinguishing a malformed
    // option list from a well formed one, and would change no verdict: the sanity
    // policy is stated on the presence of options, not on their contents, and every
    // option-based attack that matters is covered by refusing options outright. What
    // it would cost is a bounded walk over attacker-chosen lengths, which is where
    // the classic zero-length-option infinite loop lives. Not walking removes the
    // hazard instead of guarding it.
    //
    // Nothing is let through by the omission either. If the option area runs past the
    // end of the packet, this offset lands outside the window and the L4 read refuses
    // the packet with the truncation counter.
    Ok(L3 {
        family: Family::V4,
        src: mapped([hdr[12], hdr[13], hdr[14], hdr[15]]),
        ip_total_len: u16::from_be_bytes([hdr[2], hdr[3]]),
        frag: frag_state(u16::from_be_bytes([hdr[6], hdr[7]])),
        proto: hdr[9],
        l4_off: base + hdr_len,
        anomalies: if hdr_len > FIXED_HDR_LEN {
            anomaly::IP_OPTIONS_PRESENT
        } else {
            0
        },
    })
}

/// From the flags and fragment offset field, read as one big-endian word. Shared with
/// the fast path, which reads the same word at a constant offset.
pub(super) const fn frag_state(word: u16) -> FragState {
    const MORE_FRAGMENTS: u16 = 0x2000;
    const OFFSET_MASK: u16 = 0x1fff;

    let more = word & MORE_FRAGMENTS != 0;
    let offset = word & OFFSET_MASK;
    match (more, offset) {
        (false, 0) => FragState::None,
        (_, 0) => FragState::First,
        _ => FragState::Later,
    }
}

/// IPv4 in the unified 16-byte key, as `::ffff:a.b.c.d`.
pub(super) const fn mapped(addr: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr[0], addr[1], addr[2], addr[3],
    ]
}
