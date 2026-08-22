use carapace_common::{Family, FragState, PacketView, anomaly};

use super::{ParseError, Window};

/// The header without options.
const FIXED_HDR_LEN: usize = 20;

#[inline(never)]
pub fn parse(win: &Window, view: &mut PacketView) -> Result<(), ParseError> {
    let base = view.l3_off as usize;
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
        return Err(ParseError::Malformed);
    }
    // IHL is four bits, so the header is at most sixty bytes and no bound on the
    // option area needs stating.
    let hdr_len = ihl_words * 4;

    view.set_family(Family::V4);
    view.ip_total_len = u16::from_be_bytes([hdr[2], hdr[3]]);
    view.set_frag(frag_state(u16::from_be_bytes([hdr[6], hdr[7]])));
    view.proto = hdr[9];
    view.src = mapped([hdr[12], hdr[13], hdr[14], hdr[15]]);
    view.dst = mapped([hdr[16], hdr[17], hdr[18], hdr[19]]);

    if hdr_len > FIXED_HDR_LEN {
        view.anomalies |= anomaly::IP_OPTIONS_PRESENT;
    }

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
    // end of the packet, this offset lands outside the window and the L4 read below
    // refuses the packet with the truncation counter.
    view.l4_off = (base + hdr_len) as u32;
    Ok(())
}

/// From the flags and fragment offset field, read as one big-endian word.
const fn frag_state(word: u16) -> FragState {
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
const fn mapped(addr: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr[0], addr[1], addr[2], addr[3],
    ]
}
