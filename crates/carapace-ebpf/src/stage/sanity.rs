//! Stage 1. Before the list, because there is no reason to hand a malformed packet to
//! the stack just because its source is a friend.
//!
//! Malformed is not the same as unwanted. A fragmented packet is not malformed and
//! goes to stage 4; an inconsistent length, an impossible combination of TCP flags and
//! the presence of IP options are what belongs here. The first two are facts about the
//! packet, the third is a policy, and the policy is stated as such.

use carapace_common::{CounterId, FragState, PacketView, anomaly};

use crate::{
    helpers,
    parse::l4::{IPPROTO_TCP, IPPROTO_UDP},
    settings,
    stage::Outcome,
};

pub const TCP_FIN: u8 = 1 << 0;
pub const TCP_SYN: u8 = 1 << 1;
pub const TCP_RST: u8 = 1 << 2;
pub const TCP_ACK: u8 = 1 << 4;

/// A UDP length field cannot be smaller than the header it is in.
const UDP_HDR_LEN: u16 = 8;

#[inline(never)]
pub fn run(view: &PacketView) -> Outcome {
    match refusal(view) {
        Some(counter) => {
            helpers::bump(counter);
            Outcome::Drop
        }
        None => Outcome::Continue,
    }
}

fn refusal(view: &PacketView) -> Option<CounterId> {
    let ip_bytes = view.packet_len.saturating_sub(view.l3_off);
    let header_bytes = view.l4_off.saturating_sub(view.l3_off);

    // Both directions are inconsistencies. A total length below the headers that were
    // parsed describes an impossible packet; one above what arrived is a forged
    // length, because XDP sees the whole frame. A frame padded to the Ethernet
    // minimum is the legitimate case of a total length below what arrived, so only
    // the strict excess is refused.
    if view.ip_total_len < header_bytes || view.ip_total_len > ip_bytes {
        return Some(CounterId::SanityIpLength);
    }

    if view.has(anomaly::IP_OPTIONS_PRESENT) && !settings::accept_ip_options() {
        return Some(CounterId::SanityIpOptionsRefused);
    }

    // A later fragment carries no transport header, so there is no length and no flag
    // to be consistent about. It is stage 4 that decides its fate.
    if view.frag() == FragState::Later {
        return None;
    }

    let l4_bytes = view.packet_len.saturating_sub(view.l4_off);
    match view.proto {
        IPPROTO_UDP if view.l4_len < UDP_HDR_LEN || view.l4_len > l4_bytes => {
            Some(CounterId::SanityL4Length)
        }
        IPPROTO_TCP if !flags_are_possible(view.tcp_flags) => Some(CounterId::SanityTcpFlags),
        _ => None,
    }
}

/// Combinations no endpoint can produce, which makes them scans and not traffic.
///
/// A bare FIN covers more than it looks: FIN without ACK catches the FIN scan, and
/// also FIN together with RST, which has FIN set and ACK clear.
const fn flags_are_possible(flags: u8) -> bool {
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
