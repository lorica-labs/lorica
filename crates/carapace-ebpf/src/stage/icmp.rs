//! Stage 2. Above the list and above the tiers, because two kinds of ICMP message
//! cannot be dropped without breaking the connectivity the pipeline is there to
//! protect, and neither failure is ever traced back to the filter.
//!
//! Path MTU discovery is the one the plan names: drop an ICMPv4 type 3 code 4 or an
//! ICMPv6 Packet Too Big and the path blackholes at the first oversized packet. The
//! symptom is a client stuck loading, and nobody connects it to the MTU.
//!
//! IPv6 neighbour discovery is the same guarantee applied to the other message with
//! the same property: without router and neighbour solicitation the link does not
//! resolve at all, so an operator who turned off "other ICMP" would silently lose IPv6
//! entirely. It is unconditional here for the same reason and not as a separate
//! feature.
//!
//! Unconditional means unconditional, and the flood it invites is bounded by the rate
//! limit of the leaky buckets, which is the next phase. Until then the counters are
//! what makes the volume visible.

use carapace_common::{CounterId, Family, FragState, PacketView};

use crate::{
    helpers,
    parse::l4::{IPPROTO_ICMP, IPPROTO_ICMPV6},
    settings,
    stage::Outcome,
};

const V4_DEST_UNREACH: u8 = 3;
const V4_FRAGMENTATION_NEEDED: u8 = 4;
const V4_ECHO_REPLY: u8 = 0;
const V4_ECHO_REQUEST: u8 = 8;

const V6_PACKET_TOO_BIG: u8 = 2;
const V6_ECHO_REQUEST: u8 = 128;
const V6_ECHO_REPLY: u8 = 129;
const V6_ROUTER_SOLICIT: u8 = 133;
const V6_ROUTER_ADVERT: u8 = 134;
const V6_NEIGHBOR_SOLICIT: u8 = 135;
const V6_NEIGHBOR_ADVERT: u8 = 136;

enum Class {
    /// Crosses whatever the configuration says.
    PathMtu,
    /// Crosses whatever the configuration says.
    Neighbor,
    Echo,
    Other,
}

#[inline(never)]
pub fn run(view: &PacketView) -> Outcome {
    if view.proto != IPPROTO_ICMP && view.proto != IPPROTO_ICMPV6 {
        return Outcome::Continue;
    }
    // A later fragment carries no type byte, so there is nothing to classify. Stage 4
    // owns it.
    if view.frag() == FragState::Later {
        return Outcome::Continue;
    }

    match classify(view) {
        Class::PathMtu => {
            helpers::bump(CounterId::IcmpPathMtuPassed);
            Outcome::Pass
        }
        Class::Neighbor => {
            helpers::bump(CounterId::IcmpNeighborPassed);
            Outcome::Pass
        }
        // Continue rather than pass: following the configuration includes being
        // subject to the list, which is part of the configuration.
        Class::Echo => {
            if settings::drop_icmp_echo() {
                helpers::bump(CounterId::IcmpEchoDropped);
                Outcome::Drop
            } else {
                Outcome::Continue
            }
        }
        Class::Other => {
            if settings::drop_icmp_other() {
                helpers::bump(CounterId::IcmpOtherDropped);
                Outcome::Drop
            } else {
                Outcome::Continue
            }
        }
    }
}

/// Keyed on the family rather than on the protocol byte: the two ICMP type spaces do
/// not overlap in meaning, and an ICMPv4 type read out of an IPv6 packet would be
/// nonsense.
fn classify(view: &PacketView) -> Class {
    match view.family() {
        Family::V4 => match (view.icmp_type, view.icmp_code) {
            (V4_DEST_UNREACH, V4_FRAGMENTATION_NEEDED) => Class::PathMtu,
            // Every other code of destination unreachable is useful but not
            // load-bearing, so it follows the configuration.
            (V4_ECHO_REQUEST | V4_ECHO_REPLY, _) => Class::Echo,
            _ => Class::Other,
        },
        Family::V6 => match view.icmp_type {
            V6_PACKET_TOO_BIG => Class::PathMtu,
            V6_ECHO_REQUEST | V6_ECHO_REPLY => Class::Echo,
            V6_ROUTER_SOLICIT | V6_ROUTER_ADVERT | V6_NEIGHBOR_SOLICIT | V6_NEIGHBOR_ADVERT => {
                Class::Neighbor
            }
            _ => Class::Other,
        },
    }
}
