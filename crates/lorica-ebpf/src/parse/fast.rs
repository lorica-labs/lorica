//! Untagged IPv4 without options, carrying UDP or TCP.
//!
//! The shape the majority of the traffic actually has, and the one the walker charges a
//! VLAN loop, an option check and a fragment branch for without ever using one. One
//! bounds check covers the whole prefix and every field after it is a load at a constant
//! offset, in a straight line with no loop.
//!
//! It returns the same three results the walker returns, and not a view of its own. That
//! is not tidiness: a second construction of the view was measured at **+150 instructions
//! a packet** against **-20** for this one, because two live copies of a 56-byte struct in
//! the same frame spill more than the branches they remove. One assembly for both paths is
//! also what makes "the fast path cannot change a verdict" a property of the code rather
//! than a promise.
//!
//! Twenty instructions is less than the shape promised, and worth writing down. Parsing
//! cost about 300 cycles when it also carried a memset and four call boundaries; with
//! those gone the walker was already close to a straight line for this shape, and what a
//! fast path still has to win is two bounds checks and a loop guard.
//!
//! What it does not do is decide anything. A packet that is not this shape, or whose
//! prefix is not there, returns `None` and the walker states the verdict — so the fast
//! path can be wrong about the shape and never about the packet.

use lorica_common::{Family, FragState};

use super::{L3, Window, eth, ipv4, l4};

const ETH_HDR_LEN: usize = 14;
const IPV4_FIXED: usize = 20;
const L4_OFF: usize = ETH_HDR_LEN + IPV4_FIXED;
/// Ethernet, the fixed IPv4 header and a whole UDP header. The one bounds check.
const PREFIX: usize = L4_OFF + 8;
/// TCP states its data offset at byte 12 and its flags at byte 13, past the prefix. Two
/// checks for TCP then, one for UDP, which is the side of the split that matters.
const TCP_TAIL: usize = 6;

/// Version 4 with a header length of exactly five words: no options, so the transport
/// header sits at a constant offset and nothing has to be walked to find it.
const IPV4_NO_OPTIONS: u8 = 0x45;

/// One `u16` at a constant offset from a pointer the bound has already been granted on.
///
/// `from_be_bytes([p[i], p[i + 1]])` on an array reads two bytes, shifts, ors — and then LLVM
/// emits a `be16` on top of the value the shift-or already put in big-endian order. Read as a
/// `u16` and swapped once, it is one load and one `be16`.
///
/// # Safety
///
/// `at + 2` must be inside the range [`Window::window`] granted.
#[cfg(feature = "parse-pointer")]
#[inline(always)]
unsafe fn be16_at(p: *const u8, at: usize) -> u16 {
    // `read_unaligned`, because nothing says the packet starts on an even address and an
    // aligned read the hardware tolerates is still a lie to the compiler.
    u16::from_be(unsafe { core::ptr::read_unaligned(p.add(at).cast::<u16>()) })
}

/// # Safety
///
/// `at` must be inside the range [`Window::window`] granted.
#[cfg(feature = "parse-pointer")]
#[inline(always)]
unsafe fn u8_at(p: *const u8, at: usize) -> u8 {
    unsafe { core::ptr::read_unaligned(p.add(at)) }
}

#[cfg(feature = "parse-pointer")]
#[inline(always)]
pub fn headers(win: &Window) -> Option<(eth::L2, L3, l4::L4)> {
    let p = win.window::<PREFIX>(0)?;
    // SAFETY: every offset below is a literal under `PREFIX`, which is the range the line
    // above granted. The two-byte reads end at 39 and the four-byte source at 29.
    unsafe {
        if be16_at(p, 12) != eth::ETH_P_IP || u8_at(p, ETH_HDR_LEN) != IPV4_NO_OPTIONS {
            return None;
        }

        let proto = u8_at(p, 23);
        if proto != l4::IPPROTO_UDP && proto != l4::IPPROTO_TCP {
            return None;
        }

        let frag = ipv4::frag_state(be16_at(p, 20));
        if frag == FragState::Later {
            return None;
        }

        let sport = be16_at(p, 34);
        let dport = be16_at(p, 36);
        let (l4_len, tcp_flags, hdr_len) = if proto == l4::IPPROTO_UDP {
            (be16_at(p, 38), 0, l4::UDP_HDR_LEN)
        } else {
            let tail = win.window::<TCP_TAIL>(PREFIX)?;
            (0, u8_at(tail, 5), l4::tcp_hdr_len(u8_at(tail, 4)))
        };

        Some((
            eth::L2 {
                l3_off: ETH_HDR_LEN,
                ethertype: eth::ETH_P_IP,
                vlan_tags: 0,
            },
            L3 {
                family: Family::V4,
                src: ipv4::mapped([u8_at(p, 26), u8_at(p, 27), u8_at(p, 28), u8_at(p, 29)]),
                ip_total_len: be16_at(p, 16),
                frag,
                proto,
                l4_off: L4_OFF,
                anomalies: 0,
            },
            l4::L4 {
                sport,
                dport,
                l4_len,
                tcp_flags,
                hdr_len,
                ..l4::L4::NONE
            },
        ))
    }
}

#[cfg(not(feature = "parse-pointer"))]
#[inline(always)]
pub fn headers(win: &Window) -> Option<(eth::L2, L3, l4::L4)> {
    let p = win.bytes::<PREFIX>(0)?;

    if u16::from_be_bytes([p[12], p[13]]) != eth::ETH_P_IP || p[ETH_HDR_LEN] != IPV4_NO_OPTIONS {
        return None;
    }

    let proto = p[23];
    if proto != l4::IPPROTO_UDP && proto != l4::IPPROTO_TCP {
        return None;
    }

    let frag = ipv4::frag_state(u16::from_be_bytes([p[20], p[21]]));
    if frag == FragState::Later {
        // No transport header at the offset the loads below assume. The walker is where
        // it is known that a later fragment has none at all.
        return None;
    }

    let sport = u16::from_be_bytes([p[34], p[35]]);
    let dport = u16::from_be_bytes([p[36], p[37]]);
    let (l4_len, tcp_flags, hdr_len) = if proto == l4::IPPROTO_UDP {
        (u16::from_be_bytes([p[38], p[39]]), 0, l4::UDP_HDR_LEN)
    } else {
        let tail = win.bytes::<TCP_TAIL>(PREFIX)?;
        (0, tail[5], l4::tcp_hdr_len(tail[4]))
    };

    Some((
        eth::L2 {
            l3_off: ETH_HDR_LEN,
            ethertype: eth::ETH_P_IP,
            vlan_tags: 0,
        },
        L3 {
            family: Family::V4,
            src: ipv4::mapped([p[26], p[27], p[28], p[29]]),
            ip_total_len: u16::from_be_bytes([p[16], p[17]]),
            frag,
            proto,
            l4_off: L4_OFF,
            anomalies: 0,
        },
        l4::L4 {
            sport,
            dport,
            l4_len,
            tcp_flags,
            hdr_len,
            ..l4::L4::NONE
        },
    ))
}
