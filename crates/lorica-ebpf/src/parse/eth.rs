use super::{ParseError, Window};

pub const ETH_HDR_LEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;

/// Two tags cover 802.1Q and QinQ, which is the depth real networks use. Past it the
/// policy is an explicit drop with a counter, because a silent pass on stacked tags
/// is a filter bypass: the addresses and ports the pipeline would judge are not the
/// ones the stack will act on.
pub const MAX_VLAN_TAGS: u8 = 2;

/// A tag control field followed by the inner ethertype.
const VLAN_TAG_LEN: usize = 4;

pub struct L2 {
    pub l3_off: usize,
    pub ethertype: u16,
    pub vlan_tags: u8,
}

/// The `profiling` feature is what puts each parser in a subprogram of its own, so it
/// gets a JIT symbol a `perf` campaign can attribute cycles to. The object that ships
/// is built without it, because a call boundary is not free here: it costs a bpf-to-bpf
/// call, the spills around it, and above all every optimisation LLVM cannot make across
/// it — the parsed view stays a struct written to the stack instead of the handful of
/// registers it becomes when the boundaries are gone. Worth 30 instructions a packet on
/// the whole path. The same idiom is on the three other parsers and is not repeated
/// there; the stages keep their boundary and say why at the first of them.
#[cfg_attr(feature = "profiling", inline(never))]
pub fn parse(win: &Window) -> Result<L2, ParseError> {
    let mut ethertype = win.be16(12).ok_or(ParseError::Truncated)?;
    let mut off = ETH_HDR_LEN;
    let mut tags = 0u8;

    while tags < MAX_VLAN_TAGS {
        if !is_vlan(ethertype) {
            break;
        }
        let tag = win
            .header::<VLAN_TAG_LEN>(off)
            .ok_or(ParseError::Truncated)?;
        ethertype = tag.be16_at::<2>();
        off += VLAN_TAG_LEN;
        tags += 1;
    }

    if is_vlan(ethertype) {
        return Err(ParseError::DepthExceeded);
    }

    Ok(L2 {
        l3_off: off,
        ethertype,
        vlan_tags: tags,
    })
}

const fn is_vlan(ethertype: u16) -> bool {
    ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD
}
