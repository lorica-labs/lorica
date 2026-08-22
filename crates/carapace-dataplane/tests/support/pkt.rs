//! Packet construction for the kernel tests.
//!
//! Every field a test cares about is settable and nothing is silently fixed up
//! except the two length fields, which have explicit overrides so a test can state
//! an inconsistent length on purpose.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    /// Neither IPv4 nor IPv6. Serialised as ARP, so the parser sees an
    /// encapsulation it does not judge.
    Unknown,
    V4,
    V6,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum L4Kind {
    None,
    Udp,
    Tcp,
    Icmp,
}

pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_DSTOPTS: u8 = 60;

/// `BPF_PROG_TEST_RUN` refuses an XDP input shorter than an Ethernet header, so a
/// truncation case cannot go below this. It is a limit of the tool, not of the
/// program.
pub const MIN_TEST_RUN_LEN: usize = 14;

pub struct PktBuilder {
    vlans: Vec<(u16, u16)>,
    family: Family,
    src: [u8; 16],
    dst: [u8; 16],
    ipv4_options: Vec<u8>,
    ext_headers: Vec<(u8, u8)>,
    frag: Option<(u16, bool)>,
    l4: L4Kind,
    sport: u16,
    dport: u16,
    tcp_flags: u8,
    icmp: (u8, u8),
    payload_len: usize,
    ip_total_len_override: Option<u16>,
    udp_len_override: Option<u16>,
    truncate_at: Option<usize>,
}

impl PktBuilder {
    pub fn eth() -> Self {
        Self {
            vlans: Vec::new(),
            family: Family::Unknown,
            src: mapped([10, 90, 1, 2]),
            dst: mapped([10, 90, 1, 1]),
            ipv4_options: Vec::new(),
            ext_headers: Vec::new(),
            frag: None,
            l4: L4Kind::None,
            sport: 12_345,
            dport: 30_120,
            tcp_flags: 0,
            icmp: (0, 0),
            payload_len: 0,
            ip_total_len_override: None,
            udp_len_override: None,
            truncate_at: None,
        }
    }

    pub fn vlan(mut self, vid: u16) -> Self {
        self.vlans.push((ETH_P_8021Q, vid));
        self
    }

    /// Outer tag first, as it appears on the wire.
    pub fn qinq(mut self, outer: u16, inner: u16) -> Self {
        self.vlans.push((ETH_P_8021AD, outer));
        self.vlans.push((ETH_P_8021Q, inner));
        self
    }

    pub fn vlan_tag(mut self, tpid: u16, vid: u16) -> Self {
        self.vlans.push((tpid, vid));
        self
    }

    pub fn ipv4(mut self) -> Self {
        self.family = Family::V4;
        self
    }

    /// Raw option bytes, verbatim. The length has to be a multiple of four because
    /// IHL counts words, and padding them here would let a malformed option set look
    /// terminated.
    pub fn ipv4_options(mut self, opts: &[u8]) -> Self {
        assert_eq!(
            opts.len() % 4,
            0,
            "IHL counts 4-byte words, so an option blob has to be a multiple of four"
        );
        self.family = Family::V4;
        self.ipv4_options = opts.to_vec();
        self
    }

    pub fn ipv6(mut self) -> Self {
        self.family = Family::V6;
        self.src = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        self.dst = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        self
    }

    /// Appends one IPv6 extension header of type `next` whose `hdr_ext_len` field is
    /// `len`, so it occupies `(len + 1) * 8` bytes. `next` is what the preceding
    /// header points at; the chain is terminated by the L4 protocol.
    pub fn ext_header(mut self, next: u8, len: u8) -> Self {
        self.ext_headers.push((next, len));
        self
    }

    /// An offset above zero makes this a later fragment, which carries no L4 header
    /// at all. On IPv6 this becomes a fragment extension header.
    pub fn frag(mut self, offset: u16, more: bool) -> Self {
        self.frag = Some((offset, more));
        self
    }

    pub fn udp(mut self, sport: u16, dport: u16) -> Self {
        self.l4 = L4Kind::Udp;
        self.sport = sport;
        self.dport = dport;
        self
    }

    pub fn tcp(mut self, sport: u16, dport: u16) -> Self {
        self.l4 = L4Kind::Tcp;
        self.sport = sport;
        self.dport = dport;
        self
    }

    pub fn tcp_flags(mut self, flags: u8) -> Self {
        self.l4 = L4Kind::Tcp;
        self.tcp_flags = flags;
        self
    }

    /// Fragmentation Needed on IPv4, Packet Too Big on IPv6. The message that must
    /// cross whatever the configuration says.
    pub fn icmp_ptb(mut self) -> Self {
        self.l4 = L4Kind::Icmp;
        self.icmp = match self.family {
            Family::V6 => (2, 0),
            _ => (3, 4),
        };
        self
    }

    pub fn icmp(mut self, ty: u8, code: u8) -> Self {
        self.l4 = L4Kind::Icmp;
        self.icmp = (ty, code);
        self
    }

    pub fn src_v4(mut self, addr: [u8; 4]) -> Self {
        self.src = mapped(addr);
        self
    }

    pub fn dst_v4(mut self, addr: [u8; 4]) -> Self {
        self.dst = mapped(addr);
        self
    }

    pub fn src_v6(mut self, addr: [u8; 16]) -> Self {
        self.src = addr;
        self
    }

    pub fn payload(mut self, len: usize) -> Self {
        self.payload_len = len;
        self
    }

    /// States a total length the packet does not have. Sanity is about the
    /// disagreement between what a header claims and what arrived.
    pub fn ip_total_len(mut self, len: u16) -> Self {
        self.ip_total_len_override = Some(len);
        self
    }

    pub fn udp_len(mut self, len: u16) -> Self {
        self.udp_len_override = Some(len);
        self
    }

    pub fn truncate(mut self, at: usize) -> Self {
        self.truncate_at = Some(at);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        out.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        for (tpid, vid) in &self.vlans {
            out.extend_from_slice(&tpid.to_be_bytes());
            out.extend_from_slice(&vid.to_be_bytes());
        }
        out.extend_from_slice(&self.ethertype().to_be_bytes());

        let l3_off = out.len();
        match self.family {
            Family::Unknown => out.extend_from_slice(&[0u8; 28]),
            Family::V4 => self.write_ipv4(&mut out),
            Family::V6 => self.write_ipv6(&mut out),
        }
        self.write_l4(&mut out);
        out.resize(out.len() + self.payload_len, 0x41);
        self.fix_lengths(&mut out, l3_off);

        if let Some(at) = self.truncate_at {
            assert!(
                at >= MIN_TEST_RUN_LEN,
                "BPF_PROG_TEST_RUN refuses an XDP input below {MIN_TEST_RUN_LEN} bytes"
            );
            out.truncate(at);
        }
        out
    }

    const fn ethertype(&self) -> u16 {
        match self.family {
            Family::Unknown => 0x0806,
            Family::V4 => 0x0800,
            Family::V6 => 0x86dd,
        }
    }

    /// The protocol the L4 header, if any, is written as.
    const fn l4_proto(&self) -> u8 {
        match self.l4 {
            L4Kind::None => 253,
            L4Kind::Udp => IPPROTO_UDP,
            L4Kind::Tcp => IPPROTO_TCP,
            L4Kind::Icmp => match self.family {
                Family::V6 => IPPROTO_ICMPV6,
                _ => IPPROTO_ICMP,
            },
        }
    }

    /// A later fragment has no L4 header. Writing one would make the test exercise a
    /// packet the network cannot produce.
    fn carries_l4(&self) -> bool {
        !matches!(self.frag, Some((offset, _)) if offset > 0)
    }

    fn write_ipv4(&self, out: &mut Vec<u8>) {
        let ihl = 5 + (self.ipv4_options.len() / 4) as u8;
        out.push(0x40 | ihl);
        out.push(0);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0xbeefu16.to_be_bytes());
        let flags_frag = match self.frag {
            Some((offset, more)) => (if more { 0x2000 } else { 0 }) | (offset & 0x1fff),
            None => 0,
        };
        out.extend_from_slice(&flags_frag.to_be_bytes());
        out.push(64);
        out.push(self.l4_proto());
        // Left at zero: XDP runs before any checksum validation, so a correct one
        // would prove nothing and a wrong one changes nothing.
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.src[12..16]);
        out.extend_from_slice(&self.dst[12..16]);
        out.extend_from_slice(&self.ipv4_options);
    }

    fn write_ipv6(&self, out: &mut Vec<u8>) {
        let mut chain: Vec<(u8, u8)> = self.ext_headers.clone();
        if self.frag.is_some() {
            chain.push((IPPROTO_FRAGMENT, 0));
        }

        out.extend_from_slice(&[0x60, 0, 0, 0]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(chain.first().map_or_else(|| self.l4_proto(), |c| c.0));
        out.push(64);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);

        for (i, (kind, ext_len)) in chain.iter().enumerate() {
            let next = chain.get(i + 1).map_or_else(|| self.l4_proto(), |c| c.0);
            if *kind == IPPROTO_FRAGMENT {
                let (offset, more) = self.frag.unwrap();
                let field = (offset << 3) | u16::from(more);
                out.push(next);
                out.push(0);
                out.extend_from_slice(&field.to_be_bytes());
                out.extend_from_slice(&0xdeadbeefu32.to_be_bytes());
            } else {
                let total = (*ext_len as usize + 1) * 8;
                out.push(next);
                out.push(*ext_len);
                out.resize(out.len() + total - 2, 0);
            }
        }
    }

    fn write_l4(&self, out: &mut Vec<u8>) {
        if !self.carries_l4() {
            return;
        }
        match self.l4 {
            L4Kind::None => {}
            L4Kind::Udp => {
                out.extend_from_slice(&self.sport.to_be_bytes());
                out.extend_from_slice(&self.dport.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            L4Kind::Tcp => {
                out.extend_from_slice(&self.sport.to_be_bytes());
                out.extend_from_slice(&self.dport.to_be_bytes());
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
                out.push(0x50);
                out.push(self.tcp_flags);
                out.extend_from_slice(&64_240u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            L4Kind::Icmp => {
                out.push(self.icmp.0);
                out.push(self.icmp.1);
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
            }
        }
    }

    fn fix_lengths(&self, out: &mut Vec<u8>, l3_off: usize) {
        match self.family {
            Family::Unknown => {}
            Family::V4 => {
                let total = self
                    .ip_total_len_override
                    .unwrap_or((out.len() - l3_off) as u16);
                out[l3_off + 2..l3_off + 4].copy_from_slice(&total.to_be_bytes());
            }
            Family::V6 => {
                let payload = (out.len() - l3_off - 40) as u16;
                let stated = self
                    .ip_total_len_override
                    .map_or(payload, |total| total.saturating_sub(40));
                out[l3_off + 4..l3_off + 6].copy_from_slice(&stated.to_be_bytes());
            }
        }

        if self.l4 == L4Kind::Udp && self.carries_l4() {
            let l4_off = self.l4_offset(out, l3_off);
            let stated = self.udp_len_override.unwrap_or((out.len() - l4_off) as u16);
            out[l4_off + 4..l4_off + 6].copy_from_slice(&stated.to_be_bytes());
        }
    }

    fn l4_offset(&self, out: &[u8], l3_off: usize) -> usize {
        match self.family {
            Family::V4 => l3_off + ((out[l3_off] & 0x0f) as usize) * 4,
            Family::V6 => {
                let mut off = l3_off + 40;
                for (kind, ext_len) in &self.ext_headers {
                    let _ = kind;
                    off += (*ext_len as usize + 1) * 8;
                }
                if self.frag.is_some() {
                    off += 8;
                }
                off
            }
            Family::Unknown => l3_off,
        }
    }
}

const fn mapped(addr: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr[0], addr[1], addr[2], addr[3],
    ]
}
