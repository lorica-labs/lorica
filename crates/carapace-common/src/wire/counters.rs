/// Index into the counter array.
///
/// Complete for this phase in one place on purpose: five stage tasks run in parallel
/// and would otherwise each edit this file. A stage adds no variant, it uses one.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CounterId {
    ParseTruncated = 0,
    ParseDepthExceeded,
    ParseUnknownEncap,

    SanityIpLength,
    SanityL4Length,
    SanityTcpFlags,
    SanityIpOptionsRefused,

    IcmpPathMtuPassed,
    IcmpEchoDropped,
    IcmpOtherDropped,

    LpmAllowExit,
    LpmDropHit,
    LpmScopeMiss,
    LpmExpired,

    FragmentFirstPassed,
    FragmentLaterDropped,
    FragmentLaterAllowed,
}

impl CounterId {
    pub const ALL: [CounterId; 17] = [
        Self::ParseTruncated,
        Self::ParseDepthExceeded,
        Self::ParseUnknownEncap,
        Self::SanityIpLength,
        Self::SanityL4Length,
        Self::SanityTcpFlags,
        Self::SanityIpOptionsRefused,
        Self::IcmpPathMtuPassed,
        Self::IcmpEchoDropped,
        Self::IcmpOtherDropped,
        Self::LpmAllowExit,
        Self::LpmDropHit,
        Self::LpmScopeMiss,
        Self::LpmExpired,
        Self::FragmentFirstPassed,
        Self::FragmentLaterDropped,
        Self::FragmentLaterAllowed,
    ];

    /// How many slots of the counter map the named counters occupy. Every slot above
    /// this one belongs to a single entry of the unified list, so an operator can see
    /// which allow-listed source is leaving the pipeline rather than only that some
    /// source did.
    pub const COUNT: u32 = Self::ALL.len() as u32;

    /// The name a test and the agent look a counter up by. One mapping, so a renamed
    /// variant cannot silently keep an old name in a test.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ParseTruncated => "parse_truncated",
            Self::ParseDepthExceeded => "parse_depth_exceeded",
            Self::ParseUnknownEncap => "parse_unknown_encap",
            Self::SanityIpLength => "sanity_ip_length",
            Self::SanityL4Length => "sanity_l4_length",
            Self::SanityTcpFlags => "sanity_tcp_flags",
            Self::SanityIpOptionsRefused => "sanity_ip_options_refused",
            Self::IcmpPathMtuPassed => "icmp_path_mtu_passed",
            Self::IcmpEchoDropped => "icmp_echo_dropped",
            Self::IcmpOtherDropped => "icmp_other_dropped",
            Self::LpmAllowExit => "lpm_allow_exit",
            Self::LpmDropHit => "lpm_drop_hit",
            Self::LpmScopeMiss => "lpm_scope_miss",
            Self::LpmExpired => "lpm_expired",
            Self::FragmentFirstPassed => "fragment_first_passed",
            Self::FragmentLaterDropped => "fragment_later_dropped",
            Self::FragmentLaterAllowed => "fragment_later_allowed",
        }
    }

    pub const fn index(self) -> u32 {
        self as u32
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let mut i = 0;
        while i < Self::ALL.len() {
            let id = Self::ALL[i];
            if str_eq(id.name(), name) {
                return Some(id);
            }
            i += 1;
        }
        None
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
