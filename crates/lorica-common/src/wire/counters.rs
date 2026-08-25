/// Index into the counter array.
///
/// Complete for the phase in one place on purpose: several stage tasks run in parallel
/// and would otherwise each edit this file. A stage adds no variant, it uses one.
///
/// Adding a named counter shifts the absolute index of every per-entry slot of the
/// unified list, since those live above the named ones. So `counter_idx` is recompiled by
/// the policy compiler and never patched by hand, and `MapSizes.counter_entries` moves
/// with it: `tests/memlock.rs` and `tests/memlock_real.rs` are there to refuse a drift.
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
    IcmpNeighborPassed,
    IcmpEchoDropped,
    IcmpOtherDropped,

    LpmAllowExit,
    LpmDropHit,
    LpmScopeMiss,
    LpmExpired,

    FragmentFirstPassed,
    FragmentLaterDropped,
    FragmentLaterAllowed,

    // Stage 5. The return codes of `bpf_fib_lookup` are counted apart because the policy
    // differs between them: no route at all is what a convergence window looks like, and
    // a route out of the wrong interface is what a spoofed source looks like.
    UrpfNoRoute,
    UrpfWrongInterface,
    UrpfLookupUnsupported,

    // Stage 6, one per vector of the catalog. A vector without its own counter cannot be
    // told from its neighbour when an operator asks which signature fired.
    SignatureAmpDns,
    SignatureAmpNtp,
    SignatureAmpSsdp,
    SignatureAmpMemcached,
    SignatureAmpA2s,
    SignatureAmpRaknet,
    SignatureLoopyPortPair,
    SignatureFragAbuse,
    SignatureImpossibleTcpFlags,
    SignatureLengthMismatch,

    // Stage 7. Only the exceptions are counted. Counting every accepted packet would put
    // a map lookup on the steady-state path, which is the one the per-packet budget is
    // stated about.
    BucketOverBudget,
    BucketMarked,

    // Bogons and martians. They are entries of the unified list rather than a stage, so
    // the policy compiler points all of them at this one slot: the operator wants to know
    // that a bogon was refused, not which of two hundred reserved prefixes it was.
    BogonRefused,
}

impl CounterId {
    /// Complete for this phase, appended rather than interleaved: the existing indices do
    /// not move, so a stored `counter_idx` of a list entry keeps meaning what it meant.
    /// The slots above the named ones do move, since there are more named ones now — see
    /// [`Self::COUNT`].
    pub const ALL: [CounterId; 34] = [
        Self::ParseTruncated,
        Self::ParseDepthExceeded,
        Self::ParseUnknownEncap,
        Self::SanityIpLength,
        Self::SanityL4Length,
        Self::SanityTcpFlags,
        Self::SanityIpOptionsRefused,
        Self::IcmpPathMtuPassed,
        Self::IcmpNeighborPassed,
        Self::IcmpEchoDropped,
        Self::IcmpOtherDropped,
        Self::LpmAllowExit,
        Self::LpmDropHit,
        Self::LpmScopeMiss,
        Self::LpmExpired,
        Self::FragmentFirstPassed,
        Self::FragmentLaterDropped,
        Self::FragmentLaterAllowed,
        Self::UrpfNoRoute,
        Self::UrpfWrongInterface,
        Self::UrpfLookupUnsupported,
        Self::SignatureAmpDns,
        Self::SignatureAmpNtp,
        Self::SignatureAmpSsdp,
        Self::SignatureAmpMemcached,
        Self::SignatureAmpA2s,
        Self::SignatureAmpRaknet,
        Self::SignatureLoopyPortPair,
        Self::SignatureFragAbuse,
        Self::SignatureImpossibleTcpFlags,
        Self::SignatureLengthMismatch,
        Self::BucketOverBudget,
        Self::BucketMarked,
        Self::BogonRefused,
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
            Self::IcmpNeighborPassed => "icmp_neighbor_passed",
            Self::IcmpEchoDropped => "icmp_echo_dropped",
            Self::IcmpOtherDropped => "icmp_other_dropped",
            Self::LpmAllowExit => "lpm_allow_exit",
            Self::LpmDropHit => "lpm_drop_hit",
            Self::LpmScopeMiss => "lpm_scope_miss",
            Self::LpmExpired => "lpm_expired",
            Self::FragmentFirstPassed => "fragment_first_passed",
            Self::FragmentLaterDropped => "fragment_later_dropped",
            Self::FragmentLaterAllowed => "fragment_later_allowed",
            Self::UrpfNoRoute => "urpf_no_route",
            Self::UrpfWrongInterface => "urpf_wrong_interface",
            Self::UrpfLookupUnsupported => "urpf_lookup_unsupported",
            Self::SignatureAmpDns => "signature_amp_dns",
            Self::SignatureAmpNtp => "signature_amp_ntp",
            Self::SignatureAmpSsdp => "signature_amp_ssdp",
            Self::SignatureAmpMemcached => "signature_amp_memcached",
            Self::SignatureAmpA2s => "signature_amp_a2s",
            Self::SignatureAmpRaknet => "signature_amp_raknet",
            Self::SignatureLoopyPortPair => "signature_loopy_port_pair",
            Self::SignatureFragAbuse => "signature_frag_abuse",
            Self::SignatureImpossibleTcpFlags => "signature_impossible_tcp_flags",
            Self::SignatureLengthMismatch => "signature_length_mismatch",
            Self::BucketOverBudget => "bucket_over_budget",
            Self::BucketMarked => "bucket_marked",
            Self::BogonRefused => "bogon_refused",
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
