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

/// The symbol the loader patches with the stripe width, in slots.
///
/// The counter map is one flat `ARRAY` striped by processor rather than a `PERCPU_ARRAY`,
/// because the kernel refuses `BPF_F_MMAPABLE` on a per-CPU map and the agent reading the
/// counters through a mapping instead of through `BPF_MAP_LOOKUP_BATCH` is what takes the
/// sweep from milliseconds to microseconds. A striped flat array needs the stripe width in
/// the program, and the width is a load-time number: the slot count comes from the
/// deployment profile, which derives it from a memlock budget.
///
/// So it is a patched `.rodata` word, on the same mechanism as
/// [`SETTINGS_SYMBOL`](super::SETTINGS_SYMBOL), and the loader must set it and the map size
/// together — [`CounterLayout`] is what makes that one decision instead of two.
pub const COUNTER_STRIPE_SYMBOL: &str = "COUNTER_STRIPE";

/// Slots a stripe is rounded up to, so a stripe boundary never falls inside a cache line.
///
/// Eight `u64` is sixty-four bytes. Without it the last slots of one processor's stripe and
/// the first of the next share a line, and two processors counting different things would
/// invalidate each other's line on every packet — which is the exact cost a per-CPU map
/// exists to avoid, reintroduced by the layout that replaced it. The waste is at most seven
/// slots per processor.
pub const COUNTER_STRIPE_SLOTS: u32 = 8;

/// Processors the counter map is allowed to be striped for.
///
/// A dimensioning ceiling and not a limit the program enforces: the map is created for the
/// machine's own `num_possible_cpus`, and this is the number above which that stops being a
/// size anybody budgeted for. At the ceiling and the largest profile — a gateway asking for
/// 2²⁰ counter slots — the map is 512 GiB, so a machine near it needs a profile and not a
/// bigger constant. The loader refuses past it rather than creating a map the kernel would
/// refuse for less legible reasons.
///
/// 512 is what Linux ships as `CONFIG_NR_CPUS` on x86-64 defconfig for the distributions
/// this project targets, so a machine above it is one whose kernel was built for it.
pub const MAX_CPUS: u32 = 512;

/// How the counter map is laid out, and the one place the two numbers that have to agree
/// are computed.
///
/// **CPU-major**: `index = cpu * stripe + slot`. The other order — slot-major, one
/// processor's value next to another's for the same slot — puts every processor's counters
/// for one slot inside one cache line, so a bump on any processor invalidates that line
/// everywhere. CPU-major gives each processor a contiguous region it alone writes, which is
/// the property the per-CPU map provided and the only reason the increment can stay
/// non-atomic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CounterLayout {
    /// Counter slots the agent reads: the named counters, then one per entry of the list.
    pub slots: u32,
    /// Slots between the start of one processor's stripe and the next, rounded to
    /// [`COUNTER_STRIPE_SLOTS`].
    pub stripe: u32,
    /// Processors the map is striped for, which is `num_possible_cpus` and not the online
    /// count: `bpf_get_smp_processor_id` can return any of them.
    pub cpus: u32,
}

impl CounterLayout {
    /// The layout for `slots` counter slots on a machine with `cpus` possible processors.
    ///
    /// `None` when the machine is past [`MAX_CPUS`], which is the one case where the answer
    /// is a refusal rather than a number.
    pub const fn new(slots: u32, cpus: u32) -> Option<Self> {
        if cpus == 0 || cpus > MAX_CPUS {
            return None;
        }
        let stripe = slots.next_multiple_of(COUNTER_STRIPE_SLOTS);
        // A map the kernel cannot create is better refused here, where the caller can say
        // which profile asked for it.
        if stripe.checked_mul(cpus).is_none() {
            return None;
        }
        Some(Self {
            slots,
            stripe,
            cpus,
        })
    }

    /// Entries the map is created with. This is what goes to `map_max_entries`, and it is
    /// `stripe × cpus` and never `slots`.
    pub const fn entries(&self) -> u32 {
        self.stripe * self.cpus
    }

    /// Bytes the mapping covers, before the kernel rounds it up to a page.
    pub const fn bytes(&self) -> u64 {
        self.entries() as u64 * 8
    }

    /// The flat index one processor writes one slot at. The program computes this same
    /// expression from the patched stripe; this is the userspace mirror, and the test that
    /// reads a slot back is what keeps the two the same.
    pub const fn index(&self, cpu: u32, slot: u32) -> u32 {
        cpu * self.stripe + slot
    }
}
