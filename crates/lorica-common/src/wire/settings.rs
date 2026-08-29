//! Policy bits the operator sets, read by the stages that have a knob.
//!
//! One word, fixed at load time. Reading a map instead would cost a helper call on
//! every packet that reaches a stage with a knob, and the whole per-packet budget is
//! three lookups and one helper. This phase has no policy that changes while the
//! program is attached; what does change with the tiers is per-tier state, not these.
//!
//! Complete for this phase in one place, like the counters: three stage tasks would
//! otherwise each add a bit to the same word.
pub mod setting {
    /// Stage 1. IP options are refused by default. Parsing them is not the question:
    /// the header length locates the transport header either way. Options carry the
    /// source-routing family of attacks, and an operator who needs them says so.
    pub const ACCEPT_IP_OPTIONS: u32 = 1 << 0;

    /// Stage 2. Echo request and reply follow the configuration, unlike the path MTU
    /// messages, which cross unconditionally.
    pub const DROP_ICMP_ECHO: u32 = 1 << 1;

    /// Stage 2. Every other ICMP type.
    pub const DROP_ICMP_OTHER: u32 = 1 << 2;

    /// Stage 4. Later fragments carry no port, so they can never match a scope and are
    /// dropped by default. An operator running fragmented administration traffic
    /// (IPsec, IKE, large VPN packets) turns this on and accepts the degraded
    /// `(source, protocol)` key that comes with it.
    pub const ALLOW_LATER_FRAGMENTS: u32 = 1 << 3;

    /// Stage 5. Set by the loader and not by the operator: the uRPF criterion is binary
    /// and the loader evaluates it against the routing table of the ingress interface. On
    /// a host with a default route the strict check discriminates nothing, so the stage
    /// stays off and this bit stays clear.
    ///
    /// A load-time global cannot change while the program is attached, so a criterion that
    /// flips — a DHCP lease that moves the gateway, a failover — is a reload. That is the
    /// production path anyway, since the design is detached by default and attached on
    /// detection, and the hysteresis of the netlink watcher exists so a flapping route does
    /// not become a flapping reload.
    pub const URPF_ENFORCE: u32 = 1 << 4;

    /// Stage 6. Off by default: the default mode of the whole product is observation, so a
    /// signature counts its vector and lets the packet through until an operator arms it.
    pub const ENFORCE_SIGNATURES: u32 = 1 << 5;

    /// Stage 7. Off by default, for the same reason as the signatures.
    pub const ENFORCE_BUCKETS: u32 = 1 << 6;

    /// Stage 7. Tag the excess and let it reach the stack rather than dropping it.
    ///
    /// Set by the loader only when the metadata capability answers yes, because marking in
    /// XDP means writing into `xdp_md` metadata for the stack to read. On the kernel floor
    /// of the project it answers no, the bit stays clear, and the verdict stays in the data
    /// plane. Both paths reach the same response tier — the excess is not served normally —
    /// which is what makes an optional capability legitimate.
    pub const MARK_OVER_BUDGET: u32 = 1 << 7;
}

/// What the program runs with when the operator has said nothing: refuse IP options,
/// pass ICMP, drop later fragments.
pub const DEFAULT_SETTINGS: u32 = 0;

/// The bits an operator may set, and the name each is set by.
///
/// Six of the eight, because two are not the operator's to choose:
/// [`setting::URPF_ENFORCE`] is a criterion the loader evaluates against the routing table
/// of the ingress interface, and [`setting::MARK_OVER_BUDGET`] is a capability the loader
/// asks the kernel about. A name for either would let an operator claim a verdict the
/// machine cannot deliver, which is worse than not offering it.
///
/// The table sits beside the bits so that adding one and forgetting to name it is a visible
/// omission in a diff rather than a flag that silently does nothing. It is the only place
/// the names exist: the parser and the usage line both read it.
pub const OPERATOR_SETTINGS: [(&str, u32); 6] = [
    ("accept-ip-options", setting::ACCEPT_IP_OPTIONS),
    ("drop-icmp-echo", setting::DROP_ICMP_ECHO),
    ("drop-icmp-other", setting::DROP_ICMP_OTHER),
    ("allow-later-fragments", setting::ALLOW_LATER_FRAGMENTS),
    ("enforce-signatures", setting::ENFORCE_SIGNATURES),
    ("enforce-buckets", setting::ENFORCE_BUCKETS),
];

/// The policy word a comma-separated list of names spells, or the first name that is not one.
///
/// The parsing lives beside the table rather than in the agent because the two cannot be
/// checked against each other from anywhere else: a binary crate has no integration test that
/// can reach into it. The error is the offending name and not a message — this crate has no
/// allocator to build one with, and the caller has the list of what was expected right here.
///
/// Empty fragments are skipped, so a trailing comma is not an error. An unknown one is,
/// rather than a warning: the word decides whether a stage drops traffic, and a typo that
/// silently leaves a stage observing is the failure an operator finds during the attack it
/// was meant to stop.
pub fn settings_word(list: &str) -> Result<u32, &str> {
    let mut word = DEFAULT_SETTINGS;
    for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match OPERATOR_SETTINGS.iter().find(|(known, _)| *known == name) {
            Some((_, bit)) => word |= bit,
            None => return Err(name),
        }
    }
    Ok(word)
}

/// Where the measurement build reads the pipeline cutoff from, in the same word.
///
/// The upper half of the policy word rather than a second global, because the loader
/// already patches this one and a measurement is not worth a second patching path. The
/// stages that read the cutoff exist only in a build with the `stage-cutoff` feature,
/// and a production load carries zero here, which cuts nothing.
pub const STAGE_CUTOFF_SHIFT: u32 = 16;

/// The cutoff value that runs the whole pipeline. It is what a production load carries,
/// so forgetting to set one measures the program and not a truncation of it.
pub const NO_CUTOFF: u32 = 0;

/// The symbol the loader patches. Named here so the program and the loader cannot
/// disagree about it.
pub const SETTINGS_SYMBOL: &str = "SETTINGS";

/// The two halves of the 128-bit key the bucket index is hashed with, drawn at load and
/// never persisted.
///
/// Two `u64` globals rather than one struct because `u64` is unambiguously `aya::Pod`,
/// and a struct patched through `override_global` would need a layout both sides agree
/// on for no gain. Same mechanism as [`SETTINGS_SYMBOL`], same reason: the alternative is
/// a map read, and a map read is a helper call on the fast path.
pub const BUCKET_KEY_SYMBOLS: [&str; 2] = ["BUCKET_KEY0", "BUCKET_KEY1"];

/// The two budgets stage 7 charges against, as `(rate, burst)` symbol pairs: normal
/// first, then the one a signature match routes a packet to.
///
/// Load-time globals and not a map for the same reason as the policy word. This phase
/// applies budgets that come from the configuration and never varies them, so nothing
/// has to change while the program is attached; what stage 6 chooses is which of the two
/// applies.
pub const BUCKET_RATE_SYMBOLS: [[&str; 2]; 2] = [
    ["BUCKET_NORMAL_RATE", "BUCKET_NORMAL_BURST"],
    ["BUCKET_SUSPECT_RATE", "BUCKET_SUSPECT_BURST"],
];

/// Dead words read between the load and the store of a bucket, so the leak of the
/// lock-free bank can be measured as a function of the width of its read-modify-write
/// window instead of at the one width the program happens to have.
///
/// Zero in every load that is not a measurement, and zero here is not a short loop but no
/// loop at all: `.rodata` is constant to the verifier, so the body is removed before the
/// program is JITed — the same mechanism as [`SIGNATURE_VECTORS_SYMBOL`], and the same
/// evidence, a JITed size that does not move. A load-time global and not a cargo feature
/// for the reason this project has already paid for once: a feature would mean the object
/// the campaign measures is not the object that ships.
pub const BUCKET_STALL_SYMBOL: &str = "BUCKET_STALL";

/// One bit per vector of the signature catalogue, in catalogue order, patched by the
/// loader like the policy word.
///
/// Not a bit of [`SETTINGS_SYMBOL`]: the low byte of that word is spoken for and the upper
/// half is the measurement cutoff. Its own global also means the loader decides the
/// catalogue and the policy separately, which is what they are.
///
/// The reason this is a load-time global rather than a compiled-in constant is the
/// verifier: `.rodata` is read-only and constant to it, so it propagates the mask and
/// physically removes the branch of every vector the configuration left out. A
/// configuration that keeps two vectors carries two comparisons and not ten.
pub const SIGNATURE_VECTORS_SYMBOL: &str = "SIGNATURE_VECTORS";

/// The whole catalogue, ten vectors. What a loader patches when the operator named none:
/// observation of everything is what a configuration that says nothing asks for.
///
/// The program's own initialiser is zero, for the same reason the bucket budgets carry the
/// unconfigured one — a load that patched nothing enforces nothing — and
/// `signature_compile` asserts this mask is exactly as wide as the catalogue.
pub const SIGNATURE_VECTORS_ALL: u32 = (1 << 10) - 1;
