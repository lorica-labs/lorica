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
