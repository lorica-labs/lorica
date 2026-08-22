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
}

/// What the program runs with when the operator has said nothing: refuse IP options,
/// pass ICMP, drop later fragments.
pub const DEFAULT_SETTINGS: u32 = 0;

/// The symbol the loader patches. Named here so the program and the loader cannot
/// disagree about it.
pub const SETTINGS_SYMBOL: &str = "SETTINGS";
