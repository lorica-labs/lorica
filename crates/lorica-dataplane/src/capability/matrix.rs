//! One row per capability: what it buys, and the path that reaches the same response tier
//! without it.
//!
//! Releases and reference paths are transcribed from the capability table of the design
//! spec. Nothing here is inferred from behaviour, because a floor guessed one release too
//! low announces a capability the kernel does not have.
//!
//! **Two requirements are not in the table below, because they have no fallback.** Every row
//! here is an optional capability: absent, the program takes another path to the same response
//! tier. These two are not optional — an older kernel does not fall back, it refuses. They are
//! recorded here anyway because this is the file someone reads to find out which kernel release
//! buys what, and both sit well under this project's 6.8 floor, which is exactly why they are
//! affordable and exactly why they would otherwise go unwritten.
//!
//! - The object is compiled for BPF ISA v3 (`-C target-cpu=v3` in the eBPF crate's cargo
//!   config), so it needs a kernel with JMP32: **5.1**. An older kernel refuses the program at
//!   load.
//! - The counter map is created with `BPF_F_MMAPABLE`, which the kernel accepts on
//!   `BPF_MAP_TYPE_ARRAY` from **5.5** (commit `fc9702273e2e`). An older kernel refuses the
//!   *map*, so the agent never starts. The read path does have a fallback —
//!   `BPF_MAP_LOOKUP_BATCH` at about a hundred times the cost, taken when `mmap` itself is
//!   refused — but the map creation does not, which is why this belongs here and not in a row.

use super::Capability;

pub struct Entry {
    pub cap: Capability,
    /// Also the metric label, so it cannot change shape once published.
    pub name: &'static str,
    /// Release that carries the capability upstream, as `(major, minor)`.
    pub since: (u32, u32),
    /// A kernel symbol the capability cannot exist without. Preferred over `since`: it
    /// survives a distribution backport, and it catches a build where the config option is
    /// off although the release is recent enough.
    ///
    /// `None` where no symbol observed on 7.0 tells the capability apart from what the
    /// kernel already had — those rows are decided by `since` alone, and miss a backport.
    pub symbol: Option<&'static str>,
    /// The path taken without the capability. It reaches the SAME response tier: an
    /// optional capability buys cost or jitter, never a different verdict.
    pub fallback: &'static str,
}

/// Indexed by `Capability::row`, whose match stops compiling when a variant is added.
pub const ROWS: [Entry; 7] = [
    Entry {
        cap: Capability::CpumapGro,
        name: "cpumap_gro",
        since: (6, 15),
        symbol: None,
        fallback: "no cpumap at all: scrubbing stays on the ingress core. Before 6.15 cpumap \
                   breaks TCP aggregation, which costs more than the jitter it isolates",
    },
    Entry {
        cap: Capability::BpfQdisc,
        name: "bpf_qdisc",
        since: (6, 16),
        // net/sched/bpf_qdisc.c registers this struct_ops descriptor, and only under
        // CONFIG_NET_SCH_BPF. The release number alone would announce the capability on a
        // kernel built without the option.
        symbol: Some("bpf_Qdisc_ops"),
        fallback: "tier 1 stays an observed no-op: marked in metrics, never enforced, and \
                   the climb to tier 2 keeps the same temporal criteria. Never a direct \
                   jump to tier 2, which would be a different verdict per kernel",
    },
    Entry {
        cap: Capability::XdpPullData,
        name: "bpf_xdp_pull_data",
        since: (6, 18),
        symbol: Some("bpf_xdp_pull_data"),
        fallback: "the bounded parsing depth is one policy on every kernel; without the \
                   kfunc that depth costs more to reach, it is not reduced",
    },
    Entry {
        cap: Capability::MultiByteMeta,
        name: "multi_byte_meta",
        since: (6, 19),
        symbol: None,
        fallback: "the verdict stays in the dataplane instead of riding to the stack",
    },
    Entry {
        cap: Capability::RehashFlows,
        name: "rehash_flows",
        since: (6, 19),
        symbol: None,
        fallback: "manual RSS tuning against an attack that saturates one RX queue",
    },
    Entry {
        cap: Capability::BpfArena,
        name: "bpf_arena",
        since: (6, 9),
        symbol: Some("arena_map_ops"),
        fallback: "the hand-sharded mmappable array the counter map already is: a flat ARRAY \
                   striped by processor, mapped read-only, with the batch read behind it. \
                   Agent-side cost either way, so the tier reached is untouched",
    },
    Entry {
        cap: Capability::QueueLeasing,
        name: "queue_leasing",
        since: (7, 1),
        symbol: None,
        fallback: "the dataplane runs as a DaemonSet on the host rather than in the \
                   container",
    },
];
