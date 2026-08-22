//! Deployment profiles, and the memlock budget each one derives its map sizes from.
//!
//! The budget determines the size, not the reverse. A table dimensioned for the worst
//! case runs to gigabytes of kernel memory, which does not fit on a four-gigabyte VPS,
//! and the cost is invisible in the RSS of the agent while being entirely real.

use core::fmt;

/// Where the program is deployed. The three the specification names, and the trait the
/// specification asks for is this enum rather than a trait: there is nothing to
/// dispatch, only numbers to look up.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    Vps,
    Host,
    Gateway,
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Vps => "vps",
            Self::Host => "host",
            Self::Gateway => "gateway",
        };
        f.write_str(name)
    }
}

const MIB: u64 = 1024 * 1024;

impl ProfileKind {
    /// Kernel memory this profile is allowed to lock for maps.
    ///
    /// These are choices, not measurements, and the reasoning is the whole content of
    /// the number. A two-gigabyte VPS cannot spare more than a percent or so of its
    /// memory for kernel structures it cannot see in any process accounting, which
    /// puts it at tens of megabytes. A dedicated host has room for a real blocklist. A
    /// gateway is sized for somebody else traffic and is expected to be provisioned
    /// for it.
    pub const fn memlock_budget(self) -> u64 {
        match self {
            Self::Vps => 32 * MIB,
            Self::Host => 256 * MIB,
            Self::Gateway => 1024 * MIB,
        }
    }

    /// Room left in the unified list for entries the mitigation adds while running.
    /// A list sized exactly for the operator rules would have nowhere to put a
    /// blocked source, which is the entire point of the list.
    pub const fn default_mitigation_reserve(self) -> u32 {
        match self {
            Self::Vps => 16_384,
            Self::Host => 262_144,
            Self::Gateway => 1_048_576,
        }
    }
}

/// What one map entry costs in kernel memory.
///
/// **Not measured.** This is the arithmetic of the kernel structures, and it is a
/// parameter of the budget rather than a fact about a machine. An `LPM_TRIE` requires
/// `BPF_F_NO_PREALLOC` and allocates one `lpm_trie_node` per inserted prefix plus up
/// to one intermediate node per prefix; each node carries two child pointers, the
/// prefix length, a flag word, then the key data and the value inline.
///
/// The measurement that replaces it reads the `memlock` field of the loaded program
/// and `/proc/meminfo` before and after filling the map. Until then, a design that
/// does not fit under this estimate is refused, which is the safe direction.
#[derive(Clone, Copy, Debug)]
pub struct MemlockModel {
    pub list_bytes_per_entry: u64,
    pub counter_bytes_per_entry: u64,
}

impl MemlockModel {
    /// Two child pointers, a prefix length and a flag word make 24 bytes of node
    /// header; the 16-byte address and the 48-byte value bring it to 88, which the
    /// slab allocator rounds to 96. A trie holding n prefixes can need up to 2n-1
    /// nodes, so an entry is charged for two.
    pub const ESTIMATE: Self = Self {
        list_bytes_per_entry: 96 * 2,
        // A per-CPU array charges one aligned value per CPU. Sized for a large host
        // rather than for the machine in front of us, because the config is compiled
        // once and may be deployed anywhere.
        counter_bytes_per_entry: 8 * 128,
    };
}

/// Map sizes a configuration asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapSizes {
    pub unified_list_entries: u32,
    pub counter_entries: u32,
}

impl MapSizes {
    pub const fn memlock_bytes(&self, model: MemlockModel) -> u64 {
        self.unified_list_entries as u64 * model.list_bytes_per_entry
            + self.counter_entries as u64 * model.counter_bytes_per_entry
    }
}
