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
/// **Measured**, on Ubuntu 24.04 GA 6.8.0-138 with four possible processors, by filling
/// a million entries and reading both the kernel's own accounting and the slab. The
/// figures and the method are in `agent:docs/mesures/06-map-batch.md`; what matters here
/// is which of the two numbers each field carries, because they differ by a factor of two
/// and only one of them is what a small machine actually feels.
#[derive(Clone, Copy, Debug)]
pub struct MemlockModel {
    pub list_bytes_per_entry: u64,
    pub counter_bytes_per_entry: u64,
}

/// The processor count the model is stated for. The counter map is per-CPU, so its cost
/// is linear in the number of possible processors and a model that did not name one would
/// be meaningless. The loader recomputes it from the machine it is on.
pub const REFERENCE_CPUS: u64 = 8;

impl MemlockModel {
    /// **The list charges the slab, not the kernel's own figure.** Filling a million
    /// prefixes moved `SUnreclaim` by 203 112 KiB, which is 208 bytes an entry, while the
    /// map reported 104 bytes an entry through `memlock`. The kernel counts the nodes it
    /// allocated at their nominal size; the slab rounds every one of them up and the trie
    /// also allocates intermediate nodes that `memlock` never reports. The ratio came out
    /// at 1,999 — near enough to two that charging twice the reported figure is the same
    /// number, which is also what the earlier arithmetic guessed and for the right reason.
    ///
    /// The previous estimate was 192 bytes. It undercharged by 8 %, which is the
    /// dangerous direction: a configuration that fits under a model and not under the
    /// slab is refused by the machine and not by the compiler.
    ///
    /// **The counter map charges `8 × cpus + 8`.** A per-CPU array holds one
    /// eight-byte-aligned value per possible processor, and one pointer per entry in the
    /// `pptrs` table that finds them. Measured at 40 000 000 bytes for a million entries
    /// on four processors — 40 an entry against the 32 the per-processor values alone
    /// account for, and the eight left over is exactly the pointer.
    pub const fn for_cpus(cpus: u64) -> Self {
        Self {
            list_bytes_per_entry: 208,
            counter_bytes_per_entry: 8 * cpus + 8,
        }
    }

    /// The model at the reference processor count. Named `MEASURED` and no longer
    /// `ESTIMATE`, because it is one.
    pub const MEASURED: Self = Self::for_cpus(REFERENCE_CPUS);
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
