//! The memlock model, against the kernel that has to honour it.
//!
//! Kernel memory locked by maps is the dominant cost of a deployment and it is invisible
//! in the RSS of every process, so the budget is computed from a model and the model is
//! worth exactly what a machine says about it. This test is that comparison.
//!
//! **The direction of the error is the whole point.** A model that overcharges refuses a
//! configuration that would have fitted, which an operator sees immediately and can argue
//! with. A model that undercharges lets a configuration through and the machine refuses
//! it later, or worse accepts it and runs out of kernel memory under attack. So the
//! assertion is one-sided: the model may be generous, never optimistic.

#![cfg(feature = "kernel-tests")]

mod support;

use aya::{Ebpf, EbpfLoader, util::nr_cpus};
use carapace_common::{Action, CounterId, LpmKey, LpmValue};
use carapace_dataplane::maps::{self, lpm};
use carapace_policy::{MemlockModel, ProfileKind};
use support::run::object_path;

/// Enough entries for the per-entry cost to dominate the fixed cost of the map, and few
/// enough to fill in well under a second at the 855 ns an entry measured on the target.
const ENTRIES: u32 = 100_000;

fn maps_sized(list: u32, counters: u32) -> Ebpf {
    let path = object_path();
    let object = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    EbpfLoader::new()
        .map_max_entries("UNIFIED_LIST", list)
        .map_max_entries("COUNTERS", counters)
        .load(&object)
        .unwrap_or_else(|err| panic!("creating the maps failed: {err}"))
}

fn host(index: u32) -> LpmKey {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&(0x0a00_0000u32 | index).to_be_bytes());
    LpmKey::v4([addr[0], addr[1], addr[2], addr[3]], 32)
}

fn entry() -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.deadline = carapace_common::Deadline::never();
    value
}

#[test]
fn the_model_never_charges_less_than_the_kernel_does() {
    let cpus = nr_cpus().expect("cannot read the possible processor count") as u64;
    let model = MemlockModel::for_cpus(cpus);
    let ebpf = maps_sized(ENTRIES, ENTRIES);

    let list = maps::fd(&ebpf, "UNIFIED_LIST").expect("no UNIFIED_LIST map");
    let counters = maps::fd(&ebpf, "COUNTERS").expect("no COUNTERS map");

    // An LPM trie is BPF_F_NO_PREALLOC, so it starts at nothing and grows with what is
    // written. A per-CPU array is preallocated, so its whole cost is there already.
    let empty = maps::memlock_bytes(list).expect("cannot read the list memlock");
    let counter_bytes = maps::memlock_bytes(counters).expect("cannot read the counter memlock");

    let written: Vec<(LpmKey, LpmValue)> = (0..ENTRIES).map(|i| (host(i), entry())).collect();
    lpm::load(list, &written, 1_000).expect("filling the list failed");
    let full = maps::memlock_bytes(list).expect("cannot read the list memlock");

    let reported_per_entry = (full - empty) / u64::from(ENTRIES);
    let counter_per_entry = counter_bytes / u64::from(ENTRIES);

    // The kernel reports the nodes it allocated at their nominal size. The slab rounds
    // every one of them up and the trie allocates intermediate nodes the report never
    // mentions, and on the target that came out at 1,999 times the reported figure. The
    // model charges the slab, so it is compared against the reported figure doubled.
    const SLAB_OVER_REPORTED: u64 = 2;
    let real_per_entry = reported_per_entry * SLAB_OVER_REPORTED;

    println!(
        "on {} possible processors, {ENTRIES} entries:\n\
         list      kernel reports {reported_per_entry} B/entry, slab ~{real_per_entry}, \
         model charges {}\n\
         counters  kernel reports {counter_per_entry} B/entry, model charges {}",
        cpus, model.list_bytes_per_entry, model.counter_bytes_per_entry
    );

    assert!(
        model.list_bytes_per_entry >= real_per_entry,
        "the model charges {} bytes for a list entry and the slab wants about \
         {real_per_entry}: a configuration can pass the compiler and be refused by the \
         machine",
        model.list_bytes_per_entry
    );
    assert!(
        model.counter_bytes_per_entry >= counter_per_entry,
        "the model charges {} bytes for a counter slot and the kernel charges \
         {counter_per_entry}",
        model.counter_bytes_per_entry
    );
}

/// The budget of every profile, printed with what it buys. Not an assertion about a
/// number nobody measured: the sizes come from the profile, the cost from the measured
/// model, and the point is that the three deployments are stated in the same units as the
/// machine reports and can be read off next to it.
#[test]
fn every_profile_budget_is_stated_in_the_units_the_kernel_uses() {
    let cpus = nr_cpus().expect("cannot read the possible processor count") as u64;
    let model = MemlockModel::for_cpus(cpus);

    for profile in [ProfileKind::Vps, ProfileKind::Host, ProfileKind::Gateway] {
        let budget = profile.memlock_budget();
        let reserve = profile.default_mitigation_reserve();
        let sizes = carapace_policy::MapSizes {
            unified_list_entries: reserve,
            counter_entries: CounterId::COUNT + reserve,
        };
        let needed = sizes.memlock_bytes(model);
        println!(
            "{profile:<8} budget {:>5} MiB, mitigation reserve {reserve:>9} entries, \
             costs {:>5} MiB on {cpus} processors, {:>3} % of the budget",
            budget / (1024 * 1024),
            needed / (1024 * 1024),
            100 * needed / budget
        );
        assert!(
            needed <= budget,
            "{profile} cannot even hold its own mitigation reserve: {needed} bytes \
             against a budget of {budget}"
        );
    }
}
