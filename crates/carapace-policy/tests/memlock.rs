//! The budget determines the size of the maps, not the reverse.
//!
//! This is the dominant cost of the promise "under fifty megabytes", and it is not the
//! RSS of the agent: an LPM_TRIE with `BPF_F_NO_PREALLOC` allocates per node, in
//! kernel memory that no process accounting shows and that is entirely real on a
//! two-gigabyte VPS.
//!
//! Every figure here comes from `MemlockModel`, which is an estimate derived from the
//! kernel structures and not a measurement. The measurement arrives with the batch
//! module, which reads the `memlock` field of the loaded program and `/proc/meminfo`
//! either side of filling the map; this file is what tells us whether the design fits
//! under the estimate in the meantime.

use carapace_policy::{CompileError, Config, MemlockModel, ProfileKind, compile};

const NOW: u64 = 0;

fn config(profile: &str, reserve: u32) -> Config {
    Config::from_toml(&format!(
        r#"
        profile = "{profile}"
        mitigation_reserve = {reserve}
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        "#
    ))
    .expect("the configuration did not parse")
}

#[test]
fn each_profile_states_a_budget_and_they_are_ordered() {
    let vps = ProfileKind::Vps.memlock_budget();
    let host = ProfileKind::Host.memlock_budget();
    let gateway = ProfileKind::Gateway.memlock_budget();
    assert!(vps < host && host < gateway);
    assert!(vps > 0);
}

/// The refusal that matters: a design sized for a gateway does not silently become a
/// smaller design on a VPS, it stops.
#[test]
fn a_vps_refuses_a_configuration_a_gateway_would_hold() {
    let reserve = ProfileKind::Gateway.default_mitigation_reserve();

    let on_gateway = compile(&config("gateway", reserve), NOW, MemlockModel::ESTIMATE);
    assert!(on_gateway.is_ok(), "a gateway has to hold its own default");

    let on_vps = compile(&config("vps", reserve), NOW, MemlockModel::ESTIMATE);
    match on_vps {
        Err(CompileError::MemlockExceeded {
            profile,
            needed,
            budget,
        }) => {
            assert_eq!(profile, ProfileKind::Vps);
            assert!(
                needed > budget,
                "the refusal has to be about the numbers it names"
            );
        }
        other => panic!("expected a memlock refusal, got {other:?}"),
    }
}

/// The default of each profile has to fit its own budget, or the product refuses its
/// own configuration out of the box.
#[test]
fn every_profile_default_fits_its_own_budget() {
    for profile in [ProfileKind::Vps, ProfileKind::Host, ProfileKind::Gateway] {
        let name = profile.to_string();
        let reserve = profile.default_mitigation_reserve();
        let out = compile(&config(&name, reserve), NOW, MemlockModel::ESTIMATE);
        assert!(
            out.is_ok(),
            "the {name} default does not fit the {name} budget: {out:?}"
        );
    }
}

/// The headroom is worth stating: if a profile default sat at ninety-nine percent of
/// its budget, the first measurement that revised the model upward would break every
/// deployment at once.
#[test]
fn the_defaults_leave_room_for_the_model_to_be_revised() {
    for profile in [ProfileKind::Vps, ProfileKind::Host, ProfileKind::Gateway] {
        let name = profile.to_string();
        let reserve = profile.default_mitigation_reserve();
        let out = compile(&config(&name, reserve), NOW, MemlockModel::ESTIMATE)
            .expect("the default does not compile");
        let needed = out.sizes.memlock_bytes(MemlockModel::ESTIMATE);
        let budget = profile.memlock_budget();
        assert!(
            needed * 2 <= budget,
            "the {name} default uses {needed} of {budget} bytes, which leaves no room \
             for the model to be revised upward"
        );
    }
}

#[test]
fn the_rules_themselves_count_against_the_budget() {
    let mut text = String::from("profile = \"vps\"\nmitigation_reserve = 0\n");
    for i in 0..16u32 {
        text.push_str(&format!(
            "[[rules]]\nprefix = \"10.{}.{}.0/24\"\naction = \"deny\"\n",
            i / 256,
            i % 256
        ));
    }
    let config = Config::from_toml(&text).expect("the configuration did not parse");
    let out = compile(&config, NOW, MemlockModel::ESTIMATE).expect("it should fit");
    assert_eq!(out.sizes.unified_list_entries, 16);
}

#[test]
fn the_counter_map_is_sized_from_the_counter_list() {
    let out = compile(&config("host", 0), NOW, MemlockModel::ESTIMATE).unwrap();
    assert_eq!(out.sizes.counter_entries, carapace_common::CounterId::COUNT);
}
