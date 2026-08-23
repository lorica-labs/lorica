//! The bogon table, and the false positives it is not allowed to have.
//!
//! A filter that drops traffic a host legitimately receives is worse than no filter at
//! all, because the operator turns the whole thing off. Most of this file exists to make
//! that failure mode loud.

use carapace_common::{Action, CounterId, Deadline, LpmKey, V4_MAPPED_PREFIX_BITS};
use carapace_policy::{
    CompileError, Config, MemlockModel, compile,
    compile::{bogon_table::BOGONS, lpm},
};

const NOW: u64 = 1_000_000_000;

fn holds(spec: &str) -> bool {
    let key = lpm::parse_prefix(spec).expect("the spec did not parse");
    BOGONS.contains(&key)
}

fn compiled(text: &str) -> carapace_policy::Compiled {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, NOW, MemlockModel::MEASURED).expect("the configuration did not compile")
}

fn refusal(text: &str) -> CompileError {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, NOW, MemlockModel::MEASURED).expect_err("it should have been refused")
}

/// **The test that matters.** A host behind NAT receives RFC 1918 sources every second
/// it is up. A bogon list that drops them by default is the false positive that gets the
/// product uninstalled, so the absence is a property of the table and not an oversight.
#[test]
fn the_rfc_1918_ranges_are_not_in_the_table() {
    for spec in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
        assert!(
            !holds(spec),
            "{spec} is private-use: a host behind NAT legitimately receives it, and \
             filtering it by default is the classic false positive"
        );
    }
}

/// The same argument one layer out, and the same argument in IPv6. Different RFCs, one
/// reason: the operator may be inside the network the prefix belongs to.
#[test]
fn the_other_local_use_ranges_are_not_in_the_table_either() {
    assert!(!holds("100.64.0.0/10"), "shared address space, carrier NAT");
    assert!(!holds("fc00::/7"), "unique-local is the IPv6 RFC 1918");
    assert!(!holds("64:ff9b:1::/48"), "local-use NAT64 translation");
}

#[test]
fn the_ranges_that_can_never_be_a_source_are_all_there() {
    for spec in [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "::1/128",
        "fe80::/10",
        "2001:db8::/32",
    ] {
        assert!(holds(spec), "{spec} is missing from the table");
    }
}

/// The generator writes the keys itself rather than calling the parser, so this is what
/// says the two agree. A key built the wrong way is not a compile error, it is a silently
/// wrong prefix in the trie.
#[test]
fn every_generated_key_is_the_key_the_parser_would_have_built() {
    for key in BOGONS {
        let text = lpm::describe(&key);
        assert_eq!(
            lpm::parse_prefix(&text).expect("a generated key did not read back"),
            key,
            "{text} does not round-trip"
        );
    }
}

/// An IPv6 prefix short enough to contain the mapped range would deny every IPv4 address
/// in existence through one entry. `::ffff:0:0/96` is in the registry and is exactly that
/// entry, which is why the generator drops it.
#[test]
fn no_entry_covers_the_mapped_ipv4_range() {
    let mapped = lpm::parse_prefix("::ffff:0:0/96").expect("the mapped range did not parse");
    for key in BOGONS {
        if key.prefix_len >= V4_MAPPED_PREFIX_BITS {
            continue;
        }
        assert!(
            !covers(&key, &mapped.addr),
            "{} covers the v4-mapped range and would deny the whole internet",
            lpm::describe(&key)
        );
    }
}

#[test]
fn no_prefix_appears_twice_in_the_table() {
    let mut seen: Vec<(u32, [u8; 16])> = BOGONS
        .iter()
        .map(|key| (key.prefix_len, key.addr))
        .collect();
    let before = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(before, seen.len(), "the table holds the same prefix twice");
}

#[test]
fn every_bogon_is_an_unconditional_drop_on_the_one_counter() {
    let out = compiled("profile = \"host\"\n");
    assert_eq!(out.bogons.len(), BOGONS.len());
    for (_, value) in &out.bogons {
        assert_eq!(value.action, Action::Drop);
        assert_eq!(value.counter_idx, CounterId::BogonRefused.index());
        assert_eq!(value.deadline, Deadline::never());
        assert_eq!(
            value.scope_len, 0,
            "a bogon applies to every port and protocol"
        );
    }
}

/// They are entries of the list that already exists, so they occupy it and count against
/// the memlock budget like anything else in it. A table that were free would mean it was
/// not in the map.
#[test]
fn the_table_occupies_the_unified_list() {
    let out = compiled("profile = \"vps\"\nmitigation_reserve = 0\n");
    assert_eq!(out.entries.len(), 0);
    assert_eq!(out.sizes.unified_list_entries as usize, BOGONS.len());
}

/// The collision resolves the way `compile/lpm.rs` resolves any two rules on one prefix:
/// a refusal at compile time. The trie keys on the prefix alone, so silently preferring
/// one of the two would be a policy nobody could read off the file.
#[test]
fn an_operator_rule_on_a_bogon_prefix_is_refused() {
    assert_eq!(
        refusal(
            r#"
            profile = "host"
            [[rules]]
            prefix = "127.0.0.0/8"
            action = "deny"
            "#
        ),
        CompileError::BogonPrefix {
            prefix: "127.0.0.0/8".to_owned()
        }
    );
}

/// And the exception the refusal points at: a longer prefix inside a bogon compiles, and
/// wins by being the longer prefix. That is the whole precedence rule, applied here too.
#[test]
fn a_longer_prefix_inside_a_bogon_is_accepted_and_wins() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "192.0.2.7/32"
        action = "allow"
        scopes = ["tcp:443"]
        "#,
    );
    let rule = out.entries[0].0;
    let bogon = lpm::parse_prefix("192.0.2.0/24").unwrap();
    assert!(BOGONS.contains(&bogon));
    assert!(
        rule.prefix_len > bogon.prefix_len,
        "the exception has to be the more specific entry for the trie to prefer it"
    );
}

/// Whether `prefix` contains `addr`, on the first `prefix_len` bits.
fn covers(prefix: &LpmKey, addr: &[u8; 16]) -> bool {
    let whole = (prefix.prefix_len / 8) as usize;
    let spare = prefix.prefix_len % 8;
    if prefix.addr[..whole] != addr[..whole] {
        return false;
    }
    if spare == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - spare);
    prefix.addr[whole] & mask == addr[whole] & mask
}
