//! Precedence is the specificity of the address, never the order of declaration.
//!
//! That is counter-intuitive for anyone arriving from iptables, where the first
//! matching rule wins, so it is written down and tested rather than assumed.

use lorica_common::{Action, Clock, CounterId, Deadline, SCOPE_MAX};
use lorica_policy::{Config, MemlockModel, compile, compile::lpm};

/// 250 Hz rather than 1000: a deadline built by multiplying seconds by the wrong
/// constant is off by a factor of four here, and exactly right at 1000.
const CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 1_000_000,
};

fn compiled(text: &str) -> lorica_policy::Compiled {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, CLOCK, MemlockModel::MEASURED).expect("the configuration did not compile")
}

/// A host allow inside a network deny. Both entries are emitted; which one applies is
/// decided by the trie, and the longer prefix is the one it returns.
#[test]
fn a_host_allow_inside_a_network_deny_is_the_more_specific_entry() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120"]
        "#,
    );

    assert_eq!(out.entries.len(), 2);
    let deny = out
        .entries
        .iter()
        .find(|(key, _)| key.prefix_len == 120)
        .expect("the /24 is missing");
    let allow = out
        .entries
        .iter()
        .find(|(key, _)| key.prefix_len == 128)
        .expect("the /32 is missing");

    assert_eq!(deny.1.action, Action::Drop);
    assert_eq!(allow.1.action, Action::Allow);
    assert!(
        allow.0.prefix_len > deny.0.prefix_len,
        "the allow entry has to be the more specific one for the trie to prefer it"
    );
}

/// The property that matters: reordering the file changes nothing. A configuration
/// language where it did would make a policy impossible to review by reading it.
#[test]
/// The IPv6 prefix here is global unicast and not the documentation range, which would be
/// the obvious choice for a test: the documentation range is a bogon, and a rule on a bogon
/// prefix is refused at compile time. What this test is about is declaration order, so it
/// uses a prefix the compiler has no opinion about.
fn the_order_of_declaration_changes_no_entry() {
    let one = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120"]
        [[rules]]
        prefix = "2a01:4f8::/32"
        action = "deny"
        "#,
    );
    let other = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "2a01:4f8::/32"
        action = "deny"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120"]
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        "#,
    );

    let mut one: Vec<_> = one
        .entries
        .iter()
        .map(|(key, value)| (key.prefix_len, key.addr, value.action as u8))
        .collect();
    let mut other: Vec<_> = other
        .entries
        .iter()
        .map(|(key, value)| (key.prefix_len, key.addr, value.action as u8))
        .collect();
    one.sort();
    other.sort();
    assert_eq!(one, other);
}

#[test]
fn a_service_name_and_its_literal_compile_the_same() {
    let named = compiled(
        r#"
        profile = "host"
        [services]
        game = "udp:30120-30130"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["game"]
        "#,
    );
    let literal = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120-30130"]
        "#,
    );
    assert_eq!(named.entries[0].1.scopes, literal.entries[0].1.scopes);
}

#[test]
fn a_rule_without_a_ttl_never_expires() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        "#,
    );
    assert_eq!(out.entries[0].1.deadline, Deadline::never());
}

#[test]
fn a_ttl_becomes_a_deadline_on_the_clock_it_was_given() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        ttl_secs = 3600
        "#,
    );
    assert_eq!(
        out.entries[0].1.deadline,
        Deadline(CLOCK.jiffies + 3600 * CLOCK.hz as u64)
    );
}

#[test]
fn every_scope_of_a_rule_reaches_the_value() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120", "tcp:443", "tcp:22", "icmp:any"]
        "#,
    );
    let value = out.entries[0].1;
    assert_eq!(value.scope_len as usize, SCOPE_MAX);
    assert!(value.applies_to(17, 30_120));
    assert!(value.applies_to(6, 443));
    assert!(value.applies_to(6, 22));
    assert!(!value.applies_to(6, 80), "an unlisted port must not match");
}

#[test]
fn the_settings_word_carries_what_the_file_said() {
    let out = compiled(
        r#"
        profile = "host"
        [settings]
        accept_ip_options = true
        allow_later_fragments = true
        "#,
    );
    assert_eq!(
        out.settings,
        lorica_common::setting::ACCEPT_IP_OPTIONS | lorica_common::setting::ALLOW_LATER_FRAGMENTS
    );
}

/// Each entry gets its own counter slot, so a bypass through a forged allow-listed
/// source is visible as that entry rather than as an anonymous total.
#[test]
fn each_entry_gets_its_own_counter_slot() {
    let out = compiled(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["tcp:443"]
        [[rules]]
        prefix = "10.90.1.8/32"
        action = "allow"
        scopes = ["tcp:443"]
        "#,
    );
    let slots: Vec<u32> = out
        .entries
        .iter()
        .map(|(_, value)| value.counter_idx)
        .collect();
    assert_eq!(slots, vec![CounterId::COUNT, CounterId::COUNT + 1]);
}

#[test]
fn an_ipv4_rule_and_its_mapped_form_are_the_same_prefix() {
    let from_v4 = lpm::parse_prefix("10.90.1.0/24").unwrap();
    let from_v6 = lpm::parse_prefix("::ffff:10.90.1.0/120").unwrap();
    assert_eq!(from_v4, from_v6);
}
