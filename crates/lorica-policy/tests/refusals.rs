//! One test per refusal. A refusal without a test is an intention.

use lorica_common::Clock;
use lorica_policy::{CompileError, Config, MemlockModel, Warning, compile};

const CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 1_000_000,
};

fn refusal(text: &str) -> CompileError {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, CLOCK, MemlockModel::MEASURED)
        .expect_err("the configuration compiled when it should have been refused")
}

fn accepted(text: &str) -> lorica_policy::Compiled {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, CLOCK, MemlockModel::MEASURED).expect("the configuration did not compile")
}

/// Two entries on the same prefix leave the trie with no answer. Resolving it here by
/// picking one would be a false positive nobody could see afterwards.
#[test]
fn the_same_prefix_twice_is_refused() {
    let err = refusal(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "allow"
        scopes = ["tcp:443"]
        "#,
    );
    assert_eq!(
        err,
        CompileError::DuplicatePrefix {
            prefix: "10.90.1.0/24".to_owned()
        }
    );
}

/// The same prefix reached through the other family is still the same prefix, because
/// one trie holds both.
#[test]
fn the_same_prefix_written_two_ways_is_refused() {
    let err = refusal(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        [[rules]]
        prefix = "::ffff:10.90.1.0/120"
        action = "deny"
        "#,
    );
    assert!(matches!(err, CompileError::DuplicatePrefix { .. }));
}

/// An allow entry with no scope is a bare source address, so anybody who writes that
/// address into a UDP header is inside. It is the bypass the design exists to prevent.
#[test]
fn an_allow_without_a_scope_is_refused() {
    let err = refusal(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        "#,
    );
    assert_eq!(
        err,
        CompileError::UnscopedAllow {
            prefix: "10.90.1.7/32".to_owned()
        }
    );
}

/// A deny with no scope is the opposite case and entirely reasonable: it applies to
/// everything from that prefix.
#[test]
fn a_deny_without_a_scope_is_accepted() {
    let out = accepted(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.0/24"
        action = "deny"
        "#,
    );
    // Accepted, unlike the unscoped allow above, and it lands in the flat tables rather than
    // the trie — a scope is the first of the three things they have no room for, so a rule
    // that names none is the rule they were built to hold. Asserted here rather than left to
    // `entries` being empty, which would also be true if the rule had been dropped on the
    // floor.
    assert_eq!(out.flat.len(), 1, "the deny is somewhere");
    assert_eq!(out.flat[0].1, 24, "and it is the /24 that was written");
    assert!(out.entries.is_empty(), "nothing needed the trie");
}

#[test]
fn more_scopes_than_the_value_holds_is_refused() {
    let err = refusal(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:1", "udp:2", "udp:3", "udp:4", "udp:5"]
        "#,
    );
    assert_eq!(
        err,
        CompileError::TooManyScopes {
            prefix: "10.90.1.7/32".to_owned(),
            count: 5
        }
    );
}

/// A warning, not a refusal. A forged source costs an attacker nothing on UDP, so this
/// is a gun pointed at the operator own foot; they are still allowed to hold it, and
/// to document why at home.
#[test]
fn an_allow_scoped_to_udp_warns_without_refusing() {
    let out = accepted(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["udp:30120"]
        "#,
    );
    assert_eq!(
        out.warnings,
        vec![Warning::AllowOnUdp {
            prefix: "10.90.1.7/32".to_owned(),
            scope: "udp:30120".to_owned(),
        }]
    );
}

#[test]
fn an_allow_scoped_to_tcp_warns_about_nothing() {
    let out = accepted(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/32"
        action = "allow"
        scopes = ["tcp:443"]
        "#,
    );
    assert!(out.warnings.is_empty());
}

#[test]
fn a_prefix_with_host_bits_is_refused() {
    let err = refusal(
        r#"
        profile = "host"
        [[rules]]
        prefix = "10.90.1.7/24"
        action = "deny"
        "#,
    );
    assert_eq!(
        err,
        CompileError::PrefixHasHostBits {
            spec: "10.90.1.7/24".to_owned()
        }
    );
}

#[test]
fn an_unparseable_prefix_is_refused() {
    assert!(matches!(
        refusal(
            r#"
            profile = "host"
            [[rules]]
            prefix = "not-an-address"
            action = "deny"
            "#
        ),
        CompileError::BadPrefix { .. }
    ));
}

#[test]
fn a_scope_that_names_nothing_is_refused() {
    assert!(matches!(
        refusal(
            r#"
            profile = "host"
            [[rules]]
            prefix = "10.90.1.7/32"
            action = "allow"
            scopes = ["gaem"]
            "#
        ),
        CompileError::BadScope { .. }
    ));
}

/// An unknown key is a typo, and a typo that is ignored is a policy the operator
/// believes they wrote.
#[test]
fn an_unknown_field_does_not_parse() {
    assert!(
        Config::from_toml(
            r#"
            profile = "host"
            [[rules]]
            prefix = "10.90.1.0/24"
            action = "deny"
            tt_secs = 60
            "#
        )
        .is_err()
    );
}
