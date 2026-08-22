//! Field offsets of the structures shared between the eBPF program and the agent.
//!
//! The sizes and alignments are asserted inside the crate itself, so a drift fails
//! the build of both worlds and not only of this test. What lives here is what a
//! const assertion in the crate cannot express: the offsets, and the fact that the
//! constructors initialise the padding.

use std::mem::{align_of, offset_of, size_of};

use carapace_common::{Action, Deadline, LpmKey, LpmValue, SCOPE_MAX, Scope};

#[test]
fn lpm_key_matches_what_the_trie_requires() {
    // The kernel reads prefix_len as the leading u32 of an LPM_TRIE key. Any other
    // offset silently matches on the wrong bits.
    assert_eq!(offset_of!(LpmKey, prefix_len), 0);
    assert_eq!(offset_of!(LpmKey, addr), 4);
    assert_eq!(size_of::<LpmKey>(), 20);
}

#[test]
fn lpm_value_offsets() {
    assert_eq!(offset_of!(LpmValue, action), 0);
    assert_eq!(offset_of!(LpmValue, priority), 1);
    assert_eq!(offset_of!(LpmValue, scope_len), 2);
    assert_eq!(offset_of!(LpmValue, scopes), 4);
    assert_eq!(offset_of!(LpmValue, deadline), 32);
    assert_eq!(offset_of!(LpmValue, counter_idx), 40);
    assert_eq!(size_of::<LpmValue>(), 48);
    assert_eq!(align_of::<LpmValue>(), 8);
}

#[test]
fn scope_offsets() {
    assert_eq!(offset_of!(Scope, proto), 0);
    assert_eq!(offset_of!(Scope, port_lo), 2);
    assert_eq!(offset_of!(Scope, port_hi), 4);
    assert_eq!(size_of::<Scope>(), 6);
}

/// The two padding holes of `LpmValue` are copied verbatim into kernel memory. A
/// struct literal would leave them uninitialised; the constructors must not.
#[test]
fn constructors_initialise_the_padding() {
    let value = LpmValue::zeroed();
    let bytes = unsafe {
        std::slice::from_raw_parts((&raw const value) as *const u8, size_of::<LpmValue>())
    };
    assert!(
        bytes.iter().all(|b| *b == 0),
        "zeroed left a byte set: {bytes:?}"
    );

    let scope = Scope::new(17, 30_120, 30_120);
    let bytes =
        unsafe { std::slice::from_raw_parts((&raw const scope) as *const u8, size_of::<Scope>()) };
    assert_eq!(
        bytes[1], 0,
        "the padding byte of Scope was left uninitialised"
    );
}

#[test]
fn action_rejects_an_out_of_range_discriminant() {
    assert_eq!(Action::from_u8(0), Some(Action::Continue));
    assert_eq!(Action::from_u8(4), Some(Action::Mark));
    assert_eq!(Action::from_u8(5), None);
    assert_eq!(Action::from_u8(255), None);
}

#[test]
fn an_ipv4_prefix_lands_in_the_mapped_range() {
    let key = LpmKey::v4([10, 90, 1, 0], 24);
    assert_eq!(key.prefix_len, 120);
    assert_eq!(&key.addr[10..12], &[0xff, 0xff]);
    assert_eq!(&key.addr[12..], &[10, 90, 1, 0]);
    assert_eq!(LpmKey::host_v4([10, 90, 1, 1]).prefix_len, 128);
}

#[test]
fn a_scoped_entry_does_not_apply_outside_its_scope() {
    let mut value = LpmValue::zeroed();
    value.action = Action::Allow;
    value.scope_len = 1;
    value.scopes[0] = Scope::new(17, 30_120, 30_120);

    assert!(value.applies_to(17, 30_120));
    assert!(!value.applies_to(17, 30_121), "wrong port must not match");
    assert!(
        !value.applies_to(6, 30_120),
        "wrong protocol must not match"
    );
}

#[test]
fn an_entry_without_scope_applies_to_everything() {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    assert_eq!(value.scope_len, 0);
    assert!(value.applies_to(6, 443));
    assert!(value.applies_to(17, 1));
}

/// A scope_len written past the array is clamped rather than trusted: userspace
/// writes it, and the same code runs where an out-of-bounds read is a verifier
/// rejection at best.
#[test]
fn an_oversized_scope_len_is_clamped() {
    let mut value = LpmValue::zeroed();
    value.scope_len = 200;
    for i in 0..SCOPE_MAX {
        value.scopes[i] = Scope::new(6, 80, 80);
    }
    assert!(value.applies_to(6, 80));
    assert!(!value.applies_to(6, 81));
}

#[test]
fn deadline_is_a_bare_u64() {
    assert_eq!(size_of::<Deadline>(), 8);
    assert_eq!(align_of::<Deadline>(), 8);
    assert_eq!(offset_of!(LpmValue, deadline), 32);
}
