//! Field offsets of the structures shared between the eBPF program and the agent.
//!
//! The sizes and alignments are asserted inside the crate itself, so a drift fails
//! the build of both worlds and not only of this test. What lives here is what a
//! const assertion in the crate cannot express: the offsets, and the fact that the
//! constructors initialise the padding.

use std::mem::{align_of, offset_of, size_of};

use lorica_common::{Action, Deadline, LpmKey, LpmValue, PacketView, SCOPE_MAX, Scope};

/// The view is copied verbatim out of a kernel map by the parse tests, so a hole in it
/// would be read as a field. There is none: the address, eight `u16`s and eight `u8`s
/// fill 40 bytes exactly.
///
/// It was 56 while it also carried the packet start and end. Those left because only the
/// signature stage ever read through them and it is handed the context instead, and what
/// went with them was the `u64` that set the alignment — so the struct is two-aligned now
/// and the assertion below says so rather than the eight it used to.
#[test]
fn the_parsed_view_has_no_hole_in_it() {
    assert_eq!(offset_of!(PacketView, src), 0);
    assert_eq!(offset_of!(PacketView, l3_off), 16);
    assert_eq!(offset_of!(PacketView, family_raw), 32);
    assert_eq!(size_of::<PacketView>(), 40);
    assert_eq!(align_of::<PacketView>(), 2);
}

/// The accessor the signature stage reads a MAGIC through. The bound is what the
/// verifier is shown; here it is checked against real memory, which is the only place
/// an off-by-one in it can be seen at all.
#[test]
fn a_payload_read_stops_at_the_end_of_the_packet() {
    let packet: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let (mut view, data, end) = view_over(&packet);
    view.payload_off = 8;

    assert_eq!(view.payload_bytes::<4>(data, end, 0), Some([8, 9, 10, 11]));
    assert_eq!(view.payload_bytes::<2>(data, end, 2), Some([10, 11]));
    assert_eq!(
        view.payload_bytes::<4>(data, end, 1),
        None,
        "one byte past the end"
    );
    assert_eq!(view.payload_bytes::<2>(data, end, 3), None);
    // A payload offset outside the frame the parser bounds itself to, which is what
    // keeps the sum of the offset and the read under MAX_PACKET_OFF.
    view.payload_off = u16::MAX;
    assert_eq!(view.payload_bytes::<2>(data, end, 0), None);
}

/// The view and the two packet bounds, which it no longer carries.
///
/// They are the caller's now: the stage that reads a payload is handed the context it
/// already has, and every other stage stopped paying to carry two pointers it never read.
fn view_over(packet: &[u8]) -> (PacketView, u64, u64) {
    let mut view: PacketView = unsafe { std::mem::zeroed() };
    view.packet_len = packet.len() as u16;
    let data = packet.as_ptr() as u64;
    (view, data, data + packet.len() as u64)
}

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
