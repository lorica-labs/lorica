//! The deadline, compared in the kernel at every lookup.
//!
//! This is the mechanism that makes an accidental permanent blackhole structurally
//! impossible. If the agent dies, if the node reboots, if a bug stops the removal from
//! ever happening, the entry stays in the map and stops being applied. So the cases
//! here are about an entry that is *present* and *not applied*, which is a different
//! statement from an entry that was removed.

#![cfg(feature = "kernel-tests")]

mod support;

use carapace_common::{Action, Deadline, LpmKey, LpmValue, Scope};
use support::{PktBuilder, XdpAction, program};

const UDP: u8 = 17;
const GAME_PORT: u16 = 30_120;
const BLOCKED: [u8; 4] = [198, 51, 100, 7];

fn entry_slot(index: u32) -> u32 {
    carapace_common::CounterId::COUNT + index
}

/// The clock the program compares against. `bpf_ktime_get_ns` is `CLOCK_MONOTONIC`, so
/// a deadline built from this reading and one built from the kernel's own are on the
/// same axis. Any other base — `CLOCK_BOOTTIME` differs by the suspended time,
/// `CLOCK_REALTIME` by decades — would show up as a case below failing by a wide
/// margin rather than by a jitter.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into a timespec we own and does nothing else.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn drop_until(deadline: Deadline) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.deadline = deadline;
    value
}

fn allow_until(deadline: Deadline, slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Allow;
    value.scope_len = 1;
    value.scopes[0] = Scope::new(UDP, GAME_PORT, GAME_PORT);
    value.counter_idx = slot;
    value.deadline = deadline;
    value
}

fn udp_from(src: [u8; 4], dport: u16) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(1111, dport)
        .build()
}

/// The whole point. The entry is in the map, it says drop, and it is not applied.
#[test]
fn an_expired_drop_entry_is_still_in_the_map_and_no_longer_applied() {
    let mut prog = program();
    let key = LpmKey::v4(BLOCKED, 32);
    let deadline = Deadline(monotonic_ns() - 50_000_000);
    prog.insert(key, drop_until(deadline));

    let before_expired = prog.counter("lpm_expired");
    let before_hit = prog.counter("lpm_drop_hit");

    assert_eq!(
        prog.run(&udp_from(BLOCKED, GAME_PORT)),
        XdpAction::Pass,
        "a deadline in the past must stop the entry from being applied"
    );
    assert_eq!(prog.counter("lpm_expired"), before_expired + 1);
    assert_eq!(
        prog.counter("lpm_drop_hit"),
        before_hit,
        "an expired entry must not be counted as a drop it did not cause"
    );

    let read_back = prog
        .list_get(key)
        .expect("the expired entry was removed from the map, which is not the design");
    assert_eq!(
        read_back.deadline, deadline,
        "the entry has to survive its own expiry untouched: nothing in the kernel \
         removes it, and the agent is the only thing that ever will"
    );
}

/// The dangerous direction. An allow entry that has expired must stop letting the
/// packet out of the pipeline, and must not count as a legitimate exit — otherwise a
/// temporary exemption becomes a permanent one the moment the agent stops looking.
#[test]
fn an_expired_allow_entry_no_longer_lets_the_packet_out() {
    let mut prog = program();
    let source = [203, 0, 113, 9];
    prog.insert(
        LpmKey::v4(source, 32),
        allow_until(Deadline(monotonic_ns() - 50_000_000), entry_slot(0)),
    );

    let before_exit = prog.counter_at(entry_slot(0));
    let before_expired = prog.counter("lpm_expired");

    // It carries on down the pipeline, which is not the same verdict as exiting here.
    assert_eq!(prog.run(&udp_from(source, GAME_PORT)), XdpAction::Pass);
    assert_eq!(
        prog.counter_at(entry_slot(0)),
        before_exit,
        "an expired allow must not count as an exit against its entry"
    );
    assert_eq!(prog.counter("lpm_expired"), before_expired + 1);
}

/// `Deadline::never()` is `u64::MAX`, and the comparison against that sentinel is what
/// keeps a clock reading of `u64::MAX` from expiring an entry declared never to expire.
/// The arithmetic side is covered in `carapace-common`; this is the in-kernel branch.
#[test]
fn an_entry_that_never_expires_is_applied_forever() {
    let mut prog = program();
    prog.insert(LpmKey::v4(BLOCKED, 32), drop_until(Deadline::never()));

    let before_expired = prog.counter("lpm_expired");
    let before_hit = prog.counter("lpm_drop_hit");

    for _ in 0..3 {
        assert_eq!(prog.run(&udp_from(BLOCKED, GAME_PORT)), XdpAction::Drop);
    }
    assert_eq!(prog.counter("lpm_drop_hit"), before_hit + 3);
    assert_eq!(
        prog.counter("lpm_expired"),
        before_expired,
        "the sentinel was compared as a number instead of as never"
    );
}

/// An entry left at all-zero bytes is expired, and that is the direction to fail in.
///
/// The two mistakes are not symmetric. A forgotten deadline that means never turns a
/// drop into the permanent blackhole this whole mechanism exists to make impossible; a
/// forgotten deadline that means expired turns it into a no-op, which is visible in
/// `lpm_expired` and recoverable. The policy compiler writes `Deadline::never()` for a
/// rule without a TTL, so nothing in production relies on this default — it is the
/// behaviour of a bug, and it is pinned here so nobody makes it comfortable later.
#[test]
fn an_entry_with_no_deadline_at_all_is_expired_rather_than_eternal() {
    let mut prog = program();
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    assert_eq!(value.deadline, Deadline(0), "zeroed no longer means zero");
    prog.insert(LpmKey::v4(BLOCKED, 32), value);

    let before = prog.counter("lpm_expired");
    assert_eq!(prog.run(&udp_from(BLOCKED, GAME_PORT)), XdpAction::Pass);
    assert_eq!(prog.counter("lpm_expired"), before + 1);
}

/// A deadline fifty milliseconds ahead is not expired, one fifty milliseconds behind
/// is. Fifty milliseconds is far tighter than the distance between any two clock bases
/// the kernel offers, so a program reading a different clock fails this and not by a
/// margin that could be jitter.
#[test]
fn the_deadline_is_compared_against_the_same_clock_as_the_rest_of_the_pipeline() {
    let mut prog = program();
    let now = monotonic_ns();
    let ahead = [192, 0, 2, 1];
    let behind = [192, 0, 2, 2];

    prog.insert(
        LpmKey::v4(ahead, 32),
        drop_until(Deadline(now + 50_000_000)),
    );
    prog.insert(
        LpmKey::v4(behind, 32),
        drop_until(Deadline(now - 50_000_000)),
    );

    assert_eq!(
        prog.run(&udp_from(ahead, GAME_PORT)),
        XdpAction::Drop,
        "a deadline 50 ms in the future was read as already past"
    );
    assert_eq!(
        prog.run(&udp_from(behind, GAME_PORT)),
        XdpAction::Pass,
        "a deadline 50 ms in the past was read as still ahead"
    );
}

/// An expired entry must not cost a second clock reading. The whole budget is built on
/// the clock being read once per packet in `stage::run` and passed down, and the TTL is
/// the first consumer of that reading.
#[cfg(feature = "count-helpers")]
#[test]
fn the_expiry_check_reuses_the_one_clock_reading() {
    let mut prog = program();
    prog.insert(
        LpmKey::v4(BLOCKED, 32),
        drop_until(Deadline(monotonic_ns() - 50_000_000)),
    );

    assert_eq!(prog.run(&udp_from(BLOCKED, GAME_PORT)), XdpAction::Pass);

    let counts = prog.helper_counts();
    assert_eq!(
        counts.clock_reads, 1,
        "the expiry check read the clock again, got {counts:?}"
    );
    assert_eq!(
        counts.map_lookups, 2,
        "expected the list lookup and the expiry counter, got {counts:?}"
    );
}
