use carapace_common::{Clock, Deadline};

#[test]
fn never_does_not_expire_anywhere_on_the_clock() {
    let never = Deadline::never();
    assert!(never.is_never());
    assert!(!never.expired(0));
    assert!(!never.expired(u64::MAX - 1));
    // The interesting one: a naive `now >= deadline` expires here.
    assert!(!never.expired(u64::MAX));
}

#[test]
fn expiry_is_exact_to_the_jiffy() {
    let deadline = Deadline(1_000);
    assert!(!deadline.expired(999));
    assert!(
        deadline.expired(1_000),
        "the deadline instant is already past"
    );
    assert!(deadline.expired(1_001));
}

#[test]
fn a_deadline_of_zero_is_already_past() {
    assert!(Deadline(0).expired(0));
}

#[test]
fn after_saturates_instead_of_wrapping() {
    assert_eq!(Deadline::after(100, 900), Deadline(1_000));

    // Wrapping here would produce a small deadline, so an entry the operator asked
    // to keep essentially forever would be treated as already expired. For an Allow
    // entry that is the dangerous direction.
    let saturated = Deadline::after(u64::MAX - 5, 10);
    assert_eq!(saturated, Deadline::never());
    assert!(!saturated.expired(u64::MAX));
}

#[test]
fn after_zero_ttl_expires_immediately() {
    let now = 42_000_000;
    assert!(Deadline::after(now, 0).expired(now));
}

/// A TTL is configured in whole seconds and stored in jiffies, so the rate is the only
/// thing standing between the two. Getting it wrong is not visible in a verdict: the
/// entry simply lives four times too long, or expires four times too early.
#[test]
fn a_ttl_in_seconds_becomes_that_many_seconds_of_jiffies() {
    let clock = Clock {
        hz: 250,
        jiffies: 1_000,
    };
    assert_eq!(clock.deadline(60), Deadline(1_000 + 60 * 250));
    assert!(!clock.deadline(60).expired(clock.jiffies + 60 * 250 - 1));
    assert!(clock.deadline(60).expired(clock.jiffies + 60 * 250));
}

/// The saturation of `after`, reached the way an operator would reach it: a TTL in
/// seconds so long that multiplying it by the rate overflows. Wrapping would make it
/// already expired, which for an `Allow` entry is the direction that costs.
#[test]
fn a_ttl_too_long_to_hold_becomes_never_rather_than_past() {
    let clock = Clock {
        hz: 1_000,
        jiffies: 1_000,
    };
    let forever = clock.deadline(u64::MAX / 500);
    assert_eq!(forever, Deadline::never());
    assert!(!forever.expired(u64::MAX));
}
