//! What the two modes do to a real map, and what the observing one is not allowed to do.
//!
//! The load-bearing case is the first one. Nothing else in this repository can be opened
//! to a reader with the claim that the tool observes and reports without refusing traffic
//! unless a test has watched the map not move while the ladder reached the rungs that
//! refuse — so that case runs every one of them and asserts the map is byte for byte the
//! map it was, by key and by the kernel's own accounting of it.
//!
//! The module is included by path rather than imported: `loricad` is a binary, an
//! integration test cannot reach into one, and the alternative — restating the code here
//! the way `no_alloc_in_tick.rs` has to restate its allocator — would be a second
//! implementation of the one decision under test. What is compiled here is the file the
//! agent compiles.

#![cfg(all(target_os = "linux", feature = "kernel-tests"))]

#[path = "../src/enforce/mod.rs"]
mod enforce;

use std::{os::fd::BorrowedFd, path::PathBuf};

use aya::{
    Ebpf, EbpfLoader,
    maps::{
        MapData,
        lpm_trie::{Key, LpmTrie},
    },
};
use lorica_common::{Action, Clock, CounterId, Deadline, LpmKey, LpmValue};
use lorica_dataplane::{clock, maps};
use lorica_detect::{Confirmation, Decision, Reason, Tier};
use lorica_policy::Mode;

use enforce::{Applied, apply, withdraw};

/// Small, and not the object's own default: the list this test writes into has to be one
/// this file sized, or a change in `lorica-ebpf` would change what is under test.
const LIST_ENTRIES: u32 = 64;
const COUNTER_ENTRIES: u32 = CounterId::COUNT + LIST_ENTRIES;

/// The first slot above the named counters. Read from `lorica-common` rather than written
/// down: a number recopied here would go stale the day a counter is added.
const SLOT: u32 = CounterId::COUNT;

/// Seconds of life a decision is written with. A parameter of the test and of nothing
/// else: the agent's own TTL is `lorica_detect::tier::Config::ttl_secs`, and what is
/// asserted below is that whatever the ladder put in the decision is what reaches the
/// map.
const TTL_SECS: u64 = 600;

#[derive(Clone, Copy)]
struct PodValue(LpmValue);

// SAFETY: LpmValue is Copy and 'static, and every value read back here was written into
// this map by this file.
unsafe impl aya::Pod for PodValue {}

fn object_path() -> PathBuf {
    if let Ok(path) = std::env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

/// The maps, and the clock the deadlines in them are compared against.
///
/// The clock is measured through the object's own probe, not derived from a wall clock:
/// a deadline is a count of jiffies, and the whole question a deadline test can answer is
/// whether the number written is on the axis the data path reads.
fn lab() -> (Ebpf, Clock) {
    let path = object_path();
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    let mut ebpf = EbpfLoader::new()
        .map_max_entries("UNIFIED_LIST", LIST_ENTRIES)
        .map_max_entries("COUNTERS", COUNTER_ENTRIES)
        .load(&bytes)
        .unwrap_or_else(|err| panic!("creating the maps of {} failed: {err}", path.display()));
    let clock = clock::calibrate(&mut ebpf).expect("cannot measure the kernel clock rate");
    (ebpf, clock)
}

fn list_fd(ebpf: &Ebpf) -> BorrowedFd<'_> {
    maps::fd(ebpf, "UNIFIED_LIST").expect("no UNIFIED_LIST map in the object")
}

fn read_back(ebpf: &Ebpf, key: LpmKey) -> Option<LpmValue> {
    let map = ebpf.map("UNIFIED_LIST").expect("no UNIFIED_LIST map");
    let list: LpmTrie<&MapData, [u8; 16], PodValue> =
        LpmTrie::try_from(map).expect("UNIFIED_LIST is not an LPM trie");
    list.get(&Key::new(key.prefix_len, key.addr), 0)
        .ok()
        .map(|found| found.0)
}

/// The kernel's own accounting of the map, which grows per inserted prefix. It is how a
/// case with no key to look up — a forged decision that names none — can still assert
/// that nothing was inserted.
fn memlock(ebpf: &Ebpf) -> u64 {
    maps::memlock_bytes(list_fd(ebpf)).expect("cannot read the memlock of the list")
}

/// A decision at a rung that refuses packets, named on `key`.
///
/// `Rtbh` rests on the announced prefix and the other two on a confirmed key, which is
/// the only difference; `excess_bps` and `link_bps` are carried and not read by anything
/// under test here.
fn refusal(tier: Tier, key: LpmKey, deadline: Deadline) -> Decision {
    let reason = match tier {
        Tier::Rtbh => Reason::Saturation {
            excess_bps: 1,
            link_bps: 1,
            announce: Some(key),
        },
        _ => Reason::Confirmed {
            key,
            by: Confirmation::ExactKey,
            per_sec: 1,
        },
    };
    Decision::new(tier, reason, deadline)
        .expect("a rung naming its own exact key has to be constructible")
}

/// Every rung for which `Tier::drops` holds. Written as the filter and not as a list, so
/// a rung added to the ladder is covered here without anyone remembering this file.
fn refusing_rungs() -> Vec<Tier> {
    let mut rungs = Vec::new();
    let mut tier = Tier::Observe;
    loop {
        if tier.drops() {
            rungs.push(tier);
        }
        let next = tier.up();
        if next == tier {
            break;
        }
        tier = next;
    }
    rungs
}

/// The reason the repository can be opened: observing refuses nothing, at any rung.
#[test]
fn observing_writes_no_refusal_whatever_rung_the_ladder_reached() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let before = memlock(&ebpf);

    let rungs = refusing_rungs();
    assert!(
        rungs.len() >= 3,
        "the ladder has to carry rungs that refuse for this case to mean anything, found {}",
        rungs.len()
    );

    let mut withheld = 0;
    for (i, tier) in rungs.iter().enumerate() {
        // One key per rung, so a rung whose entry did get written cannot hide behind
        // another rung's miss.
        let key = LpmKey::host_v4([198, 51, 100, 10 + i as u8]);
        let decision = refusal(*tier, key, clock.deadline(TTL_SECS));
        let applied = apply(fd, Mode::Observe, &decision, SLOT).expect("observing cannot fail");
        assert_eq!(
            applied,
            Applied::Withheld(key),
            "rung {} has to report the key it would have refused",
            tier.rung()
        );
        withheld += 1;
        assert!(
            read_back(&ebpf, key).is_none(),
            "rung {} wrote {key:?} into the list in observe mode",
            tier.rung()
        );
    }

    // The metric side of the same tick: every rung was decided and reported.
    assert_eq!(withheld, rungs.len());
    assert_eq!(
        memlock(&ebpf),
        before,
        "the list grew while nothing was supposed to be written into it"
    );
}

#[test]
fn arming_writes_the_entry_with_the_deadline_the_decision_carried() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let key = LpmKey::host_v4([198, 51, 100, 7]);
    let deadline = clock.deadline(TTL_SECS);

    let decision = refusal(Tier::DropSurgical, key, deadline);
    assert_eq!(
        apply(fd, Mode::Armed, &decision, SLOT).expect("the write failed"),
        Applied::Written(key)
    );

    let entry = read_back(&ebpf, key).expect("armed mode has to write the entry");
    assert_eq!(entry.action, Action::Drop);
    assert_eq!(
        entry.deadline, deadline,
        "the entry has to carry the deadline the ladder decided, not one this path invented"
    );
    assert!(
        !entry.deadline.is_never(),
        "an entry the detection wrote must expire, and this one never does"
    );
    assert_eq!(
        entry.counter_idx, SLOT,
        "the refusal has to be counted in its own slot, or nobody can see it happening"
    );
}

/// The deadline is not optional for a mitigation entry, so a decision that carries none
/// is refused rather than written as permanent.
#[test]
fn a_decision_with_no_deadline_is_refused_rather_than_written_forever() {
    let (ebpf, _clock) = lab();
    let fd = list_fd(&ebpf);
    let key = LpmKey::host_v4([198, 51, 100, 8]);

    let decision = refusal(Tier::DropSurgical, key, Deadline::never());
    let err = apply(fd, Mode::Armed, &decision, SLOT)
        .expect_err("a refusal that never expires has to be refused");
    assert!(
        err.to_string().contains("deadline"),
        "the message has to name what is missing, got: {err}"
    );
    assert!(
        read_back(&ebpf, key).is_none(),
        "the entry was written anyway"
    );
}

/// An entry pointed at a named counter would make the drops it causes look like evidence
/// to the engine that ordered them, which is a ladder confirming itself.
#[test]
fn an_entry_pointed_at_a_named_counter_is_refused() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let key = LpmKey::host_v4([198, 51, 100, 9]);

    let decision = refusal(Tier::DropSurgical, key, clock.deadline(TTL_SECS));
    let err = apply(fd, Mode::Armed, &decision, CounterId::COUNT - 1)
        .expect_err("a slot inside the named counters has to be refused");
    assert!(
        err.to_string().contains("named"),
        "the message has to say which region the slot fell in, got: {err}"
    );
    assert!(
        read_back(&ebpf, key).is_none(),
        "the entry was written anyway"
    );
}

/// The agent dying is not a cleanup problem: the entry it left behind is still in the map
/// and stops being applied on its own.
#[test]
fn the_death_of_the_agent_leaves_the_entry_to_expire_alone() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let key = LpmKey::host_v4([198, 51, 100, 11]);
    let deadline = clock.deadline(1);

    apply(
        fd,
        Mode::Armed,
        &refusal(Tier::DropSurgical, key, deadline),
        SLOT,
    )
    .expect("the write failed");

    // Nothing withdraws it, which is the case: from here on this test is a dead agent.
    let entry = read_back(&ebpf, key).expect("the entry has to survive in the map");
    assert!(
        !entry.deadline.expired(clock.jiffies),
        "the deadline was already past when it was written, so what follows proves nothing"
    );
    assert!(
        entry
            .deadline
            .expired(clock.jiffies + 2 * u64::from(clock.hz)),
        "two seconds of uptime later, with nobody left to remove it, the entry has to \
         stop being applied: {:?} against a clock at {} Hz",
        entry.deadline,
        clock.hz
    );
    assert!(
        read_back(&ebpf, key).is_some(),
        "expiry is not removal: the entry stays in the map and stops being applied"
    );
}

/// The TTL is the net and not the policy, so the withdrawal has to happen before it.
#[test]
fn an_explicit_withdrawal_removes_the_entry_before_its_deadline() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let key = LpmKey::host_v4([198, 51, 100, 12]);

    apply(
        fd,
        Mode::Armed,
        &refusal(Tier::DropSurgical, key, clock.deadline(TTL_SECS)),
        SLOT,
    )
    .expect("the write failed");
    let entry = read_back(&ebpf, key).expect("armed mode has to write the entry");

    let now = clock::read(&ebpf).expect("cannot read the jiffy counter");
    assert!(
        !entry.deadline.expired(now),
        "the deadline is already past, so a disappearing entry would only be the net"
    );

    withdraw(fd, key).expect("the withdrawal failed");
    assert!(
        read_back(&ebpf, key).is_none(),
        "the entry is still in the list after being withdrawn"
    );

    // Withdrawing twice is what a restart, or a list reloaded without the key, looks
    // like from here. It is not an error.
    withdraw(fd, key).expect("withdrawing an entry that is already gone is not a failure");
}

/// The invariant, as the type system holds it and as this path holds what the type
/// cannot.
///
/// `Decision::new` answers `None` for every combination of a refusing rung and a reason
/// naming no exact key, so there is no value to hand to `apply` — the assertions below
/// are that absence, and there is no `Decision` literal in this file because the struct
/// is `#[non_exhaustive]` and cannot be written as one from outside its crate.
///
/// What the type does not close is the second half: the fields are `pub`, so a decision
/// already built can be raised to a refusing rung after the fact. That back door is what
/// the last block exercises, and it is why `apply` re-reads the key instead of unwrapping
/// one it was promised.
#[test]
fn a_rung_that_refuses_without_an_exact_key_cannot_be_built() {
    let (ebpf, clock) = lab();
    let fd = list_fd(&ebpf);
    let deadline = clock.deadline(TTL_SECS);

    let keyless = [
        Reason::Quiet,
        Reason::Pressure {
            counter: CounterId::BucketOverBudget,
            per_sec: 1_000_000,
            loaded_share: u32::MAX,
        },
        Reason::Saturation {
            excess_bps: 1,
            link_bps: 1,
            announce: None,
        },
    ];
    for tier in refusing_rungs() {
        for reason in keyless {
            assert!(
                Decision::new(tier, reason, deadline).is_none(),
                "rung {} was constructible on {reason:?}, which names no exact key",
                tier.rung()
            );
        }
    }

    // The back door this test used to walk through is closed. `Decision`'s fields were `pub`,
    // so a decision built at rung zero could be raised to a refusing rung afterwards while
    // keeping `Reason::Quiet`, and the constructor's check was worth nothing. They are private
    // now, and the two lines below no longer compile:
    //
    //     let mut forged = Decision::quiet();
    //     forged.tier = Tier::DropSurgical;
    //
    // `error[E0616]: field `tier` of struct `Decision` is private`. `apply` still re-reads the
    // key rather than trusting the rung, because a guard on one side of a crate boundary
    // should not rest on the other side having kept its promise.
    let before = memlock(&ebpf);
    let quiet = Decision::quiet();
    assert_eq!(
        apply(fd, Mode::Armed, &quiet, SLOT).expect("rung zero applies as a no-op"),
        Applied::Nothing
    );
    assert_eq!(
        memlock(&ebpf),
        before,
        "the list grew for a decision that named nothing to refuse"
    );
}
