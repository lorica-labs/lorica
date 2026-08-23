//! The invariant `stage/mod.rs` states, enforced: no drop rests on state another source
//! can move.
//!
//! Two stages of the pipeline classify rather than prove. The bank judges a hash of a
//! source address, which 1 024 buckets means it necessarily shares with other sources, so
//! its level is not that source's history. Six of the ten catalogue vectors judge one
//! datagram against a port and a size with no memory of what left the host. Both produce
//! *candidates*, and a candidate is confirmed by an explicit operator policy or by nothing
//! at all — `stage/bucket.rs` says why nothing downstream could confirm it instead.
//!
//! So both cases drive traffic far past the budget with the bit under test clear, and
//! assert zero drops. The counter is the other half of each assertion: a regression that
//! stopped classifying at all would satisfy a zero-drop test for the wrong reason, and a
//! test that only counted would not notice a verdict.
//!
//! These are two loads of the same object with two policy words, which is the whole
//! mechanism: `ENFORCE_BUCKETS` and `ENFORCE_SIGNATURES` are load-time globals, so the
//! armed and unarmed arms cannot share state and one cannot leak into the other.

#![cfg(feature = "kernel-tests")]

mod support;

use lorica_common::{DEFAULT_SETTINGS, Drain, Rate, setting};
use support::{BucketGlobals, PktBuilder, TestProg, XdpAction, program_with_buckets};

/// 14 Ethernet, 20 IPv4, 8 UDP and the payload.
const HEADERS: u64 = 14 + 20 + 8;

/// Well above the reflection ports, so the bucket case is not quietly a signature case.
const QUIET_SPORT: u16 = 20_000;
/// Above the ephemeral floor, so `could_be_solicited` answers yes and no amplification
/// vector looks at it.
const QUIET_DPORT: u16 = 30_120;

/// A reflected DNS answer: from port 53, to a service port nothing behind this pipeline
/// queries from, and past the 512-byte floor of the vector.
const DNS_PAYLOAD: usize = 600;
const DNS_SPORT: u16 = 53;
const DNS_DPORT: u16 = 80;

/// Packets each case offers from one source, and the burst in frames. The gap between them
/// is what makes the case a flood rather than a boundary: 36 of the 40 are over budget, so
/// a stage that dropped on bucket state alone could not go unnoticed by one frame.
const FLOOD: usize = 40;
const BURST_FRAMES: u64 = 4;

/// A burst of exactly `frames` frames of `size` bytes, and nothing draining it.
///
/// `Drain::NONE` rather than a rate, for the reason `stage_bucket.rs` gives: a jiffy is 1
/// to 4 ms wide, so a burst measured against a real rate races the tick.
fn burst_of(frames: u64, size: u64) -> BucketGlobals {
    BucketGlobals::fixed(Rate {
        drain: Drain::NONE,
        burst: frames * size,
    })
}

fn dropped(prog: &TestProg, pkt: &[u8]) -> usize {
    (0..FLOOD)
        .filter(|_| prog.run(pkt) == XdpAction::Drop)
        .count()
}

/// The bank's verdict, both ways round. Arming it is the only thing that makes the drop
/// reachable, and with it clear no amount of exhaustion reaches one.
///
/// Both arms run the identical traffic against the identical budget, so the candidate set
/// is the same in both — `bucket_over_budget` is asserted equal to prove that, because it
/// is what separates "the invariant holds" from "the stage stopped working".
#[test]
fn arming_the_bank_is_what_makes_a_bucket_drop_reachable() {
    let frame = HEADERS + 64;
    let globals = burst_of(BURST_FRAMES, frame);
    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 2])
        .udp(QUIET_SPORT, QUIET_DPORT)
        .payload(64)
        .build();
    assert_eq!(
        pkt.len() as u64,
        frame,
        "the burst is derived from this frame"
    );

    let excess = FLOOD as u64 - BURST_FRAMES;

    let unarmed = program_with_buckets(DEFAULT_SETTINGS, globals);
    let unarmed_drops = dropped(&unarmed, &pkt);
    assert_eq!(
        unarmed_drops, 0,
        "{FLOOD} packets from one source against a burst of {BURST_FRAMES} frames dropped \
         {unarmed_drops} with ENFORCE_BUCKETS clear. A bucket level is shared with every \
         other source that hashes there, so a drop decided on it alone refuses traffic no \
         operator asked to refuse"
    );
    assert_eq!(
        unarmed.counter("bucket_over_budget"),
        excess,
        "the stage has to have recognised the excess for the zero above to mean anything"
    );

    let armed = program_with_buckets(DEFAULT_SETTINGS | setting::ENFORCE_BUCKETS, globals);
    assert_eq!(
        dropped(&armed, &pkt),
        excess as usize,
        "with the operator's bit set the same excess has to be refused, or the bit does \
         nothing and the invariant above is vacuous"
    );
    assert_eq!(
        armed.counter("bucket_over_budget"),
        unarmed.counter("bucket_over_budget"),
        "the two arms saw the same candidates and differ only in what confirmed them"
    );
}

/// The strongest candidate the pipeline can build, confirmed by nothing.
///
/// An armed amplification vector matches, routes the packet to the suspect budget, and that
/// budget is exhausted 36 times over. Two classifiers agree and the packet still passes,
/// because neither of them proves anything about it: the reflection vector cannot know
/// whether something behind the pipeline sent the query, and the bucket is shared. Only
/// `ENFORCE_BUCKETS`, which this load leaves clear, would confirm it.
#[test]
fn an_amplification_candidate_that_nothing_confirms_is_not_dropped() {
    let frame = HEADERS + DNS_PAYLOAD as u64;
    let globals = burst_of(BURST_FRAMES, frame);
    let pkt = PktBuilder::eth()
        .ipv4()
        .src_v4([10, 90, 1, 3])
        .udp(DNS_SPORT, DNS_DPORT)
        .payload(DNS_PAYLOAD)
        .build();
    assert_eq!(
        pkt.len() as u64,
        frame,
        "the burst is derived from this frame"
    );

    let prog = program_with_buckets(DEFAULT_SETTINGS | setting::ENFORCE_SIGNATURES, globals);
    let drops = dropped(&prog, &pkt);

    assert_eq!(
        drops, 0,
        "{drops} of {FLOOD} reflected DNS answers were dropped with the catalogue armed and \
         the bank not. A reflection vector is a judgement — the datagram could be the answer \
         to a query this host really sent — so it routes to the tighter budget and the \
         buckets decide, and the buckets decide nothing until the operator arms them"
    );
    assert_eq!(
        prog.counter("signature_amp_dns"),
        FLOOD as u64,
        "the vector has to have matched every one of them"
    );
    assert_eq!(
        prog.counter("bucket_over_budget"),
        FLOOD as u64 - BURST_FRAMES,
        "and the suspect budget has to have been exhausted, or the zero above is only a \
         budget that was never reached"
    );
}
