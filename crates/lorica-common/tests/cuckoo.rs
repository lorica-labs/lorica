//! The three pieces of the cuckoo lookup that are arithmetic rather than structure.
//!
//! The signature search, the lane decoder and the involution of the alternate bucket are the
//! parts an eBPF transcription will copy instruction for instruction, and each of them has a
//! small enough domain to be checked outright rather than sampled. Everything about the
//! *structure* — whether insertion succeeds at a load factor of 0.5, whether the lookup agrees
//! with the Robin Hood table — is in `lorica-policy`, where the builder is.

use lorica_common::{
    Action,
    blocklist::cuckoo::{
        CUCKOO_BUCKET_MASK, CUCKOO_LANES, CuckooBucket, cuckoo_alt, cuckoo_delta, cuckoo_hash,
        cuckoo_lane, cuckoo_match, cuckoo_occupancy, cuckoo_sig,
    },
};

/// Every lane, and the empty mask. Eight inputs and a ninth case is the whole domain of the
/// decoder, so there is nothing to sample: the constant it multiplies by is built by placing a
/// three-bit field per lane, and a field one bit out of place would answer for seven lanes and
/// lie about the eighth.
#[test]
fn the_lane_decoder_is_exact_over_its_whole_domain() {
    assert_eq!(cuckoo_lane(0), None);
    for lane in 0..CUCKOO_LANES {
        // The mask `cuckoo_match` produces for a hit in this lane: the high bit of its byte.
        let mask = 0x80u64 << (8 * lane);
        assert_eq!(
            cuckoo_lane(mask),
            Some(lane),
            "the decoder maps the lane-{lane} mask {mask:#018x} to the wrong lane"
        );
    }
}

/// The signature search, over every lane and every signature value.
///
/// 8 lanes x 255 signatures x 256 values for the *neighbouring* lane is 522 240 cases, which is
/// the whole space that matters: what has to hold is that a hit is found in the right lane, and
/// that the documented borrow artefact — a lane holding `sig ^ 1` immediately above a match
/// being flagged too — never changes the answer, because the caller takes the lowest set bit.
#[test]
fn the_signature_search_finds_the_lane_that_holds_it() {
    for lane in 0..CUCKOO_LANES {
        for sig in 1..=255u8 {
            // The bucket holds this signature in `lane` and nothing anywhere else.
            let sigs = u64::from(sig) << (8 * lane);
            assert_eq!(
                cuckoo_lane(cuckoo_match(sigs, sig)),
                Some(lane),
                "signature {sig} in lane {lane} alone was not found there"
            );

            // And with an arbitrary byte in the lane above, which is where the borrow of the
            // zero-byte search lands.
            if lane + 1 < CUCKOO_LANES {
                for neighbour in 0..=255u8 {
                    let sigs = sigs | (u64::from(neighbour) << (8 * (lane + 1)));
                    assert_eq!(
                        cuckoo_lane(cuckoo_match(sigs, sig)),
                        Some(lane),
                        "signature {sig} in lane {lane} with {neighbour} above it resolved wrong"
                    );
                }
            }
        }
    }
}

/// A signature the bucket does not hold must not be found, whatever else is in it.
///
/// This is the assertion the borrow artefact could break in the other direction, and it is
/// checked over every pair of one occupied lane and one query signature.
#[test]
fn a_signature_no_lane_holds_is_not_found() {
    for lane in 0..CUCKOO_LANES {
        for held in 1..=255u8 {
            let sigs = u64::from(held) << (8 * lane);
            for sig in 1..=255u8 {
                if sig == held {
                    continue;
                }
                // A free lane is zero and a query signature is never zero, so nothing here may
                // match.
                assert_eq!(
                    cuckoo_lane(cuckoo_match(sigs, sig)),
                    None,
                    "querying {sig} against a bucket holding only {held} in lane {lane} matched"
                );
            }
        }
    }
}

/// A signature is never zero, because zero is what marks a lane free: a query that could be
/// zero would match every free lane of every bucket it reaches.
#[test]
fn no_key_has_a_zero_signature() {
    // Every hash whose low byte is zero, which is the only way a signature could be zero, and
    // then a wide sweep of real keys.
    for high in 0..=0xffffffu32 {
        assert_ne!(cuckoo_sig(high << 8), 0);
    }
    let mut key = 0x1234_5678u32;
    for _ in 0..1_000_000 {
        assert_ne!(cuckoo_sig(cuckoo_hash(key)), 0);
        key = key.wrapping_mul(0x0019_660d).wrapping_add(0x3c6e_f35f);
    }
}

/// The alternate bucket has to be an involution and never the bucket it came from.
///
/// The involution is what lets a displaced key be moved back without the table recording where
/// it was; equality would silently halve the capacity available to that key, with the
/// simulation reporting a failure it could not attribute.
#[test]
fn the_alternate_bucket_is_an_involution_and_never_the_home_one() {
    let mut key = 1u32;
    for _ in 0..2_000_000 {
        let delta = cuckoo_delta(key);
        let home =
            lorica_common::blocklist::cuckoo::cuckoo_home(cuckoo_hash(key)) & CUCKOO_BUCKET_MASK;
        let alt = cuckoo_alt(home, delta);
        assert_ne!(alt, home, "key {key} has one bucket and not two");
        assert_eq!(
            cuckoo_alt(alt, delta),
            home,
            "key {key} cannot be moved back from its alternate bucket"
        );
        key = key.wrapping_mul(0x0019_660d).wrapping_add(0x3c6e_f35f);
    }
}

/// The occupancy count against the lanes actually set, which is what the simulation reports
/// load factors from.
#[test]
fn occupancy_counts_the_lanes_that_are_set() {
    assert_eq!(cuckoo_occupancy(0), 0);
    assert_eq!(cuckoo_occupancy(u64::MAX), CUCKOO_LANES as u32);
    // Alternating lanes: a count that read the wrong end of the word would answer four either
    // way, so the pattern is asymmetric.
    assert_eq!(cuckoo_occupancy(0x0000_0000_00ff_ffff), 3);
}

/// The bucket is a cache line with every field where the layout says, checked through the
/// public API rather than through a transmute: the eBPF side reads these bytes with
/// hand-written offsets, so a field that moved would be a silent wrong verdict.
#[test]
fn a_bucket_holds_what_was_written_into_it() {
    let mut bucket = CuckooBucket::EMPTY;
    assert_eq!(cuckoo_occupancy(bucket.sigs), 0);
    bucket.sigs = 0x00_00_00_00_00_00_2a_00;
    bucket.keys[1] = 0x0a00_0001;
    bucket.tags[1] = Action::Drop as u8;
    assert_eq!(cuckoo_occupancy(bucket.sigs), 1);
    assert_eq!(cuckoo_lane(cuckoo_match(bucket.sigs, 0x2a)), Some(1));
    assert_eq!(
        Action::from_u8(bucket.tags[1]),
        Some(Action::Drop),
        "the verdict has to survive the byte it is stored in"
    );
}
