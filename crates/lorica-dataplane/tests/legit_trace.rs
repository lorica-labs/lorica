//! The exit criterion of the phase: zero false positives on a legitimate reference
//! capture, offline and deterministic.
//!
//! Every packet of `bench/traces/legit-ref.pcap` goes through `BPF_PROG_TEST_RUN` and has
//! to come back `XDP_PASS`. One drop is a phase failure and not a rate to comment on, so
//! there is no tolerance here and no threshold to tune.
//!
//! Three of the seven stages pass everything today, so this test is easy to satisfy right
//! now. That is the point: it is the non-regression, and its value is the day a signature
//! is armed against a packet in here that it should never have matched. The counters are
//! therefore read exhaustively rather than selectively — checking only the ones a reader
//! thought of is how a false positive survives — and a counter added to `CounterId` later
//! is asserted at zero by default rather than quietly excluded.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use lorica_common::{CounterId, Drain, Rate, UNITS_PER_BYTE, setting};
use support::{
    BucketGlobals, TestProg, XdpAction, pkt::MIN_TEST_RUN_LEN, program, program_with_buckets,
};

/// The policy an operator running fragmented administration traffic loads.
///
/// The fixture carries ESP datagrams the path fragmented, and under the default policy a
/// later fragment is refused *by design* — the operator has a decision to make and stage 4
/// exists to make it visible. Judging the fixture under the default would therefore
/// measure that decision and not a false positive.
///
/// `ENFORCE_BUCKETS` is set because with it clear stage 7 counts and passes, so the trace
/// never meets the rate limiter and the criterion certified six stages out of seven — and
/// the seventh is the only one whose verdict comes from timing rather than from packet
/// content, which makes it the one most able to refuse something nobody predicted.
const POLICY: u32 = setting::ALLOW_LATER_FRAGMENTS | setting::ENFORCE_BUCKETS;

/// Packets in the committed fixture, stated and not derived. A reader that stopped early
/// would otherwise report zero drops over three packets, which reads exactly like a pass.
const FIXTURE_PACKETS: usize = 44;

/// Bytes the whole fixture carries, and the shortest frame in it. Stated for the same
/// reason as the packet count: both budgets below are derived from them, so a fixture that
/// changed underneath would silently change what is being asserted.
const FIXTURE_BYTES: u64 = 16_256;
const SHORTEST_FRAME: u64 = 60;

/// The per-source budget stage 7 is armed with, in bytes per second: 1 Mbit/s, which is
/// what an operator hands a single client of an administration or game endpoint.
///
/// The fixture offers 16256 bytes over 28 seconds of capture time — 580 B/s, some 200x
/// under this — but **`BPF_PROG_TEST_RUN` does not honour the capture's timestamps.** The
/// 44 packets go through back to back, as fast as the loop issues the syscall, so the
/// whole trace reaches the bucket inside a jiffy or two and `now` barely advances. The
/// wire replay is where the pacing is tested, which is why `tcpreplay` is installed on the
/// generator; here the rate is nearly inert and the burst is what decides.
const RATE_BYTES_PER_SEC: u64 = 125_000;

/// The burst that has to admit the whole trace, and it is the fixture's own byte total.
///
/// A bucket is indexed on a hash of the source address, so the worst case this trace can
/// present to one bucket is every one of its frames landing in it: `FIXTURE_BYTES`. A
/// burst equal to that total is therefore the smallest one that provably cannot refuse a
/// conformant trace whatever the hash does with it, and it moves with the fixture instead
/// of being a round number that happens to pass.
const BURST: u64 = FIXTURE_BYTES;

/// The negative control, one constant away from `BURST` and the opposite verdict.
///
/// A burst under the shortest frame in the fixture refuses every packet that reaches stage
/// 7, and it does so without racing the jiffy: a bucket found at level zero still has to
/// fit the frame under the ceiling, so no amount of drain can rescue this case. That is
/// what makes the pass above mean something — the stage is live, and the same trace at the
/// same rate comes back refused when the budget is the one thing that moves.
const TIGHT_BURST: u64 = SHORTEST_FRAME - 1;

/// The counters a clean run of the fixture moves, and by how much. Every other counter of
/// `CounterId::ALL` has to be zero afterwards.
///
/// All five count a packet that was *let through*, which is what makes the list short: the
/// pipeline only counts the exceptions it makes and the drops it decides, so a legitimate
/// trace leaves almost the whole array at zero. They are asserted exactly rather than as
/// "above zero" because they double as the integrity check of the fixture: a case that
/// silently left the file would show up here before it showed up as a missing test.
const EXPECTED: &[(&str, u64)] = &[
    // The ARP request and reply. Not IP, so not judged, and counted rather than passed
    // silently.
    ("parse_unknown_encap", 2),
    // ICMPv4 Fragmentation Needed and ICMPv6 Packet Too Big.
    ("icmp_path_mtu_passed", 2),
    // IPv6 neighbour solicitation and advertisement.
    ("icmp_neighbor_passed", 2),
    // The first fragment of the IPv4 ESP datagram and of the IPv6 one.
    ("fragment_first_passed", 2),
    // Two later fragments of the IPv4 datagram, one of the IPv6 one.
    ("fragment_later_allowed", 3),
];

#[test]
fn the_legitimate_reference_trace_loses_no_packet() {
    let path = trace_path();
    let packets = read_pcap(&path);
    check_fixture(&path, &packets);

    let prog = program_with_buckets(POLICY, budget(BURST));

    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(
            prog.run(packet),
            XdpAction::Pass,
            "packet {} of {} ({} bytes) from {} was not passed. One drop on the legitimate \
             reference trace is a phase failure",
            index + 1,
            packets.len(),
            packet.len(),
            path.display()
        );
    }

    // Without this the pass above would also hold if nothing ever reached the bucket bank,
    // which is exactly the hole arming the stage is meant to close.
    let levels = prog.bank_levels();
    let charged: u64 = levels.iter().sum::<u64>() / UNITS_PER_BYTE;
    let busiest: u64 = levels.iter().copied().max().unwrap_or(0) / UNITS_PER_BYTE;
    assert!(
        charged > 0,
        "no packet of the trace was charged to a bucket, so arming stage 7 asserted nothing"
    );
    println!(
        "stage 7 charged {charged} of the {FIXTURE_BYTES} bytes the fixture carries, at most \
         {busiest} of them to one bucket against a burst of {BURST}"
    );

    check_counters(&prog, &[]);
}

/// The negative control of the case above: the same trace, the same rate, a burst under
/// one frame, and the opposite verdict. Without it, a burst so loose that no packet could
/// ever be refused would read as a stage that admits legitimate traffic.
///
/// The marking path is asserted on the same traffic because it costs one more load: with
/// `MARK_OVER_BUDGET` the excess reaches the stack instead of being dropped, and the tier
/// an operator's dashboard reports is the same either way — `bucket_over_budget` moves by
/// the same amount, which is the property that makes the capability optional.
#[test]
fn the_same_trace_under_a_burst_below_one_frame_is_refused() {
    let path = trace_path();
    let packets = read_pcap(&path);
    check_fixture(&path, &packets);

    let dropping = program_with_buckets(POLICY, budget(TIGHT_BURST));
    let refused = packets
        .iter()
        .filter(|packet| dropping.run(packet) == XdpAction::Drop)
        .count() as u64;
    println!(
        "a burst of {TIGHT_BURST} bytes refused {refused} of the {FIXTURE_PACKETS} packets, \
         where {BURST} refuses none"
    );
    assert!(
        refused > 0,
        "a burst below the shortest frame of the fixture refused nothing, so the pass at a \
         burst of {BURST} says nothing about stage 7"
    );
    check_counters(&dropping, &[("bucket_over_budget", refused)]);

    let marking = program_with_buckets(POLICY | setting::MARK_OVER_BUDGET, budget(TIGHT_BURST));
    for packet in &packets {
        assert_eq!(
            marking.run(packet),
            XdpAction::Pass,
            "with MARK_OVER_BUDGET set the excess is tagged and reaches the stack"
        );
    }
    check_counters(
        &marking,
        &[("bucket_over_budget", refused), ("bucket_marked", refused)],
    );
}

/// Stage 7's globals: the burst asked for, and the rate converted once here the way the
/// loader converts it, because the clock on the packet path counts jiffies.
fn budget(burst: u64) -> BucketGlobals {
    let hz = program().clock().hz;
    BucketGlobals::fixed(Rate {
        drain: Drain::per_jiffy(RATE_BYTES_PER_SEC, hz),
        burst,
    })
}

fn check_fixture(path: &Path, packets: &[Vec<u8>]) {
    assert_eq!(
        packets.len(),
        FIXTURE_PACKETS,
        "{} holds {} packets and the fixture is {FIXTURE_PACKETS}. A short file passing \
         this test would be a zero-drop run over traffic that is not the reference trace",
        path.display(),
        packets.len()
    );
    let bytes: u64 = packets.iter().map(|packet| packet.len() as u64).sum();
    assert_eq!(
        bytes,
        FIXTURE_BYTES,
        "{} carries {bytes} bytes and the fixture is {FIXTURE_BYTES}. Both budgets of stage \
         7 are derived from that total",
        path.display()
    );
    let shortest = packets.iter().map(Vec::len).min().unwrap_or(0) as u64;
    assert_eq!(
        shortest,
        SHORTEST_FRAME,
        "the shortest frame of {} is {shortest} bytes and the fixture's is {SHORTEST_FRAME}, \
         which is what makes {TIGHT_BURST} a burst no frame fits under",
        path.display()
    );
}

/// `EXPECTED` plus whatever this case arms, and every other counter of `CounterId::ALL` at
/// zero — including the two of stage 7 when nothing there was refused.
fn check_counters(prog: &TestProg, extra: &[(&str, u64)]) {
    for id in CounterId::ALL {
        let expected = EXPECTED
            .iter()
            .chain(extra)
            .find(|(name, _)| *name == id.name())
            .map_or(0, |(_, count)| *count);
        assert_eq!(
            prog.counter(id.name()),
            expected,
            "{} is {} after the reference trace and should be {expected}",
            id.name(),
            prog.counter(id.name())
        );
    }
}

/// The trace under test. The environment variable is how the same assertion is pointed at
/// the large corpus, which is captured on the wire and does not live in the repository.
fn trace_path() -> PathBuf {
    if let Ok(path) = env::var("LORICA_LEGIT_TRACE") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/traces/legit-ref.pcap")
}

const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_SWAPPED: u32 = PCAP_MAGIC.swap_bytes();
const LINKTYPE_ETHERNET: u32 = 1;
const GLOBAL_HEADER: usize = 24;
const RECORD_HEADER: usize = 16;

/// The classic pcap format, hand-read: a 24-byte global header, then per record a 16-byte
/// header (ts_sec, ts_usec, caplen, origlen) and caplen bytes. Forty lines against a
/// dependency this crate has no other use for.
///
/// Every refusal below exists because its silent version produces a *pass*. A magic this
/// reader does not know would be parsed as garbage packets; a record that runs past the
/// end of the file would end the loop early over a trace nobody noticed was short; and a
/// frame whose caplen is below its origlen was cut by the capture snaplen, so feeding it
/// to the parser would raise `parse_truncated` on a packet that arrived whole.
fn read_pcap(path: &Path) -> Vec<Vec<u8>> {
    let raw = fs::read(path).unwrap_or_else(|err| {
        panic!(
            "cannot read the reference trace at {}: {err}\n\
             see bench/traces/README.md, or point LORICA_LEGIT_TRACE at another capture",
            path.display()
        )
    });
    assert!(
        raw.len() >= GLOBAL_HEADER,
        "{} is {} bytes, which is not even a pcap global header",
        path.display(),
        raw.len()
    );

    let magic = u32::from_le_bytes(raw[..4].try_into().expect("four bytes"));
    let big_endian = match magic {
        PCAP_MAGIC => false,
        PCAP_MAGIC_SWAPPED => true,
        other => panic!(
            "{} opens with {other:#010x}, which is not a classic pcap magic. 0xa1b2c3d4 \
             and its byte swap are the microsecond format this reader accepts; 0xa1b23c4d \
             is the nanosecond variant and 0x0a0d0d0a is pcapng, and reading either as a \
             classic pcap would turn header bytes into packets",
            path.display()
        ),
    };
    let word = |at: usize| {
        let bytes: [u8; 4] = raw[at..at + 4].try_into().expect("four bytes");
        if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };

    let linktype = word(20);
    assert_eq!(
        linktype,
        LINKTYPE_ETHERNET,
        "{} is linktype {linktype} and not Ethernet. A cooked capture — tcpdump -i any — \
         prefixes a header this Ethernet parser would read as a MAC address",
        path.display()
    );

    let mut packets = Vec::new();
    let mut at = GLOBAL_HEADER;
    while at < raw.len() {
        assert!(
            raw.len() - at >= RECORD_HEADER,
            "{} ends in {} bytes of a 16-byte record header after {} packets",
            path.display(),
            raw.len() - at,
            packets.len()
        );
        let caplen = word(at + 8) as usize;
        let origlen = word(at + 12) as usize;
        assert_eq!(
            caplen,
            origlen,
            "record {} of {} was captured at {caplen} of {origlen} bytes. A snaplen-cut \
             frame is not the frame that arrived",
            packets.len() + 1,
            path.display()
        );
        assert!(
            caplen >= MIN_TEST_RUN_LEN,
            "record {} of {} is {caplen} bytes, below the {MIN_TEST_RUN_LEN} that \
             BPF_PROG_TEST_RUN accepts as an XDP input",
            packets.len() + 1,
            path.display()
        );
        let start = at + RECORD_HEADER;
        assert!(
            raw.len() - start >= caplen,
            "record {} of {} claims {caplen} bytes and only {} remain in the file",
            packets.len() + 1,
            path.display(),
            raw.len() - start
        );
        packets.push(raw[start..start + caplen].to_vec());
        at = start + caplen;
    }
    packets
}
