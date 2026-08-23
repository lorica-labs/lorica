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

use carapace_common::{CounterId, setting};
use support::{XdpAction, pkt::MIN_TEST_RUN_LEN, program_with};

/// The policy an operator running fragmented administration traffic loads.
///
/// The fixture carries ESP datagrams the path fragmented, and under the default policy a
/// later fragment is refused *by design* — the operator has a decision to make and stage 4
/// exists to make it visible. Judging the fixture under the default would therefore
/// measure that decision and not a false positive.
const POLICY: u32 = setting::ALLOW_LATER_FRAGMENTS;

/// Packets in the committed fixture, stated and not derived. A reader that stopped early
/// would otherwise report zero drops over three packets, which reads exactly like a pass.
const FIXTURE_PACKETS: usize = 44;

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
    assert_eq!(
        packets.len(),
        FIXTURE_PACKETS,
        "{} holds {} packets and the fixture is {FIXTURE_PACKETS}. A short file passing \
         this test would be a zero-drop run over traffic that is not the reference trace",
        path.display(),
        packets.len()
    );

    let prog = program_with(POLICY);

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

    for id in CounterId::ALL {
        let expected = EXPECTED
            .iter()
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
    if let Ok(path) = env::var("CARAPACE_LEGIT_TRACE") {
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
             see bench/traces/README.md, or point CARAPACE_LEGIT_TRACE at another capture",
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
