# Legitimate reference traces

The exit criterion of this phase is **zero false positives on legitimate traffic**. One dropped
packet is a phase failure, not a rate to comment on. This directory holds the artefact that
criterion is stated against, and it stays here permanently: every later phase re-runs it as the
non-regression, and a signature armed against something in here goes red before it goes to
production.

Two halves read it.

| Half | Where | What it asserts |
|---|---|---|
| `crates/lorica-dataplane/tests/legit_trace.rs` | build VM, CI | Every packet through `BPF_PROG_TEST_RUN` returns `XDP_PASS`, and every counter of `CounterId::ALL` that is not one of five pass-counters is zero afterwards |
| `scripts/lab/replay-legit.sh` | generator VM 902 | The trace actually left the wire whole, at a rate it prints with every result |

The wire half's receiving end — the drop counters at zero and `xdp:xdp_exception` at zero — is read
on the target, by a Rust test holding the program attached. `bpftool` cannot load this repository's
object at all (aya emits legacy map definitions libbpf dropped in 1.0), so no shell script can
attach it, and `replay-legit.sh` does not try: it sends, and it asserts the only loss a sender can
see. A trace the generator failed to send would make the target's zero mean nothing.

## `legit-ref.pcap` — the committed fixture

**Synthetic. Every packet of it.** Nothing in this file was captured from a real client, and it is
labelled that way here because a synthetic trace described as a capture is worse than an honest
synthetic one. 44 packets, ~17 kB, classic pcap, linktype Ethernet, timestamps spanning 28.000 s.

| Case | Packets | What is in them |
|---|---|---|
| ARP | 2 | Request and reply. Not IP, so not judged — the `parse_unknown_encap` pass path a real capture always exercises |
| Minecraft Java, TCP 25565 | 11 | SYN, ACK, handshake + login start, encryption response, join, chunk data (2 × 1400 B), position, keep-alive, chat, FIN/ACK. One client, one session, spanning the whole 28 s |
| FiveM, UDP 30120 | 6 | Two clients, 24 B to 1200 B, the small-frequent then large-occasional shape of a game session |
| Administration, IKE UDP 500 | 2 | Whole datagrams, 400 B and 1200 B. IKE fragments *inside* IKE (RFC 7383) precisely so the UDP datagram never needs IP fragmentation |
| Administration, ESP fragmented | 3 | One 3360-byte ESP datagram the path fragmented: first fragment plus two later ones, IPv4 |
| ICMP Packet Too Big | 2 | ICMPv4 type 3 code 4 with its quoted header, and ICMPv6 type 2. The two messages that cross unconditionally |
| IPv6 neighbour discovery | 2 | Neighbour solicitation and advertisement |
| Outbound DNS and its replies | 4 | Two queries out to a resolver, two replies back — one 96 B, one **1100 B**. See below |
| IPv6 extension headers | 2 | Destination Options + TCP 25565, Hop-by-Hop + UDP 30120 |
| IPv6 fragmentation | 2 | Fragment extension header, first and later, over ESP |
| One shared IPv4, eight sessions | 8 | `100.64.7.9`, eight source ports, four TCP and four UDP. The CGNAT case that breaks a naive per-IP threshold: eight independent players behind one address |

The 1100-byte DNS reply is in there on purpose. It has the exact shape the amplification signature
looks for — source port 53, response far larger than a query — and it is legitimate, because this
host asked for it. It is the packet most likely to make this test go red the day
`signature_amp_dns` is armed, which is the whole reason the trace exists.

### How it differs from a real capture, precisely

- **Destination MAC is broadcast.** A real capture carries the target's unicast address. Broadcast
  means the replay needs no MAC rewrite and the target needs no promiscuous mode; XDP never reads
  the destination MAC, so no stage sees a difference.
- **Payloads are filler bytes**, not protocol bytes. Header fields — ports, flags, lengths, fragment
  offsets, ICMP types, extension header chains — are all real, and they are all this pipeline reads.
  A future stage that inspects payload bytes (a Minecraft handshake parser, a DNS question parser)
  needs a capture, not this file.
- **IPv4 header checksums are correct; L4 checksums are correct except on fragments**, where the
  checksum covers a reassembly a single fragment cannot carry. XDP runs before the stack validates
  either.
- **Addresses are documentation ranges** (`192.0.2.0/24`, `198.51.100.0/24`) plus shared address
  space (`100.64.0.0/10`), so the fixture names nobody's real host. When a bogon list that refuses
  documentation ranges is armed, these sources have to be renumbered or the list scoped — the
  fixture is not exempt from the policy it is testing.
- **Frames under 60 bytes are zero-padded**, as a NIC pads them, which exercises the sanity stage's
  allowance for a total length below what arrived.

### One case held out, and why

A **fragmented UDP datagram** is not in this fixture, and the reason is not that it is hard to
write: the sanity stage drops it. The first fragment of a fragmented UDP datagram carries the UDP
header, whose length field states the length of the whole reassembled datagram, which is by
definition larger than the fragment carrying it. `crates/lorica-ebpf/src/stage/sanity.rs` compares
`l4_len` against the bytes present in *this* packet and refuses the excess, so the first fragment of
every fragmented UDP datagram — IKE over UDP 500 without RFC 7383, a fragmented DNS response over
UDP, a fragmented QUIC datagram — is dropped with `sanity_l4_length`, before stage 4 ever gets to
apply the fragment policy. That is a false positive: the packet is legitimate and the counter says
"malformed".

The fix is one condition — the L4 length check has nothing to say about a packet whose stated length
describes a reassembly — and it belongs to whoever owns that stage. Fragmented administration
traffic is in the fixture as fragmented ESP, which the plan names as the alternative and which real
IPsec produces. Add the UDP-fragment case here the day the condition lands; it is the natural
regression test for the fix.

## Capturing the real thing

The fixture is a fixture: tens of packets per case, enough for a per-packet verdict. The reference
corpus is a capture, it is large, and it does not live in this repository. **Size budget: nothing in
`bench/traces/` over 500 kB.** A corpus goes on the measurement machine's disk and is pointed at
with `LORICA_LEGIT_TRACE`, which the offline test reads instead of the fixture.

On the target, `enp6s19` only, never the LAN NIC:

```
sudo tcpdump -i enp6s19 -s 0 -w /var/tmp/legit-<case>.pcap
```

`-s 0` is not optional. tcpdump's default snaplen is large enough in 4.99, but an older default cuts
frames at 68 bytes, and both readers here refuse a capture whose `caplen` is below its `origlen` —
a snaplen-cut frame is not the frame that arrived, and feeding one to the parser raises
`parse_truncated` on a packet that was whole.

Per case:

- **Minecraft Java session.** A real server and a real client, on the same test link. Start the
  capture, connect, let the client stand in the world for a minute, disconnect. This is the case the
  lab cannot produce synthetically at all — the login sequence has a state machine and an encryption
  handshake that filler bytes do not reproduce.
- **FiveM UDP session.** Same procedure with a FiveM server on 30120.
- **Fragmented administration traffic.** Bring up an IPsec tunnel over the test link and push a
  transfer through it with the MTU lowered (`ip link set enp6s19 mtu 1280`) so the path fragments.
- **ICMP Packet Too Big.** Lower the MTU at one end and send a full-size DF packet from the other:
  `ping -M do -s 1400 10.90.1.1`.
- **DNS.** A resolver reachable on the test link, then `dig` a large TXT record from the target.
- **IPv6 with extension headers.** `ping6` produces neighbour discovery for free; extension headers
  need a sender that writes them — `mausezahn` on the 902 is installed and can.
- **Shared IPv4.** Several clients behind one NAT, or several source ports from one host, which is
  what the shared address looks like from the target's side.
- **Legitimate load, at volume.** `scripts/lab/gen-legit.sh --profile tcp-reqresp` and
  `--profile udp-echo` from the 902 while tcpdump runs on the target. That is the generator this
  repository already has, and it is the one to use — the hostile comparison is
  `gen-syn-flood.sh` and `gen-udp-flood.sh`, and a corpus mixing the two proves nothing about false
  positives.

## Replaying it

```
scripts/lab/replay-legit.sh --all --assert-zero-drop --out bench/results/legit-replay
```

Two things about the rate, both of them consequences of the tooling actually installed on the 902.

`tcpreplay` is **not installed**, so a replay goes through the netsniff-ng suite:
`netsniff-ng --in t.pcap --out t.cfg` then `trafgen --in t.cfg`. **The `.cfg` conversion keeps the
packet bytes and discards the original inter-packet timing.** trafgen therefore paces at a constant
rate, and `replay-legit.sh` defaults that rate to the trace's own packets-divided-by-span — 2 pps
for the fixture — rather than to a round number, and prints it with every result. Four of the seven
stages are stateless and indifferent to pacing; the leaky buckets are a rate limiter, and a
legitimate capture replayed fast enough will trip them. A drop under a rate the trace never had is
not a false positive.

A timing-faithful replay needs `apt install tcpreplay` on the 902, after which
`sudo tcpreplay -i enp6s19 --pps=N t.pcap` preserves the capture's own pacing. That is a
prerequisite, stated here rather than installed silently.

The script also refuses any interface whose address is outside the lab test subnet. The 902 has a
live LAN NIC, `enp6s18` on `192.168.1.83`, and generated traffic on it leaks onto a real network, so
the interface is verified rather than warned about.
