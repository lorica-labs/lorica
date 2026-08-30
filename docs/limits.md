# Limits

What Lorica costs, what it does not do, and what has not been measured. Read this before the
README's feature list, not after it.

Every number here was measured on the lab described at the bottom. Where a number is missing,
this page says so instead of estimating one.

---

## 1. Attaching an XDP program to virtio-net costs throughput, permanently

Measured on the receive path, one virtio-net interface, an application above it:

| | detached | attached | change |
|---|---:|---:|---:|
| RX throughput | 14 048 Mbps | 5 842 Mbps | **−58 %** |
| application p99 | 668 µs | 1 051 µs | **+57 %** |
| jitter | — | — | roughly doubled |

Transmit is untouched. **This is paid 100 % of the time**, under attack or not, because it is
the cost of the program being on the hook at all.

**The mechanism is not what we expected, and the difference matters to you.** The hypothesis
was that attaching turns off two hardware offloads, receive checksumming among them. That was
tested and is false: the offload table is byte-identical before and after, `rx-checksumming`
reads `on [fixed]`, and GRO is on in both states. What actually happens is that the XDP
program runs *before* GRO, so GRO arrives with nothing left to coalesce and the stack pays
per-packet costs it used to amortise over a batch.

Which means the tax depends on your traffic, and in a direction you can reason about: a
large-packet flow that GRO was coalescing well loses the most, and a small-packet flow that
GRO could barely coalesce should lose much less. **We have not measured the small-packet
profile.** If your workload is small packets, the 58 % above is an upper bound, not your
number.

One more caveat on the same figure: 14 048 Mbps detached is already the virtio path's own
limit on this host. The 58 % is therefore a ratio measured on that path, not a constant of
XDP.

## 2. The pps at which on-host mode degrades your application is not known

The honest answer, and the reason.

This lab tops out at **~267 000 pps delivered** (~295 000 emitted from a single generator, and
two concurrent generators reach ~300 000 in aggregate — the bridge and `vhost-net`, not
Lorica, are the limit). At 267 kpps of 64-byte frames that is about 137 Mbps: there is nothing
to defend at that rate, so the regime where the answer lives — where the kernel's per-packet
cost becomes the limiting factor, typically past a million pps — is **above the ceiling of the
instrument** and is not covered.

Any pps figure you see about Lorica should be read against that ceiling. We do not have a
number for where on-host mode starts hurting the application it is protecting, and we will not
invent one.

## 3. The XDP hook takes one program, and refuses the second

If something else already owns XDP on your interface — Cilium in XDP mode, a hosting
provider's own filter, another eBPF tool — Lorica cannot attach alongside it. It refuses, and
it names what it found rather than falling back quietly.

Lorica also requires **native** attach. If the driver cannot take the program natively, the
kernel offers a generic-mode fallback that runs much later in the stack; Lorica does not use
it, because a program in generic mode measures something different from what it claims to
measure. `ip -d link show <iface>` must report `xdp`; `xdpgeneric` is a refusal.

## 4. Red Hat supports XDP only through libxdp; Lorica loads with aya

Stated here rather than left for you to discover during an incident. Red Hat's support policy
for XDP covers programs loaded via `libxdp`. Lorica uses [aya](https://aya-rs.dev), a pure-Rust
loader. On a RHEL-family distribution this puts Lorica outside the supported path, whatever it
does technically.

This is a supportability fact, not a defect claim in either direction.

## 5. `panic = "abort"`: the agent dies rather than continuing wrong

The release profile sets `panic = "abort"`. A bug that would unwind instead terminates the
process. This is a deliberate failure model, and it only works because of the next paragraph.

**Every entry the detection writes carries a deadline**, compared against the kernel clock at
lookup. If the agent dies, nothing cleans up and nothing has to: the entries expire on their
own. `lorica-ctl rules` shows the deadline of every active entry, and no active rule can exist
without one — that is a tested assertion, not a convention, and it is the guard against an
accidental permanent blackhole.

What you lose when the agent dies is detection and reporting, not traffic.

## 6. Out of the box it protects nothing, and three wires are still open

Two different statements live under this heading. The first is a **choice**: observation is the
default. The second is a **state**: parts of the enforcement half are not connected yet. Both are
true today and only the first is permanent.

### The choice

`--mode observe` is the default. The agent reads the counters, runs the detection ladder, reports
the decision it would have taken, and does not touch the kernel's list. That is the point of the
default, and it is why this repository could be opened: a tool that watches and reports cannot
create the destructive false positive.

To arm it: `--mode armed` on the command line, or `lorica-ctl arm` on a running agent. Arming
also needs at least one counter slot above the named counters (`--counters 4096`), and Lorica
refuses to arm without one rather than charging its own refusals to a stage counter and reading
them back as evidence. `lorica-ctl status` reports `armable` beside `mode` so you do not have to
try the command to find out.

### The state — what a running agent will and will not do

**It drops, on the packet path, with no configuration:** truncated frames, over-deep
encapsulation, incoherent IP or L4 length, impossible TCP flag combinations, IP options, and
non-initial fragments. That is a real class of traffic and it is the whole of what is enforced.

**Two things are still not wired, and one of them is the interesting half of the product:**

1. **The reverse-path check counts but does not enforce.** Its bit is the loader's and not the
   operator's, because whether a strict check discriminates anything is a property of the
   routing table and not a preference: on a host with a default route it would refuse nothing
   and cost every packet a `bpf_fib_lookup`. The evaluator that reads that criterion exists and
   is tested, and the agent never runs it, so the bit stays clear on every load. There is no
   flag for it and there should not be one — what is missing is the agent asking the question.

2. **The detection ladder cannot reach a rung that refuses packets.** Rungs 3 and above need a
   key whose own counter slot is rising, and rungs 5 and 6 need the bucket bank; the tick
   publishes the 34 named counters and neither of those two inputs. Armed or not, the ladder
   tops out at rung 1 and `written` stays at zero. **This is the one that matters**: it is the
   difference between a filter you aim and a filter that aims itself.

**What is wired, and was not when this page was first written:**

- **The policy word is yours.** `--policy enforce-signatures,enforce-buckets`, or the
  `[settings]` block of a configuration file. Ten amplification vectors and the leaky-bucket
  bank refuse traffic when you arm them, and count it when you do not.
- **The operator blocklist loads.** `--config PATH` compiles a file and publishes it before the
  program is attached. An IPv4 `deny` with no scope and no TTL goes into the two flat tables —
  one memory access an address, and no kernel memory per entry — and everything else goes into
  the trie. Which table a rule lands in is decided by the rule, never written in the file, and
  the counters are the same either way.
- **There is a configuration file**, and `examples/lorica.toml` is an annotated one that
  compiles as it stands. `lorica-ctl reload` still refuses: the file is read once, at startup.

So a deployment today refuses what you named and nothing it worked out for itself. The two wires
above are tracked on the [wiki status page](https://github.com/lorica-labs/lorica/wiki/Status).

## 7. Kernel capabilities: what an older kernel costs you

Seven capabilities are detected at startup, by kernel symbol where a symbol distinguishes them
and by release number where none does. `lorica-ctl status` reports what your kernel gives you.

| capability | since | without it |
|---|---|---|
| `cpumap_gro` | 6.15 | no cpumap: scrubbing stays on the ingress core |
| `bpf_qdisc` | 6.16 | rung 1 stays an observed no-op — marked, never enforced |
| `bpf_xdp_pull_data` | 6.18 | the same bounded parsing depth costs more to reach |
| `multi_byte_meta` | 6.19 | the verdict stays in the dataplane instead of riding to the stack |
| `rehash_flows` | 6.19 | manual RSS tuning against a flood that saturates one RX queue |
| `bpf_arena` | 6.9 | batch reads and a hand-sharded array — agent-side cost either way |
| `queue_leasing` | 7.1 | the dataplane runs as a host DaemonSet rather than in the container |

**The invariant that makes this table safe to read: an absent capability changes cost or
jitter, never a verdict.** The clearest case is `bpf_qdisc`. Without it, rung 1 is a no-op
that is counted rather than a rung that is skipped — because skipping it would make identical
traffic reach a *different* rung on two hosts at the same instant, which is a worse thing to
own than a rung that marks nothing.

Rung 1 deserves a second sentence anyway, capability or not: scheduling lives on the egress
path, and a host can only schedule **its own egress**, not the congested upstream link a pulse
wave is filling. In front of a fleet, as a gateway, rung 1 is fully useful. On the host it
protects, it is essentially observational.

## 8. Blocklist limits

The operator blocklist is two flat tables, 20 MiB fixed regardless of how many entries you
load. That buys a lookup cost that does not grow with your list, and it comes with shapes it
cannot hold:

- **Prefixes at most /24 are free** — all 16.7 million of them fit in 4 MiB, whatever you
  configure.
- **Longer prefixes cost keys, and there are about 1.05 million of them.** A `/25` is 128 keys,
  a `/32` is one. Past the ceiling the builder **refuses the snapshot and keeps the previous
  one** rather than truncating your rules. A truncated rule is a rule that half applies, and
  nothing in your configuration file would show which half.
- **One exception inside a short prefix costs a whole block.** Denying `10.0.0.0/8` while
  allowing `10.1.2.3/32` costs 256 keys, not one: marking that `/24` as "consult the table"
  removes the `/8`'s answer for the other 255 addresses, so they are written out explicitly.
  Correct, and expensive if you have thousands of such exceptions.
- **A prefix at most /24 can only deny or allow.** Two bits hold four codes and all four are
  taken. Rate-limiting or marking a `/16` is refused at load time rather than rounded to the
  nearest verdict, which would silently change what your rule does.
- **IPv6 does not use the flat tables.** It goes to the trie, which is still there and whose
  cost does grow with its contents.

Two things this page will update when they are resolved:

- **Publishing a new snapshot is not atomic.** The two tables are written in one syscall, but
  the packet path can read that 20 MiB copy while it is in flight. We have not yet established
  whether the kernel's copy gives eight-byte granularity, which would settle it, or whether
  swapping the attached program is the answer.
- **A flat-table hit is not attributable to one rule of your file.** It is counted — both
  halves of stage 3 bump `lorica_lpm_drop_hit` and `lorica_lpm_allow_exit`, so the number is
  right whichever table answered — but a flat slot is eight bytes with nowhere to put a counter
  index. Per-entry attribution stays with the trie, and it was never available at the size the
  flat tables exist for: a million entries is a million slots times every processor.

## 9. `/metrics` will never carry a label an attacker chooses

Not a limitation so much as a refusal you should know about, because it is why you cannot get
per-source metrics out of Lorica.

No label takes a value chosen by whoever sends the packet — no source IP, no source port, no
flow id, no observed ASN. An adversary varying their sources would otherwise inflate your
time-series database at will, which turns your monitoring into an amplifier. The number of
series Lorica exposes is fixed at compile time and there is a test that counts them and fails
if a label is added.

`/metrics` binds to loopback by default. Exposing it off-host is an address you type.

## 10. What Lorica is not

It is not DPDK. It is not a programmable switch. It makes **no promise in Mpps** — see §2 for
why it could not honour one honestly even if it wanted to.

The promise is narrower and testable: *Lorica absorbs the line your host sells you, and tells
you what it measures at your place.*

---

## The lab these numbers come from

Proxmox on a Dell R730, Xeon E5-2683 v3 (Haswell). The measured guest runs 6.8.0-138 with 4
pinned vCPUs at 1.875–1.953 GHz **with no turbo**, and the guest has no `cpufreq` at all — the
`cpu MHz` in `/proc/cpuinfo` there is the nominal TSC cadence, not the core clock.

**Why this page quotes cycles for anything on the packet path, and nanoseconds only elsewhere.**
Per-packet timings come from the `duration` field of `BPF_PROG_TEST_RUN`, and that field was
measured against the CPU time of the same work: 128 ns of `duration` for 262 ns of task-clock,
a factor of 2.06, stable across three levels and three campaigns. Ratios and stage-to-stage
differences survive that; absolute nanoseconds do not, and the frequency cannot be pinned from
inside the guest to convert them. So the unit of record for the packet path is the cycle. The
userspace numbers on this page — throughput, p99, RSS — do not come through that field and are
not affected.
