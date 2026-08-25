# Lorica

An XDP DDoS filter for one host, written in Rust, that **observes by default and refuses
nothing until you tell it to**.

The promise, narrow on purpose: *Lorica absorbs the line your host sells you, and tells you
what it measures at your place.* Not Mpps. Not a programmable switch. Not DPDK.

**Read [docs/limits.md](docs/limits.md) first.** It has the costs, the shapes this design
cannot hold, and the numbers we do not have. It is not an appendix — attaching an XDP program
to virtio-net costs 58 % of receive throughput on this lab, permanently, whether or not anyone
is attacking you, and you should know that before you install anything.

---

## What it does

Seven stages on the packet path, in the kernel, and one agent in userspace that watches them
and decides.

The stages parse, check coherence, consult the source list, handle fragments, optionally check
the reverse path, match a catalogue of known amplification vectors, and charge a leaky-bucket
bank. The agent reads their counters on a tick, decides a rung on a seven-step ladder, and — if
you have armed it — writes one exact key into the kernel's list with a deadline on it.

## The one invariant worth reading before the code

**A drop can never rest on state another source can move.**

With 1 024 buckets and any realistic number of active sources, two sources necessarily share a
bucket. No quality of hashing changes that; it is the pigeonhole principle. So buckets and
probabilistic signatures produce **candidates**, and every drop is confirmed by an exact key, by
a packet that is objectively invalid, or by a bit of the policy word.

This is not a comment, it is a type: a decision that refuses traffic cannot be constructed
without naming the exact key it refuses, and the constructor returns `None` instead. There is a
test that tries it from outside the crate and one that tries it from the agent, and a third
that shows the whole mechanism disarmed and re-armed with the classifier still counting.

## Observation is the default, and that is the point

Out of the box, Lorica **protects nothing**. It watches, counts and reports. The ladder climbs,
the metrics move, the kernel's list does not.

```
lorica-ctl status | jq .mode     # "observe"
```

A tool that observes cannot create the destructive false positive, which is why this repository
could be opened while the enforcement half is still young. Arming is one word — `--mode armed`,
or `mode = "armed"` in the configuration — and [docs/limits.md §6](docs/limits.md) says what
changes when you type it.

## Metrics that an attacker cannot inflate

`/metrics` carries **no label whose value is chosen by whoever sends the packet**. No source IP,
no source port, no flow id, no observed ASN. An adversary varying their sources would otherwise
grow your time-series database at will, turning your monitoring into an amplifier and your
dashboards into the second casualty of the attack.

The rule is testable and it is tested: the number of series is fixed at compile time, a test
counts what the registry actually renders and fails past a checked-in ceiling, and a second test
fails if any label name from a blacklist appears. Endpoint binds to loopback by default.

Three projects reached this architecture independently, which is the strongest argument for it:
**FastNetMon** disables per-host counters by default and pre-computes a top-10 per second,
moving to ClickHouse past 50 000 hosts; **Cloudflare** ships `sample_limit = 200` as a default;
**Cilium/Hubble** removed `source_ip` from its labels. If you have hit this wall yourself, you
already know why.

## Install

[docs/install.md](docs/install.md). Short version: a recent kernel, `CAP_BPF` and
`CAP_NET_ADMIN`, an eBPF object built by the nightly toolchain, and native XDP attach — if
`ip -d link` says `xdpgeneric`, Lorica refuses rather than measuring something else.

## Layout

| crate | what it is |
|---|---|
| `lorica-common` | every type that crosses the kernel boundary, and all per-packet arithmetic. `no_std`, no dependency |
| `lorica-ebpf` | the XDP program. A **separate workspace**: nightly, `-Z build-std=core`, BPF ISA v3 |
| `lorica-dataplane` | loading, attaching, map access, capability detection, and the kernel tests |
| `lorica-policy` | the operator's configuration compiled into what the program reads |
| `lorica-detect` | snapshots to rungs: two cadences, hysteresis, descent, cardinality. No I/O at all |
| `lorica-escalate` | the `Escalator` trait and the webhook behind it, with the guards in front |
| `loricad` | the agent |
| `lorica-ctl` | a thin client. One text line over a Unix socket, prints the JSON. **Zero dependencies** |
| `lorica-export` | conversions kept off the agent's startup path |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). One convention that is not written anywhere else and that
every reviewer here will ask for: **each module opens on a `//!` that justifies the choice made
and names the alternative that was rejected, with the number that rejected it.** If you cannot
name what you did not do, the decision has not been made yet.

## Security

[SECURITY.md](SECURITY.md), which also carries the false-positive report template. The first
question it asks is whether you were running in `observe` or `armed`, because in `observe`
nothing was refused and a "false positive" is then something else.

## Licence

Dual-licensed under Apache-2.0 or MIT, at your option. See [LICENSE-APACHE](LICENSE-APACHE) and
[LICENSE-MIT](LICENSE-MIT).
