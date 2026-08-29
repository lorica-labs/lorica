# Lorica

An XDP packet filter for a single Linux host, written in Rust. It measures what reaches your
machine, and refuses nothing until you tell it to.

```
┌── kernel ─────────────────────────────────────────┐
│  XDP  →  parse → coherence → list → fragments     │
│          → reverse path → signatures → buckets    │
│                    ↓ 34 counters                  │
└────────────────────┼──────────────────────────────┘
                     ↓  mmap, no syscall
        agent  →  ladder  →  /metrics, journal, socket
```

**Read [docs/limits.md](docs/limits.md) before you install anything.** Attaching an XDP program
to virtio-net costs 58 % of receive throughput on our lab, permanently, whether or not anyone is
attacking you.

---

## Status: what runs today

This repository is open while the enforcement half is still being built. The table is the whole
truth, and the [wiki](https://github.com/lorica-labs/lorica/wiki/Status) carries the detail.

| | |
|---|---|
| ✅ **Drops** malformed and impossible packets: truncated, bad IP/L4 length, impossible TCP flags, IP options, over-deep encapsulation, non-initial fragments | on the packet path, no configuration |
| ✅ **Counts** everything else through 34 named counters, including all ten amplification signatures and every over-budget packet | 1 480 instructions/packet, measured |
| ✅ **Reports** through Prometheus, a 1 Hz journal and a Unix control socket | no label an attacker can choose |
| ⚠️ **Does not enforce** signatures, leaky buckets or reverse-path checks | the policy word is compiled in and there is no flag to change it |
| ⚠️ **Does not load** an operator blocklist | the compiler exists, the agent does not call it |
| ⚠️ **Does not write** a refusal into the kernel | the detection ladder tops out at rung 1 of 7 |

So: **Lorica today is an instrument, not yet a mitigation.** If you deploy it and an attack
arrives, it will show you the attack in detail and drop only the malformed part of it.

## Quick start

```bash
# 1. build (userspace stable, eBPF nightly — two toolchains, see docs/install.md)
cargo build --release --workspace
cd crates/lorica-ebpf && cargo +nightly build --release && cd ../..

# 2. run, detached — loads and verifies the program, touches no packet
sudo ./target/release/loricad \
     --object crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf

# 3. ask it what it is doing
sudo ./target/release/lorica-ctl status
curl -s http://127.0.0.1:9090/metrics | grep ^lorica_
```

Add `--iface eth0` to put it in the packet path. Read
[the attach tax](docs/limits.md#1-attaching-an-xdp-program-to-virtio-net-costs-throughput-permanently)
first — it is the single most expensive decision in this tool.

Full procedure, options and failure modes: **[docs/install.md](docs/install.md)**.

## Documentation

Read in this order.

| | |
|---|---|
| [docs/install.md](docs/install.md) | prerequisites, build, run, every option and every startup refusal |
| [docs/usage.md](docs/usage.md) | day two: reading the counters, the control socket, the metrics, arming |
| [docs/limits.md](docs/limits.md) | what this costs, what it cannot hold, and the numbers we do not have |
| [docs/architecture.md](docs/architecture.md) | how it works and why it is shaped this way — start here to read the code |
| [bench/README.md](bench/README.md) | how to reproduce every published number, on three machines |
| [bench/results/INDEX.md](bench/results/INDEX.md) | every number, mapped to the script, the raw data and the captured environment |
| [wiki](https://github.com/lorica-labs/lorica/wiki) | the response ladder, deployment profiles, measurement method, status |

## Two rules the design rests on

**A drop can never rest on state another source can move.** Two sources necessarily share a
leaky bucket — pigeonhole, not hashing quality — so buckets and signatures produce *candidates*.
Every refusal is confirmed by an exact key or by an objectively invalid packet, and that is a
type: a decision refusing traffic cannot be constructed without naming the key it refuses.

**No metric carries a label an attacker chooses.** No source IP, port, flow id or ASN — otherwise
an adversary rotating sources grows your TSDB at will. The series count is fixed at compile time
and a test fails past a checked-in ceiling.

Both are argued, with the measurement behind them, in
[docs/architecture.md](docs/architecture.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). One convention worth stating here, because every reviewer
will ask for it: **each module opens on a `//!` that justifies the choice made and names the
alternative that was rejected, with the number that rejected it.** If you cannot name what you
did not do, the decision has not been made yet.

## Security

[SECURITY.md](SECURITY.md), which also carries the false-positive report template.

## Licence

Dual-licensed under Apache-2.0 or MIT, at your option.
See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
