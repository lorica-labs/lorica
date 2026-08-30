# Lorica benchmarks — reproduction recipe

This is a recipe, not documentation: what you need, in what order, how long it takes, and for every
published number the line `result → script → raw data → environment`. Everything here runs from this
repository alone. The analysis reports that read these numbers live outside the repository and are not
needed to reproduce them.

## What you need

Three machines, isolated from any production network:

| Role | This lab | Requirements |
|---|---|---|
| target | VM 901 | Linux 6.8, virtio-net, hardware PMU, `bpftool`, `fio`, `iperf3`, `jq`, `ethtool` |
| generator | VM 902 | `trafgen` (netsniff-ng), `iperf3` |
| build | VM 900 | Rust stable + `x86_64-unknown-linux-musl`, `clang`, `make` |

The target and generator share a test link (here `10.90.1.1` and `10.90.1.2` on a bridge with no path
to any other network). The build host never measures. See `agent:docs/runbook-creation-vm.md` for the
lab itself; this recipe assumes the three machines exist and reach each other.

A static probe binary must be present on the target and generator at `/tmp/latency-probe`. Build it on
the build host and copy it:

```
cd bench/latency-probe
cargo build --release --target x86_64-unknown-linux-musl
# copy target/x86_64-unknown-linux-musl/release/latency-probe to /tmp/latency-probe on 901 and 902
```

A static musl build is required because the build host's glibc is newer than the target's; a dynamic
binary will not start on the target.

The eBPF fixtures must be built on the build host and copied to the target under `bench/progs/`:

```
make -C bench/progs        # produces xdp_pass.o xdp_drop.o xdp_portdrop.o xdp_reflect.o and bench/data/udp64.bin
```

## Order, and time

1. **Conformance** (~1 min each). Nothing runs until this passes on the target.

   ```
   scripts/bench-env.sh
   scripts/lab/check-env.sh && echo CONFORME
   ```

   `check-env.sh` refuses to measure on a machine whose state would not match the results; it names the
   fix for each control. Re-run `bench-env.sh` if THP or the governor has drifted.

2. **Tool ceiling** (~8 min). Run on the target; it drives the generator over SSH.

   ```
   scripts/lab/bridge-ceiling.sh --out bench/results/bridge-ceiling --gen-host <gen-ssh> --dst-ip <target-test-ip>
   ```

   This number bounds every attack axis below. Read it before trusting any pps figure.

3. **Machine floor** (~2 min). The cost of an XDP program that does nothing, and of turning on the
   kernel's own accounting.

   ```
   scripts/lab/measure-floor.sh --out bench/results
   ```

The campaigns below run one at a time on the target; two at once pollute each other.

4. **Attach tax** (~5 min):
   `scripts/lab/measure-attach-tax.sh --gen-host <gen-ssh> --peer-ip <gen-test-ip> --self-ip <target-test-ip> --out bench/results/attach-tax`
5. **p99 under flood** (~15 min):
   `scripts/lab/measure-p99.sh --gen-host <gen-ssh> --self-ip <target-test-ip> --ceiling <pps from step 2> --out bench/results/p99`
6. **Hot attach** (~4 min):
   `scripts/lab/measure-hot-attach.sh --gen-host <gen-ssh> --self-ip <target-test-ip> --peer-ip <gen-test-ip> --out bench/results/hot-attach`
7. **XDP_TX ceiling** (~5 min):
   `scripts/lab/measure-xdp-tx.sh --gen-host <gen-ssh> --self-ip <target-test-ip> --out bench/results/xdp-tx`
8. **Storage** (~2 min):
   `scripts/lab/measure-storage.sh --out bench/results/storage`

Every script writes a timestamped environment record next to its result via `scripts/lab/capture-env.sh`.

## Result → script → raw data → environment

| Published number | Script | Raw data | Environment |
|---|---|---|---|
| Tool ceiling (~270–295 kpps) | `scripts/lab/bridge-ceiling.sh` | `bench/results/bridge-ceiling/bridge-ceiling.csv` | `bench/results/bridge-ceiling/env-*.txt` |
| XDP floor (15 ns) + instrumentation cost (64 ns) | `scripts/lab/measure-floor.sh` | `bench/results/floor-*.json` | `bench/results/env-*.txt` |
| Attach tax (−58 % RX) | `scripts/lab/measure-attach-tax.sh` | `bench/results/attach-tax/attach-tax.csv`, `offloads.diff` | `bench/results/attach-tax/env-*.txt` |
| p99 none/nft/xdp | `scripts/lab/measure-p99.sh` | `bench/results/p99/p99.csv` | `bench/results/p99/env-*.txt` |
| Hot attach outage (<7 ms) | `scripts/lab/measure-hot-attach.sh` | `bench/results/hot-attach/hot-attach.csv` + control CSVs | `bench/results/hot-attach/env-*.txt` |
| XDP_TX ceiling (≥290 kpps) | `scripts/lab/measure-xdp-tx.sh` | `bench/results/xdp-tx/xdp-tx.csv` | `bench/results/xdp-tx/env-*.txt` |
| fsync p99 (6.26 ms), cold read (1.4 GB/s) | `scripts/lab/measure-storage.sh` | `bench/results/storage/storage.json`, `fsync-fio.json` | `bench/results/storage/env-*.txt` |
| Instructions per packet, per stage | `scripts/lab/measure-stage-cost.sh` | `bench/results/stage-cost-*/stage-cost.csv` | `bench/results/stage-cost-*/env-*.txt` |

`bench/results/INDEX.md` restates this mapping for the data already in the tree.

## Two instruments, and neither answers the other's question

`measure-stage-cost.sh` measures what a packet **executes**, by cutting the pipeline after
stage *k* and differencing two whole-path readings. `EBPF_EXTRA=feature` builds the measured
object with an extra eBPF feature, so a variant behind a flag is measured with the same
instrument and in the same session as its baseline — the only way a difference between two
builds is about the code rather than about two afternoons.

`scripts/lab/attribute-instructions.py` measures what is **present**, by source region, out of
`llvm-objdump --line-numbers` and the DWARF the release profile already emits. No kernel, no
target, no privileges.

**The first is the wrong instrument inside a stage**, and this project learned that by
publishing a wrong figure. A cut level is a branch: work whose result is dead on the cut path
may be sunk below it and charged to the next level, and that does not show up in a check that
the levels sum to the whole, because moving cost between levels does not change the total. Use
the sweep between stages and the attribution inside one.

**The second cannot tell you what a packet runs.** A fifth of the entry point is IPv6 code an
IPv4 packet executes none of. Read a region's figure as an upper bound.

One caveat that cost an afternoon: `--ebpf-features` does **not** reach `jited_size`.
`build_ebpf` builds the object that ships without any feature, by design, and the size test
reads that one.

## What is excluded, and why the numbers are honest

- The lab tops out near 290 kpps: above it the figures describe the hypervisor, not Lorica. Every pps
  result cites this ceiling.
- virtio has no hardware packet timestamping; latency is TSC plus kernel software timestamps, declared
  as a validity threat in each report.
- Live migration and a loaded host are excluded by protocol: run on a quiet host, and `check-env.sh`
  refuses if guest steal time exceeds its threshold.
- No mean is reported for any latency; percentiles only.
