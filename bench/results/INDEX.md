# Results index

Each row maps a published number to the script that produced it, the raw data in this tree, and the
environment captured at run time. Measured 22 August 2026 on VM 901 (Ubuntu 24.04 GA 6.8.0-138,
E5-2683 v3, virtio-net, 4 pinned vCPU). The recipe to regenerate any of these is `bench/README.md`.

| Number | Value | Script | Raw data | Environment |
|---|---|---|---|---|
| Tool ceiling | ~270–295 kpps delivered | `scripts/lab/bridge-ceiling.sh` | `bridge-ceiling/bridge-ceiling.csv`, `bridge-ceiling/knee.txt` | `bridge-ceiling/env-20260822T095550Z.txt` |
| XDP floor | 15 ns/run | `scripts/lab/measure-floor.sh` | `floor-20260822T093726Z.json` | `env-20260822T093726Z.txt` |
| bpf_stats cost | +64 ns/run | `scripts/lab/measure-floor.sh` | `floor-20260822T093726Z.json` | `env-20260822T093726Z.txt` |
| JITed size (xdp_pass) | 20 bytes | `scripts/lab/measure-floor.sh` | `floor-20260822T093726Z.json` | `env-20260822T093726Z.txt` |
| Attach tax, RX throughput | 14.0 → 5.8 Gbps (−58 %) | `scripts/lab/measure-attach-tax.sh` | `attach-tax/attach-tax.csv` | `attach-tax/env-20260822T102205Z.txt` |
| Attach tax, offload diff | empty (no offload cleared) | `scripts/lab/measure-attach-tax.sh` | `attach-tax/offloads.diff` | `attach-tax/env-20260822T102205Z.txt` |
| p99 under flood, none/nft/xdp | ~450 µs, no separation | `scripts/lab/measure-p99.sh` | `p99/p99.csv` | `p99/env-20260822T102936Z.txt` |
| Hot attach outage | < 7 ms, no broken connections | `scripts/lab/measure-hot-attach.sh` | `hot-attach/hot-attach.csv`, `hot-attach/*-gaps.csv` | `hot-attach/env-20260822T110140Z.txt` |
| XDP_TX ceiling | ≥ 290 kpps, ratio ~1.0 | `scripts/lab/measure-xdp-tx.sh` | `xdp-tx/xdp-tx.csv` | `xdp-tx/env-20260822T111604Z.txt` |
| fsync latency | p50 3.16 ms, p99 6.26 ms | `scripts/lab/measure-storage.sh` | `storage/storage.json`, `storage/fsync-fio.json` | `storage/env-20260822T111941Z.txt` |
| Cold read | 1.4 GB/s (host cache, see report) | `scripts/lab/measure-storage.sh` | `storage/storage.json` | `storage/env-20260822T111941Z.txt` |
| Per-packet cost, parsing, before the fixes | 148 ns (61 % of the total) | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260822T211828Z.txt` |
| Per-packet cost, parsing, after | 35 ns | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T001233Z.txt` |
| Per-packet cost, one clock read, before | 54 ns | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260822T211828Z.txt` |
| Per-packet cost, one clock read, after | 4 ns | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T001233Z.txt` |
| Per-packet cost, unified list lookup | 22 ns, the dominant item now | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T001233Z.txt` |
| Per-packet cost, whole pipeline, before | 243 ns, spread 15 ns | `scripts/lab/measure-stage-cost.sh` | `stage-cost/sweep-*.txt` | `stage-cost/env-20260822T211828Z.txt` |
| Per-packet cost, whole pipeline, after | 70 ns, spread 3 ns | `scripts/lab/measure-stage-cost.sh` | `stage-cost/sweep-*.txt` | `stage-cost/env-20260823T001233Z.txt` |
| Campaign-to-campaign spread, before the fixes | 236 to 288 ns (11 %) | `scripts/lab/measure-stage-cost.sh` | `stage-cost/sweep-*.txt` | `stage-cost/env-20260822T211828Z.txt` |
| Campaign-to-campaign spread, after | 70, 70, 71 ns (1.4 %) | `scripts/lab/measure-stage-cost.sh` | `stage-cost/sweep-*.txt` | `stage-cost/env-20260823T001233Z.txt` |
| Assertion 3 quantity, instructions per packet | 748.4 to 749.6 (0.16 %), ceiling 765 | `scripts/lab/measure-stage-cost.sh --max-instructions` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T001233Z.txt` |
| BPF ISA level, JITed size | 7063 bytes at v1, 6707 at v3 (-5.0 %) | `--test jited_size` | in the test output | `stage-cost/env-20260823T001233Z.txt` |
| BPF ISA level, instructions per packet | 983 at v1, 944 at v3, 940 at v4 | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T001233Z.txt` |
| BPF ISA level, 32-bit compares | 0 of 203 at v1, 162 of 203 at v3 | `llvm-objdump -d` on the object | one command, not retained | - |
| Bank layout, per-CPU, cost | 85 ns, scales 3.83x on 4 cores | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-contention.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| Bank layout, shared unlocked, cost | 84 ns, 250 ns under a concentrated attack | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-contention.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| Bank layout, shared locked, cost | 107 ns, 1988 ns and 0.24x under a concentrated attack | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-contention.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| Per-CPU dilution | 0.2500 of the offered traffic on 4 cores | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-leak.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| Shared unlocked bank, lost updates | charges 0.3819, so 2.62x offered | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-leak.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| Shared counter, atomic add | 24 ns alone, 156 ns and 0.87x on 4 cores | `scripts/lab/measure-bucket-contention.sh` | `bucket-contention/bucket-contention.csv` | `bucket-contention/env-20260822T215728Z.txt` |
| bpf_fib_lookup vs LPM lookup | 48 ns vs 9 ns above the floor, ratio 5.3 | `scripts/lab/measure-fib-vs-lpm.sh` | `fib-vs-lpm/fib-vs-lpm.csv` | `fib-vs-lpm/env-20260822T220149Z.txt` |
| Unified list, shallow miss | 251-262 ns, flat from 1 to 1M entries | `--test measure_lpm_depth` | `lpm-depth/lpm-depth.csv` | `lpm-depth/env-20260822T231554Z.txt` |
| Unified list, deep miss | 330-343 ns at full trie depth, size-independent | `--test measure_lpm_depth` | `lpm-depth/lpm-depth.csv` | `lpm-depth/env-20260822T231554Z.txt` |
| Unified list, hit | 266 ns at 1 entry to 581 ns at 1M | `--test measure_lpm_depth` | `lpm-depth/lpm-depth.csv` | `lpm-depth/env-20260822T231554Z.txt` |

The `xdp:xdp_exception` counter is zero on every retained run; any run with a nonzero value was
discarded, not annotated.

## Phase 1, measured 23 August 2026 on the same VM 901

**Read this before any row above or below.** Every nanosecond in this file comes from the `duration`
field of `BPF_PROG_TEST_RUN`, and that field was measured against the CPU time of the same work:
**128 ns of `duration` for 262 ns of task-clock**, a stable factor of **2.06** over three levels and
three campaigns. Ratios and stage-to-stage differences are sound; absolutes are about half the CPU
time. Cycles, x86 instructions and task-clock agree with each other and put this host at
**1.875–1.953 GHz with no turbo** — there is no `cpufreq` in the guest and `/proc/cpuinfo` reports the
nominal TSC rate. **Cycles per packet is the figure to quote**, at 0.4 % reproducibility against 2.4 %
for the nanoseconds.

| Number | Value | Script | Raw data | Environment |
|---|---|---|---|---|
| Effective frequency, no turbo | 1.875–1.953 GHz, from `cycles / task-clock` | `perf stat -e cycles,instructions,task-clock` | one command, not retained | `stage-cost/env-20260823T170211Z.txt` |
| `duration` against CPU time | 128 ns reported for 262 ns of task-clock, factor 2.06 | idem | idem | idem |
| Per-packet cost, whole pipeline | **533 cycles**, 1298 x86 instructions, 131 ns of `duration` | `scripts/lab/measure-stage-cost.sh` | `stage-cost/stage-cost.csv` | `stage-cost/env-20260823T170211Z.txt` |
| Assertion 3, three ceilings armed | 1325 instructions, 545 cycles, 144 ns | `measure-stage-cost.sh --max-instructions --max-cycles --max-ns` | `stage-cost/stage-cost.csv` | idem |
| Stage 5 uRPF, armed | **+140 ns**, not the 48 ns a C fixture predicted | `--test per_packet_cost` | in the test output | idem |
| Stage 6 signatures, whole catalogue vs none | 123 ns vs 99 ns; 7556 vs 6136 JITed | `--test per_packet_cost`, `--test signature_pruning` | in the test output | idem |
| Stage 7 bank, division removed | −11 ns interleaved; IPC at that level stops falling, 1.986 → 2.077 | `--test per_packet_cost` | `stage-cost/stage-cost.csv` | idem |
| Bucket index, SipHash-2-4 → multiply-shift | **−89 ns**, −1290 JITed bytes | `--test per_packet_cost`, `--test jited_size` | in the test output | idem |
| JITed size, whole catalogue armed | 7577 bytes, ceiling 8330 | `--test jited_size` | in the test output | idem |
| **Unified list, realistic absent key** | **414 ns at 1M entries** (p99 440), 27 bits shared | `--test measure_lpm_depth` | in the test output | idem |
| Unified list, absent key outside the dense region | 109–117 ns, flat from 1 to 1M — **the old probe** | `--test measure_lpm_depth` | in the test output | idem |
| Unified list, hit | 89 ns at 1 entry to 384 ns at 1M | `--test measure_lpm_depth` | in the test output | idem |
| Bank leak, uniform distribution | **0.93–0.99 at every core count and window** — no leak | `--test stage_bucket --exact` | `bank-surface/surface.log` | idem |
| Bank leak, concentrated, window as shipped | 1.42 at 4 cores (1.21–1.46 over 9 samples) | idem | `bank-surface/surface.log` | idem |
| Bank leak, concentrated, window widened | 1.94 at 64 dead reads, 3.73 at 1024 | idem | `bank-surface/surface.log` | idem |
| Enforcement at one thread, every arm | 0.93–0.99 of the configured rate | idem | `bank-surface/surface.log` | idem |
| Zero false positives on the wire | 44 sent, 45 arrived, 0 drops, 0 `xdp_exception` | `scripts/lab/wire-trace.sh` | `wire-trace/wire-trace.txt` | `wire-trace/env-20260823T164106Z.txt` |
| Keyed index, chosen collisions | chi-square 76.8 against a null-derived threshold of 1294.4 | `--test keyed_index` | in the test output | - |

### Rows above this section that phase 1 superseded

| Row | Was | Now |
|---|---|---|
| Per-packet cost, whole pipeline, after | 70 ns, three stages still stubs | 131 ns of `duration` with seven stages, **533 cycles** |
| Per-packet cost, unified list lookup | 22 ns, "the dominant item now" | still dominant, and **414 ns** with a realistic key at 1M entries |
| Assertion 3 quantity | 748.4–749.6, ceiling 765 | 1298.3, ceiling 1325, plus a cycle and a nanosecond ceiling |
| BPF ISA level, instructions per packet | 944 at v3 | 1298 with seven stages |
| Shared unlocked bank, lost updates | "charges 0.3819, so 2.62x offered" | that fixture had four cores doing nothing else; the real stage leaks **nothing** under a uniform distribution |
| bpf_fib_lookup vs LPM lookup | 48 ns, ratio 5.3 | the fixture was low by about three: **+140 ns** on the real stage |
| Unified list, shallow miss / deep miss / hit | 251–581 ns, whole pipelines at a ~250 ns base | re-measured on the seven-stage pipeline; the shallow-miss flatness was **the probe key** |
