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
