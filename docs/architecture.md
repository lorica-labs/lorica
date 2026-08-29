# Architecture

How Lorica is shaped, and why. This is the map you read before the code: it names each piece,
the constraint that forced it, and the file where the argument is actually made. Every module in
this tree opens on a `//!` that justifies its choice and names the alternative that was rejected,
with the number that rejected it — this page points at those headers rather than restating them,
because a restatement is a copy that goes stale.

The numbers below were measured on the lab described in
[bench/README.md](../bench/README.md); every one of them is traceable through
[bench/results/INDEX.md](../bench/results/INDEX.md).

---

## 1. Two halves, one boundary

```
kernel                                    userspace
──────────────────────────────────        ─────────────────────────────────
XDP program                               agent (loricad)
  7 stages, no loop, no allocation          10 Hz tick
  writes 34 counters + per-entry slots      reads them, decides, reports
                    │                                    │
                    └────── shared maps ─────────────────┘
                       COUNTERS   flat array, mmapped
                       UNIFIED_LIST   LPM trie, written by the agent
                       BUCKET_BANK    leaky buckets, written by the program
                       .bss           two flat blocklist tables, 20 MiB
```

The boundary is deliberate and asymmetric. **The kernel decides nothing it cannot decide from the
packet in front of it**; everything requiring history, aggregation or policy happens in the agent
and comes back as a map write. That is what keeps the packet path branch-bounded and
verifier-friendly, and it is what makes the agent's cost a separate, measurable budget rather
than a tax on every packet.

`lorica-common` is the seam: `no_std`, no dependency, compiled identically into the eBPF object
and into the agent, so a layout the two sides could disagree about does not exist. Its
`const _: () = assert!(…)` lines fail the build of both the moment one drifts.

---

## 2. The packet path

Nine cut points, seven stages, in `crates/lorica-ebpf/src/stage/mod.rs`:

| # | stage | what it decides | enforced today |
|---|---|---|---|
| — | parse | truncation, encapsulation depth, IP/L4 length coherence, TCP flag validity, IP options | **yes**, unconditionally |
| 2 | ICMP | echo and non-echo policy; path-MTU and neighbour discovery always pass | behind a policy bit |
| 3 | source list | two flat tables, then the LPM trie. Operator verdicts and detection entries | **yes** — but both structures are empty until something loads them |
| 4 | fragments | first fragment passes and is counted; later fragments have no transport header | **yes**, drops later fragments |
| 5 | reverse path | `bpf_fib_lookup` against the ingress interface | behind a policy bit |
| 6 | signatures | ten amplification and coherence vectors | counted; enforcement behind a policy bit |
| 7 | buckets | leaky-bucket bank, 1 024 buckets of 64 bytes | counted; enforcement behind a policy bit |

**The policy bits are a `.rodata` word patched at load.** The verifier reads `.rodata` as
constant, so a vector or a stage that is not armed is *removed from the program before it is
JITed* rather than skipped at run time — the size of the object is a function of the
configuration. Today the agent writes `DEFAULT_SETTINGS = 0` and offers no way to change it; see
[limits.md §6](limits.md).

### What the verifier forced

Three shapes in this program exist because of the 6.8 verifier and not because of the algorithm.
Each is worth reading if you write eBPF:

- **No loop over an attacker-chosen index.** The Robin Hood probe sequence is written out
  sixteen times by a macro rather than looped. A loop bounded by anything the verifier reads as a
  variable multiplies its state space by the trip count, and the one loop this program tried was
  refused with `var_off=(0x0; 0xff)` after LLVM moved the mask that made it safe.
  → `crates/lorica-ebpf/src/stage/blocklist.rs`
- **A `read_volatile` barrier before a mask.** LLVM folds the index hash, proves the result under
  2²¹ and *deletes* the `AND` that made the access safe. 7.0 follows the reasoning; 6.8 loses the
  bound at the final `XOR` and refuses with `math between map_value pointer and register with
  unbounded min value`. A volatile read through the stack is what LLVM may not see across.
  → `crates/lorica-common/src/blocklist/mod.rs`, constant `OA_SLOTS`
- **No division anywhere on the packet path**, asserted by a test that decodes all four BPF
  divide forms out of the object. Every quotient is a shift, and every conversion that is not one
  happens once in userspace. → `crates/lorica-dataplane/tests/helper_budget.rs`

### The static budgets

Three ceilings are checked in CI against the compiled object, not against intent:

| budget | value | where |
|---|---|---|
| helper calls present in the packet path | **6 of 6** — list, bank, counters, clock, reverse path, processor id | `tests/helper_budget.rs` |
| kfunc calls | 0 | same |
| JITed bytes | 9 995 of 10 491 | `tests/jited_size.rs` |
| division/modulo instructions | 0 | `tests/helper_budget.rs` |

---

## 3. The three data structures

### The two flat blocklist tables — 20 MiB, constant cost

An `LPM_TRIE` is `BPF_F_NO_PREALLOC`: every level is a dereference to a separately allocated
node, so depth *is* cost. Measured on the target, an absent key inside a populated `/16` costs
116 ns at one entry and **414 ns at one million**, for 198 MiB of kernel memory.

What replaces it costs the same at one entry and at ten million:

```
CLASS24   2^24 × 2 bits =  4 MiB   00 nothing · 01 deny · 10 allow · 11 consult the table
OA_TABLE  2^21 × 8 B    = 16 MiB   u32 key + u32 tag, Robin Hood, open addressing
```

The lever is that these are **`.bss` globals and not maps**: a global is reached by one `LDX` off
a pointer the verifier materialises with `ld_imm64`, so the stage adds *zero* helper calls. With
a million scattered `/32`, only about 6 % of the 16.7 M `/24` carry the `Table` mark, so a
legitimate address leaves in one access 94 % of the time.

Two results from simulation are worth citing, both reproducible with
`cargo test -p lorica-policy --test blocklist_sim -- --trials 1000`:

- **The compiled probe count is not a bound.** Over a thousand key sets per shape at the maximum
  permitted load factor of 0.5, the worst probe length reaches 16 in 0.2 % of draws on the
  whole-`/24` blocks the builder actually emits. The builder refuses those, deterministically and
  with no re-seed, because the hash is not keyed. "Robin Hood insertion cannot fail" is true of
  the algorithm and false of the algorithm under a compiled bound.
- **Hopscotch is infeasible here, and that is proved rather than argued.** H=8 requires every key
  within `[home, home+8)`; no draw in two thousand has a maximum probe length below 8.

A bucketised cuckoo alternative — two buckets of eight lanes, eight-bit signatures compared eight
at a time with a zero-byte search — is implemented behind
`--features blocklist-cuckoo` and measures **8 387 JITed bytes against 9 995, and 315 fewer
instructions**. It is not the default: what decides the switch is cycles per packet on traffic
that reaches the table, and that campaign has not run.
→ `crates/lorica-common/src/blocklist/cuckoo.rs`

### The leaky-bucket bank — shared, lock-free, on cache lines

1 024 buckets, each on a 64-byte line of its own. Three layouts were measured against each other:

| layout | uncontended | under a concentrated attack |
|---|---|---|
| per-CPU | 85 ns, scales 3.83× on 4 cores | dilutes enforcement to exactly 1/N |
| shared, `bpf_spin_lock` | 107 ns | **1 988 ns and 0.24× of one core** |
| shared, lock-free | 84 ns | 250 ns |

The lock collapses under exactly the attack shape it exists to handle. Per-CPU does not collapse
but divides the enforcement by the core count, so a flood spread across source ports collects
4.00× the configured budget for free. The retained layout tolerates lost updates, and the
direction of that error is the reason it is defensible: **a lost update runs the level low**, so
the ceiling is reached later and enforcement comes out more permissive. The error is always
non-detection, never a conformant flow wrongly refused.
→ `crates/lorica-ebpf/src/maps.rs`, `BUCKET_BANK`

### The counter array — flat, striped by processor, mapped

Reading fifty thousand counter slots ten times a second through `BPF_MAP_LOOKUP_BATCH` cost
**10.8 % of a core**, and none of it was avoidable inside the syscall: two `copy_to_user` calls
and a `cond_resched()` per element. The kernel refuses `BPF_F_MMAPABLE` on a per-CPU map, so the
map became one flat `ARRAY` of `stripe × cpus` u64, laid out CPU-major:

```
index = cpu × stripe + slot        stripe rounded up to a 64-byte cache line
```

Each processor owns a contiguous region nothing else writes, which is what keeps the increment a
plain non-atomic add — that was the per-CPU map's guarantee and it is the layout's now. The
reverse order would put every processor's value for one slot in one cache line and make each bump
invalidate it everywhere.

Measured before and after on the same machine in one session:

| slots | per-CPU + `LOOKUP_BATCH` | flat + `mmap` | factor |
|---|---|---|---|
| 4 096 | 1.005 ms · 245 ns/slot | 12.95 µs · 3.16 ns/slot | **78** |
| 50 000 | 10.774 ms · 215 ns/slot | 207.9 µs · 4.16 ns/slot | **52** |

The whole agent tick over 4 096 slots went from a mean of 864 µs to **14.5 µs**, allocating
nothing either way. The price is on the packet path: one `bpf_get_smp_processor_id`, which the
verifier does not inline before 6.10, at **+37.4 instructions per packet**. Below roughly
6.2 Mpps sustained, the machine wins CPU on the trade; the vhost ceiling of the measured VM is
267 kpps.

Every read of the mapping goes through `AtomicU64::load(Relaxed)`. The data path writes those
words with a non-atomic add while the agent reads them: through a `&u64` that is a data race and
therefore undefined behaviour whatever the machine does. A relaxed load is the same instruction
on x86-64 and aarch64 and costs nothing.
→ `crates/lorica-dataplane/src/maps/mmap.rs`

---

## 4. The agent

One timer, one sweep, one control socket. `crates/loricad/src/main.rs`.

```
every 100 ms:  sweep the counters → publish an immutable snapshot
               → ladder decides a rung → apply (or withhold) → journal
```

- **The tick allocates nothing.** Asserted over a thousand ticks with a counting global
  allocator. `panic = "abort"` and no `catch_unwind`: the failure model is "the agent dies and the
  rules expire by their deadline".
- **The snapshot is published, never mutated.** Two buffers alternate behind an `ArcSwap`; a
  reader that outlives its tick makes the next one allocate, and that count is exported rather
  than hidden.
- **Every rule carries a deadline** on the kernel's own jiffy clock, measured at startup through
  a probe map because `CONFIG_HZ` has no userspace interface. If the agent dies, the rules expire
  without it.

### The response ladder

Seven rungs, in `crates/lorica-detect/src/tier/ladder.rs`. Hysteresis in both directions, one
rung at a time, and a descent withdraws what it wrote instead of waiting for the deadline.

```
0 Observe → 1 Mark → 2 Limit → 3 DropSurgical → 4 DropBroad → 5 Escalate → 6 Rtbh
                               └──────── these three refuse packets ────────┘
```

**A rung that refuses packets cannot be constructed without naming the exact key it refuses.**
`Decision::new` returns `None` otherwise. The ground of a refusal is one of two things: an entry
of the unified list whose own counter slot is rising — unshareable, because no other source can
increment that slot — or objectively invalid packets being counted while that key takes the hits.
Bucket pressure and signature matches are *candidates* and can only reach rungs 1 and 2.

Today the ladder tops out at rung 1, because the tick publishes only the 34 named counters and
neither the per-entry slots nor the bucket levels — the two inputs the confirming rungs need.
That is the open wire, and it is named in [limits.md](limits.md).

---

## 5. How anything here is measured

This matters more than any single figure, and it is the part most worth borrowing.

**The unit of record on the packet path is the instruction, not the nanosecond.** Three
consecutive runs of one unchanged program measured 612.5, 619.7 and 652.4 cycles per packet — a
spread of 6.5 % — while the instruction count over the same three runs was 1 444.5, 1 444.5 and
1 445.4, a spread of 0.06 %. A code regression is therefore caught at a tenth of an instruction
per packet, and a cycle ceiling only catches a gross change.

**Nanoseconds from `BPF_PROG_TEST_RUN` are half the CPU time.** That field was measured against
the task clock of the same work: 128 ns of `duration` for 262 ns of task-clock, a factor of 2.06,
stable across levels and campaigns. Ratios and stage-to-stage differences survive it; absolute
nanoseconds do not, and the guest cannot pin its own frequency to convert them.

**A ceiling is a decision somebody argued, checked against the object.** Sizes, call counts and
instruction counts are asserted in tests that read the compiled program, so growth breaks a build
instead of surprising a reader. When a ceiling is raised, the diff carries the reason.

**A baseline is kept beside the measurement that uses it.**
`bench/results/stage-cost-before/` exists so the subtraction behind "+37.4 instructions per
packet" can be re-run by someone who does not trust it.

---

## 6. The crates, and what each one may depend on

The dependency direction is a design constraint, not an accident of layout.

| crate | what it is | may depend on |
|---|---|---|
| `lorica-common` | every type crossing the kernel boundary, and all per-packet arithmetic | **nothing**. `no_std`, zero dependencies — it compiles into the eBPF object |
| `lorica-ebpf` | the XDP program. A separate workspace: nightly, `-Z build-std=core`, BPF ISA v3 | `lorica-common`, `aya-ebpf` |
| `lorica-dataplane` | loading, attaching, map access, capability detection, the kernel tests | `lorica-common`, `aya` |
| `lorica-policy` | the operator's configuration compiled into what the program reads | `lorica-common` |
| `lorica-detect` | snapshots to rungs: two cadences, hysteresis, descent, cardinality | `lorica-common`. **No I/O at all**, which is what makes every rung testable without a kernel |
| `lorica-escalate` | the `Escalator` trait and the webhook behind it, with the guards in front | `lorica-common` |
| `loricad` | the agent. The only crate that is allowed to combine the others | all of them |
| `lorica-ctl` | a thin client: one text line over a Unix socket, prints the JSON | **nothing** — zero dependencies, so an operator debugging a host installs one static binary |
| `lorica-export` | conversions kept off the agent's startup path | `lorica-common` |

Two of those constraints are load-bearing. `lorica-common` having no dependency is what lets the
same source compile into the kernel object and into the agent, so a layout the two sides could
disagree about does not exist. `lorica-detect` having no I/O is what lets the response ladder be
exercised exhaustively in unit tests — the alternative is a detection engine you can only test by
sending it traffic.

`lorica-ebpf` is a **separate cargo workspace** and not a member of the main one: it builds for a
tier 3 target on nightly with `-Z build-std=core`, and cargo cannot select a toolchain per
workspace member. Building it is an explicit step, never a side effect of `cargo check
--workspace`.

## 7. Where to read next

| you want | go to |
|---|---|
| to run it | [install.md](install.md), then [usage.md](usage.md) |
| what it costs you | [limits.md](limits.md) |
| to reproduce a number | [bench/README.md](../bench/README.md) and [bench/results/INDEX.md](../bench/results/INDEX.md) |
| the argument behind a specific choice | the `//!` header of the module that made it |
| the response ladder in detail | [wiki: Response ladder](https://github.com/lorica-labs/lorica/wiki/Response-ladder) |
| memlock budgets per deployment | [wiki: Deployment profiles](https://github.com/lorica-labs/lorica/wiki/Deployment-profiles) |
