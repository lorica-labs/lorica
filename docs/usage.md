# Using Lorica

Day two. [install.md](install.md) got the agent running; this page is about reading what it
tells you and changing what it does. Everything here is against a running agent — start it
first.

Throughout, `lorica-ctl` must run as the user the agent runs as. The agent needs `CAP_BPF`, so it
is privileged and its socket belongs to root; an unprivileged `lorica-ctl` reports a permission
error that reads like a bug and is not one.

---

## 1. Is it alive, and what is it doing

```bash
sudo lorica-ctl status
```

One JSON object on stdout. The fields, grouped by the question they answer:

**Am I in the packet path?**

| field | meaning |
|---|---|
| `attached` | `true` once the program is on an interface |
| `interface` | *which* interface, because `true` alone does not say, and the [attach tax](limits.md#1-attaching-an-xdp-program-to-virtio-net-costs-throughput-permanently) is charged to one |
| `kernel` | the release the program was verified against |

**Is the agent healthy?**

| field | meaning |
|---|---|
| `ticks` | grows between two calls. This is the whole liveness check |
| `jiffies` | the kernel clock the deadlines are compared against. A `0` is a probe that stopped answering, which no running agent does |
| `kernel_hz` | measured at startup — `CONFIG_HZ` has no userspace interface |
| `rss_kib` | the agent's own resident memory |
| `full_sweeps`, `sweep_every_ticks`, `slot_reads_per_second` | the cadence of the counter read, and the number its cost is linear in |

**What has it decided?**

| field | meaning |
|---|---|
| `mode` | `observe` or `armed` |
| `armable` | whether `arm` would be *accepted*. Reported beside the mode so you do not have to arm a security system to find out |
| `rung` | 0 to 6 on the [response ladder](https://github.com/lorica-labs/lorica/wiki/Response-ladder) |
| `written`, `withheld`, `withdrawn` | refusals applied, refusals computed and not applied, refusals taken back |
| `standing` | the prefix currently refused because of this agent, or `null` |
| `stages` | one entry per named counter, rendered from the catalogue and never from a list written by hand |

Two more commands read state and change nothing:

```bash
sudo lorica-ctl tiers   # the rungs this agent has stood on, and how many transitions
sudo lorica-ctl rules   # every entry of the unified list, with the deadline each carries
```

`rules` exists to establish one property: **no active entry lacks a deadline**. An entry without
one outlives the agent that wrote it.

---

## 2. The counters

Thirty-four named counters, and **every one of them counts an exception**. Nothing counts
accepted packets — that would put a lookup on the steady-state path — so a flood of well-formed
SYNs crosses all seven stages and increments nothing. If you are watching for a flood, the
interface's `rx_packets` is the denominator, not this agent's totals.

| group | counters | what a rise means |
|---|---|---|
| parse | `parse_truncated`, `parse_depth_exceeded`, `parse_unknown_encap` | malformed or unusually encapsulated frames. The first two are **dropped** |
| coherence | `sanity_ip_length`, `sanity_l4_length`, `sanity_tcp_flags`, `sanity_ip_options_refused` | objectively invalid packets. All **dropped** |
| ICMP | `icmp_path_mtu_passed`, `icmp_neighbor_passed`, `icmp_echo_dropped`, `icmp_other_dropped` | path-MTU and neighbour discovery always pass; the other two only move when the policy bit is set |
| source list | `lpm_allow_exit`, `lpm_drop_hit`, `lpm_scope_miss`, `lpm_expired`, `bogon_refused` | the list had something to say about this source |
| fragments | `fragment_first_passed`, `fragment_later_dropped`, `fragment_later_allowed` | fragmentation volume, and its drops |
| reverse path | `urpf_no_route`, `urpf_wrong_interface`, `urpf_lookup_unsupported` | spoofed sources — or a host that does not forward, which makes the third one every frame |
| signatures | `signature_amp_dns`, `_ntp`, `_ssdp`, `_memcached`, `_raknet`, `signature_loopy_port_pair`, `signature_frag_abuse`, `signature_impossible_tcp_flags`, `signature_length_mismatch` | a known amplification or coherence vector matched. **Counted, not dropped**, unless the policy bit is set |
| buckets | `bucket_over_budget`, `bucket_marked` | a source exceeded its budget. **Counted, not dropped**, unless the policy bit is set |

The counters move before the policy is applied, deliberately: the count is what you read to
decide whether arming a stage is safe, so it has to move in the mode where nothing is armed.

---

## 3. Metrics

`/metrics` on `127.0.0.1:9090` by default, Prometheus text format. Loopback because a scrape
serialises the whole registry — an off-host address is a decision, not a default. Turn it off
with `--metrics off`.

```bash
curl -s http://127.0.0.1:9090/metrics | grep ^lorica_
```

| series | what it is |
|---|---|
| `lorica_stage_events_total{counter="…"}` | one per named counter, the totals above |
| `lorica_agent_ticks_total` | liveness, same as `ticks` |
| `lorica_agent_full_sweeps_total`, `lorica_agent_slot_reads_per_second` | the cost of the counter read |
| `lorica_agent_attached` | 1 when in the packet path |
| `lorica_agent_kernel_hz`, `lorica_agent_kernel_jiffies` | the clock the deadlines live on |
| `lorica_log_writes_lost_total`, `lorica_log_events_folded_total` | lines the sink refused, and counter movements an aggregate line stood for |
| `lorica_metrics_scrape_duration_seconds` | a histogram of this endpoint's own cost |

**No series carries a label whose value an attacker picks** — no source IP, port, flow id or ASN.
The count of series is fixed at compile time and a test fails past a checked-in ceiling of 64.
Alert on `lorica_agent_ticks_total` not increasing before you alert on anything else: an agent
that stopped ticking is reporting yesterday's numbers with today's timestamp.

---

## 4. The journal

One aggregate line per second on stderr, whatever the packet rate, plus at most three lines per
incident — `detected`, `mitigating`, `cleared`. The volume is a function of the *state*, not of
the traffic, and there is a test that fails if that stops being true.

The `digest` line carries, beyond the counters:

| field | what it is for |
|---|---|
| `ticks` | the *jump* since the last line. A hole is a tick the agent did not get to run, which is the earliest evidence of saturation available |
| `tick_worst_us`, `tick_mean_us` | the tail of the tick |
| `nivcsw` | involuntary context switches. Correlated with the tail ⇒ CFS preemption |
| `steal_us`, `runq_wait_us` | correlated with the tail ⇒ the hypervisor, and nothing inside the guest will fix it |
| `minflt` | minor faults. Expected to be **zero**: the readers allocate nothing after construction, so anything else is a defect here rather than a property of the machine |

`runq_wait_us` reads zero unless `kernel.sched_schedstats` is on, which it is not by default. A
zero there means *not measured*, not *did not wait*.

No timestamp: journald stamps every entry it accepts, and an RFC3339 stamp would be 27 bytes on a
140-byte line.

---

## 5. Putting it in the packet path

```bash
sudo lorica-ctl attach eth0
sudo lorica-ctl detach
```

or `--iface eth0` at startup. Read [limits.md §1](limits.md) first: **58 % off receive throughput
and 57 % onto the application's p99**, measured on virtio, paid on every packet whether or not
anything is attacking.

The attach is native or nothing. A driver without native XDP support is refused rather than
downgraded to generic mode, and an interface whose hook is already held by something else —
Cilium, a provider's protection, another eBPF tool — is refused with the occupant named. The hook
takes one program per interface, and replacing it would silently stop whatever it was doing.

**Attaching does not arm.** An attached agent in `observe` moves its counters and writes nothing.

---

## 6. The configuration file, and which table a rule lands in

```bash
sudo loricad --object ./lorica-ebpf --config /etc/lorica.toml
```

[`examples/lorica.toml`](../examples/lorica.toml) is annotated and compiles as it stands. It
carries the profile, the mode, the policy bits, the named scopes, the signature selection and
the rules. `--policy`, `--counters` and `--mode` are refused alongside it, each named: the file
carries all three, and two places to set one thing make "why is this rule not firing" depend on
which one you read.

**Every value is checked before anything is loaded.** A bad prefix, an allow with no scope, a
configuration that does not fit its profile's memory budget — all of them reach you at the
prompt, with the two numbers where a budget is involved, and no map is created.

### Two tables, and the file does not say which

Stage 3 has two halves. An IPv4 `deny` with no scope and no `ttl_secs` goes into the two flat
tables: 4 MiB covering every `/24` and 16 MiB of exact addresses, read in **one memory access**
and costing no kernel memory per entry. Everything else goes into the trie, whose cost does grow
with what you put in it — a scope, a deadline and IPv6 are the three things the flat tables have
no room for.

Which half holds a rule is decided by the rule and never written in the file. On startup the
agent says what it did:

```
loricad: 2 prefixes in the flat tables (1 keys, 0 expanded, worst probe 0), one write
loricad: 2 operator entries and 28 bogon prefixes in the list, room for 16414
```

Two things follow that are worth knowing before you read a dashboard:

- **The counters are the same either way.** Both halves bump `lorica_lpm_drop_hit` and
  `lorica_lpm_allow_exit`, so the number is right whichever table answered. What a flat hit
  cannot give you is attribution to one line of your file — eight bytes a slot leave nowhere to
  put a counter index.
- **A less specific rule never overtakes a more specific one**, even across the two tables. The
  flat tables are read first, so a `/24` deny placed there would answer before a `/32` allow in
  the trie; the compiler therefore keeps that `/24` in the trie instead. Precedence is the
  specificity of the address, always, and never the order of declaration or the structure a
  rule compiled into.

### Arming a stage is not the same thing as arming the agent

`enforce_signatures` and `enforce_buckets` in `[settings]` — or `--policy` — decide whether
**stages** refuse traffic they classify themselves. `mode` decides whether the **ladder** may
write a refusal it worked out. The two are independent, and the next section is about the second.

---

## 7. Arming the ladder

```bash
sudo lorica-ctl arm
sudo lorica-ctl disarm
```

or `--mode armed` at startup. Arming needs at least one counter slot **above** the 34 named ones
— pass `--counters 4096` — and `status.armable` tells you whether it would be accepted. An armed
agent with no room above the named counters would charge its own refusals to a stage counter and
read them back as evidence for the next decision.

What changes, and only this: whether the map moves. The decision is computed, validated and
counted identically in both modes, so `observe` tells you exactly what arming would have done.

`disarm` puts the mode back **and withdraws the key arming wrote**. It does not wait for the
deadline: an operator who disarms and then watches traffic still being dropped for the rest of a
ten-minute TTL has been told the agent is off while it is not. Only the key this agent wrote is
withdrawn — the list is shared, and emptying it would remove the operator's own entries.

> **What arming does not yet do.** The ladder cannot currently reach a rung that refuses packets:
> the tick publishes the 34 named counters and neither the per-entry slots nor the bucket levels,
> which are the two inputs the confirming rungs need. Armed, the agent will report rungs 0 and 1
> and write nothing. See [limits.md §6](limits.md).

---

## 8. Tuning the sweep

Two knobs, and they are not the same knob.

| flag | what it does | freshness | worst tick |
|---|---|---|---|
| `--sweep-every N` | full sweep every N ticks | ÷N | unchanged |
| `--sweep-stride N` | one full sweep spread over N reads | ÷N | **÷N** |

`--sweep-every` skips whole ticks and leaves the worst one where it is; `--sweep-stride` cuts the
worst read and skips nothing. Both are safe because these counters only increase: a slot a read
did not visit keeps a lower bound on the truth, never a drop, and detection differences two
snapshots.

Neither is likely to matter. The counter array is mapped, so a full sweep of 4 096 slots costs
13 µs — the flags exist for the fallback path, which the agent takes only if the kernel refuses
the mapping and which it names at startup when it does.

---

## 9. What has no answer yet

`lorica-ctl reload` refuses, and says why: a configuration file is read **once, at startup**, so
there is nothing to re-read without a restart. A `reload` that answered success would let you
conclude your edited file is in force. Restarting is the supported path and the design expects
it — the policy word, the signature selection and the map sizes are all fixed at load, because
reading them from a map instead would cost a helper call on every packet that reaches a stage
with a knob.

**The reverse-path stage cannot be armed, and deliberately has no flag.** Whether a strict check
discriminates anything is a property of your routing table, not a preference: on a host with a
default route it refuses nothing and costs every packet a `bpf_fib_lookup`. The agent is supposed
to evaluate that criterion and set the bit itself, and it does not yet.

**The ladder cannot refuse anything it worked out for itself.** Rungs 3 and above need a key
whose own counter slot is rising and rungs 5 and 6 need the bucket bank, and the tick publishes
neither. Both are named in [limits.md](limits.md) §6 and tracked on the
[wiki status page](https://github.com/lorica-labs/lorica/wiki/Status).
