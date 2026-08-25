# Installing Lorica

Everything below is meant to be run in order, from a shell, on the machine that will run the
agent. If a command is missing, that is a bug in this file — please report it.

## Prerequisites

- **Linux on x86_64.** The eBPF object is compiled for `bpfel-unknown-none`, and parts of
  the detection path have hand-written AVX2 and AVX-512 forms with a scalar fallback.
- **Kernel 6.8 or newer.** That is the floor this project tests against: the kernel matrix
  in CI runs 6.8, 6.12 and 7.0, and a failure on 6.8 is blocking. Newer kernels are not
  required — every kernel capability above the floor is *detected*, and when one is absent
  the program takes another path to the same verdict. `lorica-ctl status` prints that table
  for the kernel you are on.
- **`CAP_BPF` and `CAP_NET_ADMIN`**, which in practice means starting the agent with `sudo`.
  Loading and attaching an XDP program is privileged; nothing here works without it.
- **`memlock`.** From kernel 5.11 the memory a BPF map costs is charged to the cgroup, not
  to `RLIMIT_MEMLOCK`, so at this project's floor there is nothing to raise and `ulimit -l`
  can be left alone. If a load fails with `EPERM` or `ENOMEM` on a system that enforces the
  old accounting, raise `ulimit -l` for the user the agent runs as. The map cost itself is
  readable from the kernel's own accounting, the `memlock:` line of the map's `fdinfo`.
- **A free `127.0.0.1:9090`**, or `--metrics off`. That is where `/metrics` listens by
  default.

Nothing has to be created by hand. The agent creates the parent directory of its control
socket at startup, and removes a socket left behind by a killed agent.

## Getting the binaries and the eBPF object

Two binaries and one object are enough to start: `loricad` (the agent), `lorica-ctl` (the
client that asks it what it is doing), and `lorica-ebpf`, the eBPF object the agent loads.
`lorica-export` is only needed if you are compiling a blocklist.

### From a release

```sh
# Pick the tag you want from https://github.com/lorica-labs/lorica/releases
tar -xzf lorica-<tag>-x86_64-unknown-linux-musl.tar.gz
cd lorica-<tag>-x86_64-unknown-linux-musl
sha256sum -c SHA256SUMS
```

The binaries are statically linked against musl, so they carry no glibc requirement of
their own: the kernel release above is the only version you have to check.

### From source

The eBPF object is built by a **different toolchain** than the userspace binaries — nightly,
for a tier 3 target, with `bpf-linker` on `PATH`. `CONTRIBUTING.md` has the details and the
reason.

```sh
cargo build --release --workspace
cd crates/lorica-ebpf && cargo +nightly build --release && cd ../..
```

That leaves the object at
`crates/lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf`, and the binaries in
`target/release/`.

## Starting it

`--object` is required, and it is the only required option — the agent refuses to start
without it, because the object is produced by a toolchain the agent cannot invoke:

```sh
sudo ./loricad --object ./lorica-ebpf
```

The agent prints one line to stderr as soon as it has loaded the program, calibrated the
kernel clock and opened its socket. It names the counter slots, the batch size, the tick
rate, the sweep cadence, the resulting slot reads per second, the socket path, and the
kernel clock rate with the jiffy it read. If you see that line, the program passed the
verifier on your kernel.

It then runs until it is signalled — `Ctrl-C`, or `SIGTERM`. Pass `--seconds N` for a run
with a bound, and the agent prints a summary line of its own when the bound is reached.

## Checking that it runs

```sh
sudo ./lorica-ctl status
```

The answer is JSON on stdout: the kernel release, whether the program is attached, the tick
period, the kernel clock rate and current jiffy, the counter slots, the tick and sweep
counters, the agent's RSS, and one row per detected kernel capability with the reference
path taken when it is absent.

Two things to look at:

- **`ticks` grows between two calls.** That is the whole liveness check. A `jiffies` of `0`
  means the clock probe stopped answering, which no running agent does.
- **`attached`.** See *What it does not do yet* below.

`lorica-ctl` must run as the user the agent runs as. The agent needs `CAP_BPF`, so it runs
privileged and its socket belongs to root; a `lorica-ctl` run unprivileged reports a
permission error that reads like a bug and is not one.

If `/metrics` is on, the same state is scrapeable:

```sh
curl -s http://127.0.0.1:9090/metrics | head
```

## The options, and their defaults

| Option | Default | What it does |
| --- | --- | --- |
| `--object PATH` | *required* | The eBPF object to load. |
| `--socket PATH` | `/run/lorica/control.sock` | Where the control socket is bound. |
| `--counters N` | `34` | Counter slots the map is sized for. The 34 named counters come first; every slot above them belongs to one entry of the unified list. |
| `--hz N` | `10` | Ticks per second. |
| `--batch N` | `1000` | Elements per `BPF_MAP_LOOKUP_BATCH` call. |
| `--sweep-every N` | `1` | Ticks between two full sweeps of the counter map. `1` is every tick; above that, per-entry counters get staler and the CPU cost falls linearly. |
| `--seconds N` | `0` | Seconds to run before exiting. `0` runs until signalled. |
| `--metrics ADDR\|off` | `127.0.0.1:9090` | Where `/metrics` listens, or `off`. Loopback by default: a scrape serialises the whole registry, so an off-host address is a decision, not a default. |
| `--mode observe\|armed` | `observe` | Whether a refusal is applied or only reported. |

Four startup refusals, so you can recognise them:

- `--hz 0`, `--batch 0` or `--sweep-every 0` never tick, read nothing, or never sweep.
- `--counters` below the 34 named counters is refused rather than clamped.
- `--mode armed` needs at least one slot **above** the named counters — pass `--counters 35`
  or more. An armed agent with no room above them would charge its own refusals to a stage
  counter and then read them back as evidence for the next decision.
- A missing or unreadable `--object`, or an object the verifier rejects, fails at startup
  with the path in the message.

## Arming it

**The default mode is `observe`, and in `observe` the agent refuses nothing.** It reads the
counters, runs the detection ladder, and reports the decision it would have taken. That is
the default on purpose: a tool that watches and reports cannot cause a destructive false
positive.

Arming is one flag, plus the slot requirement above:

```sh
sudo ./loricad --object ./lorica-ebpf --mode armed --counters 4096
```

Armed, an accepted decision is written into the unified list, a decision that moves to a
different prefix takes the previous one back out, and a descent withdraws what it had
refused instead of waiting for the entry's deadline. The mode is also the first question
any false-positive report has to answer — see `SECURITY.md`.

## What it does not do yet

The agent loads the program, verifies it, calibrates the clock and reads the maps. It does
**not** attach the program to an interface: `"attached": false` in `lorica-ctl status` is
the current, correct answer, and it means no packet of yours has been through the
dataplane. Detached-by-default is a measured design decision, not an oversight, and
`docs/limits.md` is where the shape of it — and everything else this will not do for you —
is written down.
