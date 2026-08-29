# Contributing

Patches are welcome. This file covers building, testing, and the three repository rules a
newcomer breaks without knowing they exist.

## Building

The userspace crates build on stable, with the toolchain the repository pins in
`rust-toolchain.toml`:

```sh
cargo build --release --workspace
```

The eBPF program is not part of that workspace and is not built by that command. See rule
(b) below.

## Testing

Everything that needs no kernel:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Those three are what `.github/workflows/ci.yml` runs first, so a change that fails one of
them fails the pull request before anything else is even attempted.

The tests that load a program into the kernel run through a script, because the eBPF object
has to be built by a second toolchain and the test binary has to be privileged while the
build stays unprivileged:

```sh
bash scripts/lab/kernel-tests.sh
bash scripts/lab/kernel-tests.sh --crate loricad --test no_alloc_in_tick
```

They need `clang` and `libbpf-dev` for the bench objects the attach tests take the hook
with. See rule (c) below for what else they need.

## What belongs in this repository, and what does not

**This repository holds the code, and what a third party needs in order to use it or to
reproduce a figure. Nothing else.**

Everything that describes *our* lab, *our* hypervisor or *our* hosts belongs outside it. The
distinction is not tidiness: a reader who clones this cannot use a script that pins vCPUs of
VM 900 on one particular Proxmox box, and a file they cannot use is a file that makes them
wonder what else here is written for somebody else.

The line runs through the middle of some directories, so it is worth stating on both sides:

| in | out |
|---|---|
| `scripts/lab/*.sh` — they take `--iface`, `LORICA_BUILD_HOST`, `LORICA_TARGET_HOST`, and default to overridable aliases | anything hard-coding a VM id, a hypervisor name or a CPU list of ours |
| `bench/README.md` — three machines, their roles, their requirements | the runbook that creates those three machines here |
| `bench/results/` — the numbers, with the environment captured beside them | the analysis reports that read them |
| `docs/{install,usage,limits,architecture}.md` | design and conduct documents |

Two guards exist and neither is complete. `/docs/*` is ignored with the four user-facing pages
named back in one by one, because a `git add -A` swept a design spec in once. **A `deploy/`
directory holding Proxmox pin scripts for one specific hypervisor got in anyway**, past that
guard, and lived here until somebody noticed — which is the reason this section exists rather
than only the comment in `.gitignore`.

So it is a review question, asked of every new top-level path: *could a stranger who cloned
this use it?* If the answer is no, it goes in the agent tree.

## The three rules

**(a) Run `cargo fmt --all` before every commit.** CI runs `cargo fmt --all --check` and
fails on the diff. The eBPF crate is formatted by its own toolchain, `cargo +nightly fmt`
from inside `crates/lorica-ebpf`, because that crate is a separate workspace and the root
`--all` does not reach it.

**(b) `lorica-ebpf` is a separate workspace, on nightly.** It builds for
`bpfel-unknown-none`, a tier 3 target, which needs nightly and `-Z build-std=core`; a
toolchain cannot be selected per workspace member, so the root `Cargo.toml` excludes the
crate rather than making every userspace build depend on nightly. Building it is an
explicit step:

```sh
cd crates/lorica-ebpf && cargo +nightly build --release
```

It also needs `bpf-linker` on `PATH`. `cargo install bpf-linker` fails on a machine with no
`llvm-config` on `PATH`, because the crate links against one specific LLVM; CI installs the
musl-static release binary instead, and `.github/actions/bpf-linker` records the pinned
version and the reasoning. Use the same binary locally and the object you build is the
object CI builds.

**(c) The kernel tests need Linux, `sudo`, and a built eBPF object.** Loading an XDP
program needs `CAP_BPF` and `CAP_NET_ADMIN`, so `scripts/lab/kernel-tests.sh` runs the test
binaries under `sudo` — and under `sudo -n`, so a password prompt is a hard failure rather
than a hang. They are gated behind a `kernel-tests` feature per crate for the same reason:
ungated, they joined an unprivileged `cargo test --workspace` in CI and died on `EPERM`,
which reads as a broken build rather than as a test nobody meant to run there.

None of this works on Windows, and not only the kernel part: `aya` uses `std::os::fd`, so
`lorica-dataplane` and `loricad` do not compile on Windows at all. A Windows checkout can
run `cargo fmt` and the tests of the crates that do not depend on `aya`; `cargo test
--workspace` is not one of them.

## The module convention

Every module opens on a `//!` block that states the choice the module makes, and names the
alternative that was rejected together with the number that rejected it — a measurement, a
size, a cost, a kernel release. It is the most visible convention in this repository and it
is written down nowhere else, so it is worth stating plainly: a new module without that
block, or with one that praises the design instead of pricing the alternative, will be sent
back. `crates/lorica-dataplane/src/capability/matrix.rs` and
`crates/lorica-policy/src/config/mod.rs` are the shape to copy.

The same rule is what makes a review short. If a reviewer has to ask "why not the obvious
thing", the `//!` was missing.

## Pull requests

Rebase on the default branch, keep the commit history readable, and write commit subjects
in the imperative. Do not spell a branch name into a workflow file; `ci.yml` explains what
that costs.
