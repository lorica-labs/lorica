# Security

Lorica loads a program into your kernel and, once armed, decides which packets reach your
application. Both halves of that deserve a reporting path that is not a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on
<https://github.com/lorica-labs/lorica> — the *Security* tab, *Report a vulnerability*. It
opens a private thread with the maintainers and needs no prior contact.

TODO(human): a security contact address, if one is to be offered beside the GitHub channel.
TODO(human): the response window and the coordinated-disclosure window you want to commit
to. No number is written here because a promise nobody measured is worse than no promise.

Please include what you would want to receive: the kernel release, how the agent was
started, and the smallest input that shows the problem. If the report involves a crafted
packet, a `pcap` is worth more than a description of one.

In scope: the eBPF program and anything that can make it accept or refuse the wrong packet;
the agent, its control socket, its `/metrics` endpoint; the blocklist format and the tool
that writes it. Out of scope: the effect of a policy an operator deliberately configured,
and denial of service caused by running the agent with a cadence the machine cannot afford
— that is a tuning question, and `docs/limits.md` is where it belongs.

Fixes land on the default branch and in the next tag. There is no version-support table
here, because there is no release history to make promises about yet.

## Reporting a false positive

A false positive is legitimate traffic that Lorica refused. It is the failure this project
takes most seriously, and it is also the one that gets misreported most often, so the
questions are ordered by what they rule out.

**1. Which mode was the agent in — `observe` or `armed`?** This is the first question and
it is not a formality. `observe` is the default, and in `observe` the agent computes every
decision and applies none of them: nothing is written into the unified list, so nothing can
be refused. A drop observed while the agent ran in `observe` was produced by something
else, and the report we need from you is a different one — start from what else is on the
path (another XDP or tc program, the kernel's own drops, the NIC, a firewall rule).

Related, and worth checking in the same breath: `"attached"` in `lorica-ctl status`. If it
is `false`, the program was loaded and verified but never attached to an interface, and no
packet of yours was seen by the dataplane at all.

**2. The per-stage counters.** The full output of

```sh
lorica-ctl status
```

Not a summary of it. It carries the counter slots, the tick and sweep accounting, the
kernel release, and the capability table as the *agent* detected it — which describes the
kernel the dataplane is loaded against rather than whichever machine ran the client.

**3. The list as it stood — `lorica-ctl rules`.** The refused prefixes at the moment of the
drop, each with its deadline. Every active entry has one; a report showing an entry without
one is a finding in itself and not a false positive report, because no active rule is allowed
to outlive a deadline.

**4. The trace.** A capture of the refused traffic — `pcap` preferred — with enough of the
surrounding flow to show that it was legitimate. Source addresses may be redacted as long
as the redaction is consistent across the capture, since what matters is which packets
share a source, not what the source was.

**5. The kernel release.** `uname -r`. Several capabilities are decided by release number
alone when no kernel symbol tells them apart, so the release is part of the verdict, not
just context.

**6. How the agent was started.** The whole command line, including `--counters`, `--hz`
and `--sweep-every`. The cadence changes which counters are fresh at the moment a decision
is taken.

## The trust chain, and the tool itself

Two items are worth naming here, because they are what an operator asks about and neither
is implemented yet.

**Signed BPF programs** (kernel 6.18) would let an operator verify that the filter the
kernel loaded is the filter that was published, closing the chain between a release
artefact and a running dataplane. When it arrives it arrives as a *detected capability*,
exactly like every row of `crates/lorica-dataplane/src/capability/matrix.rs`: never a
prerequisite, never a kernel floor, and an absent signature never changes the verdict a
packet receives.

**CET shadow stack** is on by default on recent x86 hardware and userspace, and the agent
inherits it. A security tool is worth hardening like anything else that runs privileged.
