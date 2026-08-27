# Proxmox pinning hookscripts

`pin-104.sh` and `pin-900.sh` confine each VM's whole scope -- vCPU threads, vhost workers,
iothreads, main QEMU thread -- to the CPUs the partitioning plan gives it. Proxmox's own
`affinity:` only tasksets the vCPU threads, which is why a cgroup cpuset is used instead.

Every CPU list comes from `docs/mesures/hyperviseur-recommandations.md` section 2, table
"Plan applique le 27 aout" (option B, vNUMA 2x10) -- not the mono-socket option A of
section 3, which was tried and killed by the OOM killer.

## Before anything

```sh
scripts/lab/check-topology.sh
```

It must pass on the hypervisor. It checks that the SMT sibling of N is N+28, that even CPUs
are on node 0, and that no VM can run on `29,31,33,35,48,49,50,51,52,53,54,55` -- the
siblings of the three measurement islands, which the plan keeps empty. If it fails, the CPU
lists in these scripts point at the wrong cores and applying them puts the islands on the
siblings of the load they exist to avoid. Nothing below may be applied until it passes.

## Install

```sh
cp pin-104.sh pin-900.sh /var/lib/vz/snippets/
chmod +x /var/lib/vz/snippets/pin-104.sh /var/lib/vz/snippets/pin-900.sh
qm set 104 --hookscript local:snippets/pin-104.sh
qm set 900 --hookscript local:snippets/pin-900.sh
```

Each takes effect at the VM's next start, not on the running instance: the hook runs at
`post-start`. Stop and start the VM, a guest reboot does not re-run it.

## Host settings, once

```sh
# the host's own non-VM work stays on the housekeeping pool
systemctl set-property --runtime system.slice user.slice init.scope \
  AllowedCPUs=9,11,13,15,17,19,37,39,41,43,45,47
```

and in `/etc/default/irqbalance`, to keep IRQs off the islands and off their siblings:

```
IRQBALANCE_BANNED_CPULIST="1,3,5,7,20,22,24,26,21,23,25,27,29,31,33,35,48,50,52,54,49,51,53,55"
```

`--runtime` does not survive a host reboot, and neither does it write anything to
`/etc/systemd`. That is intended -- a pinning that outlives the plan is worse than one that
has to be reapplied -- but it means the `systemctl` line above is part of the boot
procedure of this hypervisor and not a one-off. The hookscripts do re-run on every VM
start, so only the host-wide line needs redoing.

## Checks after applying

```sh
numastat -p $(cat /run/qemu-server/104.pid)
grep . /proc/irq/*/smp_affinity_list
```

- `numastat -p` must show 104's memory split across the two nodes as the vNUMA config
  binds it, roughly half and half; a run that shows it concentrated on one node means
  `hostnodes=...,policy=bind` did not take.
- `smp_affinity_list` must list no IRQ on the twelve sibling CPUs or on the islands
  themselves. An IRQ that stayed there is irqbalance ignoring its banned list, which is
  also why `check-env.sh` refuses to measure while irqbalance is active.
- The 90 % / 51 % NUMA imbalance of the 26 August survey is what all of this is for, and
  it is the figure to reread afterwards: it must come down. By how much is not predicted
  here -- it is a measurement, and it has not been taken yet.
