#!/bin/bash
# Proxmox hookscript for VM 104 (k3s): confine everything the VM's scope holds -- vCPU
# threads, vhost workers, iothreads, the main QEMU thread -- to the CPUs the plan gives it.
#
# Arm with: qm set 104 --hookscript local:snippets/pin-104.sh
#
# Why a cgroup cpuset rather than a taskset per thread. Proxmox's own `affinity:` is a
# plain taskset of the *vCPU* threads and of nothing else: the vhost workers, the iothreads
# and the main QEMU thread are not subject to it. Those are the threads that carry the
# virtio rings, so an `affinity:` alone leaves the packet path free to roam -- including
# onto 48,50,52,54, the siblings of the VM 901 measurement island. A cpuset on the scope
# covers the whole scope instead, and it keeps covering it for the threads created after
# the VM is already running, which is precisely when vhost workers and iothreads appear.
#
# Where the list comes from: docs/mesures/hyperviseur-recommandations.md section 2, table
# "Plan applique le 27 aout" (option B, vNUMA 2x10), row "VM 104 k3s" -- not the
# mono-socket option A of section 3, which was tried and killed by the OOM killer. Check
# the list against the machine with scripts/lab/check-topology.sh before arming this
# script: if the sibling of N is not N+28 on this host, this list places 104 on the
# siblings of the measurement islands and contaminates every measurement taken afterwards.
#
# Proxmox runs hookscripts as root, so nothing here needs sudo and nothing here asks for it.

# $1 is the vmid, $2 the phase. Every phase but this one is a no-op: the scope does not
# exist before post-start, and set-property against a missing unit is an error.
[ "$2" = "post-start" ] || exit 0

VMID=104
CPUS=0,2,4,6,8,9,11,13,15,17,28,30,32,34,36,37,39,41,43,45

systemctl set-property --runtime "$VMID.scope" "AllowedCPUs=$CPUS" || exit 1

# --- fallback for kernels older than 6.4 --------------------------------------
# From 6.4 the vhost workers are vhost_task threads of the QEMU process itself: they sit in
# the process's cgroup and the line above already holds them. Before 6.4 they are kernel
# threads named vhost-<qemu pid>, they live outside every cgroup, and set-property never
# reaches them -- so on such a kernel they have to be moved by hand, or the busiest threads
# of the VM are the only ones left unpinned.
kernel_lt_6_4() {
    uname -r | awk -F. '{ exit !($1 < 6 || ($1 == 6 && $2 < 4)) }'
}

if kernel_lt_6_4; then
    pidfile=/run/qemu-server/$VMID.pid
    if [ -r "$pidfile" ]; then
        qemupid=$(cat "$pidfile")
        # The workers are not all there the instant post-start runs: vhost-net is set up as
        # the guest driver brings each virtio queue up, which is seconds later. Hence a few
        # passes rather than one. They run in the foreground and delay the return of
        # qm start by that much, which is the cheap half of the trade: a background loop
        # would outlive the hook and be killed with its process group at an unpredictable
        # moment, and a watcher daemon is a second thing to keep alive for a kernel this
        # lab does not run.
        for _ in 1 2 3 4 5; do
            # -x so a pid that is a prefix of another VM's pid cannot match. comm is
            # truncated to 15 characters, which "vhost-" plus a pid still fits.
            for tid in $(pgrep -x "vhost-$qemupid"); do
                taskset -pc "$CPUS" "$tid" >/dev/null 2>&1
            done
            sleep 1
        done
    else
        echo "pin-104: $pidfile is unreadable, vhost kthreads left unpinned" >&2
    fi
fi
