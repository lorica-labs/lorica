#!/bin/bash
# Proxmox hookscript for VM 900 (build): same pattern as pin-104.sh, other list.
#
# Arm with: qm set 900 --hookscript local:snippets/pin-900.sh
#
# Why a cgroup cpuset rather than a taskset per thread. Proxmox's own `affinity:` is a
# plain taskset of the *vCPU* threads and of nothing else: the vhost workers, the iothreads
# and the main QEMU thread are not subject to it. On 900 that matters more than anywhere,
# because a build is what saturates a machine: its iothreads are the ones that would drift
# onto the measurement islands. A cpuset on the scope covers the whole scope, and keeps
# covering it for threads created after the VM is already running.
#
# The duplication with pin-104.sh is deliberate. A hookscript is referenced from
# /var/lib/vz/snippets and must stand alone there; one shared file sourced by two wrappers
# is one more thing to copy correctly onto a hypervisor for no gain. What must not diverge
# is CPUS, and check-topology.sh is what catches a divergence: it fails if the six role
# lists stop partitioning 0..55.
#
# Where the list comes from: docs/mesures/hyperviseur-recommandations.md section 2, table
# "Plan applique le 27 aout", row "VM 900 construction". Check it against the machine with
# scripts/lab/check-topology.sh before arming this script.
#
# Proxmox runs hookscripts as root, so nothing here needs sudo and nothing here asks for it.

# $1 is the vmid, $2 the phase. Every phase but this one is a no-op: the scope does not
# exist before post-start, and set-property against a missing unit is an error.
[ "$2" = "post-start" ] || exit 0

VMID=900
CPUS=10,12,14,16,38,40,42,44

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
        # passes rather than one, in the foreground: a background loop would outlive the
        # hook and be killed with its process group at an unpredictable moment.
        for _ in 1 2 3 4 5; do
            # -x so a pid that is a prefix of another VM's pid cannot match. comm is
            # truncated to 15 characters, which "vhost-" plus a pid still fits.
            for tid in $(pgrep -x "vhost-$qemupid"); do
                taskset -pc "$CPUS" "$tid" >/dev/null 2>&1
            done
            sleep 1
        done
    else
        echo "pin-900: $pidfile is unreadable, vhost kthreads left unpinned" >&2
    fi
fi
