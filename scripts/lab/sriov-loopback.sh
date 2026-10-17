#!/bin/sh
# Build a packet bench inside a single NIC, with no provider fabric in the path.
#
# Rented private networks turn out to be policed in packets per second: a Latitude.sh VLAN
# delivered 1.35 Mpps out of 9.29 Mpps put on the wire, with rx_missed_errors at zero on the
# receiver, so the network simply dropped 85% of the traffic. Bandwidth tests never see it,
# because saturating 10 GbE with 1500-byte frames only needs ~800 kpps.
#
# Two SR-IOV virtual functions on the SAME physical port sidestep the question entirely. Traffic
# from VF0 to VF1 is switched by the VEB inside the card and never reaches the wire, so there is
# no provider equipment left to police it. One machine is enough.
#
# What this costs in honesty: generator and DUT share the host's caches, memory controller and
# PCIe root complex, and the PHY is never crossed. Good enough to size the program and shake out
# the tooling; not the number to publish. Publishable figures need two machines on documented
# hardware, which is what the Grid'5000 track is for.
#
# Usage: sriov-loopback.sh <private-iface> [up|down]
#
# Then generate from VF0 towards VF1's MAC, which the script prints.

set -eu

IFACE=${1:?usage: sriov-loopback.sh <private-iface> [up|down]}
ACTION=${2:-up}
SYS="/sys/class/net/$IFACE/device"

# Creating VFs resets the port. Doing that to the interface carrying SSH ends the session, and on
# a rented box the console is the only way back.
if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q 'inet '; then
    addr=$(ip -4 -br addr show dev "$IFACE" | awk '{print $3}')
    case "$addr" in
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) : ;;
        *) echo "REFUSING: $IFACE carries a public address ($addr) and is probably your SSH path." >&2
           exit 1 ;;
    esac
fi

[ -e "$SYS/sriov_totalvfs" ] || { echo "$IFACE does not expose SR-IOV (no $SYS/sriov_totalvfs)" >&2; exit 1; }
TOTAL=$(cat "$SYS/sriov_totalvfs")

if [ "$ACTION" = down ]; then
    echo 0 > "$SYS/sriov_numvfs"
    echo "VFs removed from $IFACE."
    exit 0
fi

echo "$IFACE supports up to $TOTAL VFs."

# Going through 0 first: the count cannot be changed while VFs already exist.
echo 0 > "$SYS/sriov_numvfs"
echo 2 > "$SYS/sriov_numvfs"
udevadm settle 2>/dev/null || sleep 1

# Fixed MACs, because the kernel hands out random ones on every creation and the generator needs a
# destination it can hard-code.
MAC0=02:00:00:ca:fe:00
MAC1=02:00:00:ca:fe:01
ip link set "$IFACE" vf 0 mac "$MAC0"
ip link set "$IFACE" vf 1 mac "$MAC1"

# A generator forges source MACs and IPs by design. Anti-spoofing would silently drop every frame,
# which looks exactly like a policer and would waste another evening.
for vf in 0 1; do
    ip link set "$IFACE" vf "$vf" spoofchk off 2>/dev/null || \
        echo "  note: spoofchk off refused on vf $vf (driver may not allow it)" >&2
    ip link set "$IFACE" vf "$vf" trust on 2>/dev/null || true
done

# The VF netdevs are the ones sharing the PCI parent of the physical port.
PARENT=$(basename "$(readlink -f "$SYS")")
VFS=""
for d in /sys/class/net/*; do
    n=$(basename "$d")
    [ "$n" = "$IFACE" ] && continue
    [ -e "$d/device/physfn" ] || continue
    p=$(basename "$(readlink -f "$d/device/physfn")")
    [ "$p" = "$PARENT" ] && VFS="$VFS $n"
done

set -- $VFS
VF0=${1:-}
VF1=${2:-}
[ -n "$VF0" ] && [ -n "$VF1" ] || { echo "expected two VF netdevs, found:$VFS" >&2; exit 1; }

for v in "$VF0" "$VF1"; do ip link set "$v" mtu 1500 up; done
ip addr flush dev "$VF0" 2>/dev/null || true
ip addr flush dev "$VF1" 2>/dev/null || true
ip addr add 10.200.0.1/24 dev "$VF0"
ip addr add 10.200.0.2/24 dev "$VF1"

cat <<EOF

  VF0  $VF0  mac $(cat /sys/class/net/$VF0/address)  ip 10.200.0.1   <- generator
  VF1  $VF1  mac $(cat /sys/class/net/$VF1/address)  ip 10.200.0.2   <- DUT

Sanity check first, it costs a second and tells you the VEB is switching at all:
  ping -c3 -I 10.200.0.1 10.200.0.2

Then the rate probe, generator on VF0 towards VF1 (no VLAN id: there is no switch to tag for):
  sh $(dirname "$0")/pps-probe.sh $VF0 $(cat /sys/class/net/$VF1/address) 10.200.0.2 4 20 -

Watch what actually lands, in another shell:
  sar -n DEV 1 25 | grep $VF1

Received close to sent means the card switches at speed and you have a bench with no fabric in it.
Received far below sent means the VEB itself is the ceiling, which is a property of this NIC and
not something to fight. Tear down with: sriov-loopback.sh $IFACE down
EOF
