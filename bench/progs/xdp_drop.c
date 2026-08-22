/* Drops everything, so a rate measurement counts what the transport delivered
 * rather than what the guest's stack survived. Used to find the ceiling of the
 * bridge and vhost-net path, which bounds every attack axis in this phase.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}
