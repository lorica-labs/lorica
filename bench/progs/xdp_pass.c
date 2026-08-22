/* The floor. Every instrumented measurement subtracts this program's cost, so it
 * has to do nothing at all: no map, no helper, no parsing. What is left is the
 * price of entering and leaving an XDP program on this machine.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}
