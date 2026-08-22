/* Drops UDP to one port and passes everything else: the XDP equivalent of the
 * nftables raw-hook rule in bench/nftables/compare.nft, so the p99 comparison is
 * the same drop on two datapaths rather than two different policies.
 *
 * The port is fixed to 19000, the flood port used by gen-udp-flood.sh. Legitimate
 * probe traffic on other ports is passed up the stack untouched.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define FLOOD_PORT 19000

SEC("xdp")
int xdp_portdrop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* IHL is in 32-bit words; options push the L4 header further in. */
	struct udphdr *udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	if (udp->dest == bpf_htons(FLOOD_PORT))
		return XDP_DROP;

	return XDP_PASS;
}
