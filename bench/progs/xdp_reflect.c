/* Bounces IPv4 frames back out of the interface they arrived on, to find the
 * XDP_TX ceiling of virtio. Only exists for that measurement.
 *
 * Nothing recomputes the IPv4 header checksum, and nothing needs to: the sum is
 * over the whole header, so exchanging two of its 32-bit fields leaves it
 * unchanged. Ethernet addresses are not covered by it at all.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_reflect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;

	__u8 mac[ETH_ALEN];
	__builtin_memcpy(mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, mac, ETH_ALEN);

	__be32 addr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = addr;

	return XDP_TX;
}
