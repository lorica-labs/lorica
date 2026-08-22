/* What a reverse-path lookup costs, against the lookup the pipeline already pays.
 *
 * Stage 5 asks the kernel where it would send a packet addressed to this packet's source,
 * and refuses the packet if the answer is not the interface it arrived on. That is one
 * `bpf_fib_lookup` per packet, and the stage is only worth its place if that call is not
 * dramatically more expensive than the LPM trie lookup stage 3 already performs. This
 * fixture prices the two side by side, on the same frame, in the same harness.
 *
 * Both programs answer XDP_PASS whatever they find. Pricing a call is not deciding with
 * it, and a program that dropped would measure a shorter path than the one being priced.
 * The return code of the FIB lookup is counted instead, so a reader knows which path was
 * priced rather than assuming the interesting one.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* The interface the lookup is asked about. Loopback, because a test-run frame carries no
 * ingress interface and a fixture must not depend on the name a NIC happens to have on
 * one machine. What is being priced is the walk of the routing table, which the main table
 * decides; the interface picks the table, and both programs pick the same one. The report
 * says this, because an operator reading a nanosecond figure deserves to know the lookup
 * was not the one their host performs. */
#define IFINDEX 1

/* `-target bpf` does not reach the socket headers that define this, and pulling them in
 * for one constant drags in a lot that does not compile for this target. */
#define AF_INET_ 2

struct lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u64);
} reverse_list SEC(".maps");

/* One slot per return code of bpf_fib_lookup, so the priced path is named and not guessed.
 * BPF_FIB_LKUP_RET_* runs from 0 to 7 on the kernel floor. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} fib_returns SEC(".maps");

static __always_inline __u32 *source_of(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;

	return &ip->saddr;
}

/* The reverse path lookup: where would the kernel send a packet addressed to this
 * packet's source? */
SEC("xdp")
int xdp_fib_reverse(struct xdp_md *ctx)
{
	__u32 *src = source_of(ctx);
	if (!src)
		return XDP_PASS;

	struct bpf_fib_lookup params = {};
	params.family = AF_INET_;
	params.ifindex = IFINDEX;
	params.ipv4_dst = *src;

	__u32 code = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT);
	__u32 slot = code < 16 ? code : 15;
	__u64 *seen = bpf_map_lookup_elem(&fib_returns, &slot);
	if (seen)
		*seen += 1;

	return XDP_PASS;
}

/* The same question asked of an LPM trie, which is the lookup stage 3 already performs
 * once per packet. The key is the full width of the address, so the trie answers with the
 * longest entry covering it, exactly as the unified list is queried. */
SEC("xdp")
int xdp_lpm_reverse(struct xdp_md *ctx)
{
	__u32 *src = source_of(ctx);
	if (!src)
		return XDP_PASS;

	struct lpm_key key = {};
	key.prefixlen = 128;
	/* IPv4 mapped into the 128-bit key, the shape the unified list uses. */
	key.addr[10] = 0xff;
	key.addr[11] = 0xff;
	__builtin_memcpy(&key.addr[12], src, 4);

	__u64 *value = bpf_map_lookup_elem(&reverse_list, &key);
	if (value)
		*value += 1;

	return XDP_PASS;
}
