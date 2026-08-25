/* Synthetic bench for the layout of a leaky-bucket bank, and for the counter map.
 *
 * The question this fixture exists to answer: a bank in a per-CPU map sees, on each
 * core, only the fraction of the traffic RSS gave that core, so a flood spread over
 * source ports leaves every shard under rho and nothing is dropped while the aggregate
 * exceeds the budget by a factor of N. The corrections are a shared bank, which is exact
 * and can contend, or per-CPU with recalibration, which never contends and is exact only
 * in steady state. Neither is free and the measurement decides.
 *
 * Seven programs rather than one program with a mode global. The variant is then chosen
 * by the name the loader asks for, which costs no patching path and no .rodata question,
 * and each variant compiles or fails on its own.
 *
 * Three facts settled before this file was written, all of which shape it:
 *
 *   - a `struct bpf_spin_lock` is refused in the value of a PERCPU_ARRAY. map_check_btf()
 *     in kernel/bpf/syscall.c allows it for HASH, ARRAY and the storage maps and nothing
 *     else, identically on 6.8, 6.12 and 7.0. So there is no locked per-CPU variant here,
 *     and there cannot be one.
 *   - a per-CPU bucket needs no synchronisation at all. Driver XDP runs inside one NAPI
 *     poll under local_bh_disable() and softirq processing does not nest on a CPU, so no
 *     second run interleaves between the load and the store.
 *   - a map value carries at most ONE lock, at a fixed offset. So "the whole bank in one
 *     entry" means one lock for the whole bank, and every packet reaching the stage
 *     serialises even when the buckets it wants are different. That is the variant named
 *     _bank below, and it is here to be measured rather than assumed.
 *
 * Disposable measurement fixture. It prefigures nothing of the dataplane: the real
 * arithmetic lives in lorica-common and is compiled into the program under test. What
 * is reproduced here is the shape of the memory access and the cost of the guard, which
 * is what the layout decision turns on.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* A bank of a thousand buckets is the top of the ALBUS range the design cites, and it is
 * the map size for every variant. How many buckets the traffic actually touches is a
 * property of the traffic and not of this program: the index is the source port, so the
 * caller chooses the spread by choosing the ports it sends. That is also the dimension
 * that matters, since an untouched bucket contends with nothing and costs no cache line. */
#define BUCKETS 1024

/* Bytes per second and the burst allowance. Fixture values: what is being priced is the
 * arithmetic and the memory access, not this policy. */
#define RHO 1000000ULL
#define BURST 100000ULL
#define NSEC_PER_SEC 1000000000ULL

struct bucket {
	__u64 level;
	__u64 last_ns;
};

/* One lock at offset zero, then the bucket. The kernel finds the lock through BTF, which
 * is why this object is built with -g. */
struct locked_bucket {
	struct bpf_spin_lock lock;
	struct bucket b;
};

struct bank {
	struct bucket b[BUCKETS];
};

struct locked_bank {
	struct bpf_spin_lock lock;
	struct bucket b[BUCKETS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, BUCKETS);
	__type(key, __u32);
	__type(value, struct bucket);
} percpu_entries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bank);
} percpu_bank SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BUCKETS);
	__type(key, __u32);
	__type(value, struct locked_bucket);
} global_locked_entries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct locked_bank);
} global_locked_bank SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BUCKETS);
	__type(key, __u32);
	__type(value, struct bucket);
} global_racing_entries SEC(".maps");

/* The two counter maps of the other question this bench answers: reading fifty thousand
 * per-CPU counters costs 264 ns a slot because the kernel copies one value per possible
 * CPU, and the way out is a shared mmappable array — which BPF_F_MMAPABLE only offers for
 * a non-per-CPU array, so it puts an atomic add on the packet path. That is the same
 * trade-off as the bank, so it is priced on the same bench. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} counters_shared SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} counters_percpu SEC(".maps");

/* Takes the source port and the length out of a UDP packet. The index of the bucket is
 * the port, so the caller steers the distribution from the wire.
 *
 * The length comes from the IP header and not from `data_end - data`, and that is not a
 * matter of taste. The two ctx fields are packet pointers, so their difference is
 * pointer-derived; the compiler spills it across the critical section of the locked
 * variants and the verifier answers `invalid size of register spill`. A header field is a
 * plain scalar with no provenance, it spills, and it is what the real stage would charge
 * anyway. */
static __always_inline int parse_udp(struct xdp_md *ctx, __u32 *port, __u32 *size)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->protocol != IPPROTO_UDP)
		return -1;

	struct udphdr *udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return -1;

	*port = bpf_ntohs(udp->source);
	*size = bpf_ntohs(ip->tot_len);
	return 0;
}

/* The bound is a compare and not a mask. A mask is what LLVM moves or drops when it
 * believes it knows a range, and the verifier then sees an index of unknown width; the
 * previous phase paid hours for that lesson on a stack buffer. A compare leaves the
 * verifier a bound it can prove. */
static __always_inline __u32 bucket_index(__u32 port)
{
	if (port >= BUCKETS)
		port = 0;
	return port;
}

static __always_inline int charge(struct bucket *b, __u64 now, __u32 size)
{
	__u64 last = b->last_ns;
	__u64 dt = now > last ? now - last : 0;
	__u64 drain = (dt * RHO) / NSEC_PER_SEC;
	__u64 level = b->level > drain ? b->level - drain : 0;

	level += size;
	b->level = level;
	b->last_ns = now;
	return level > BURST;
}

/* One entry per bucket, per-CPU, no guard. The floor of the comparison: what the bank
 * costs when nothing is shared and nothing is protected. */
SEC("xdp")
int xdp_bucket_percpu_entry(struct xdp_md *ctx)
{
	__u32 port, size;
	if (parse_udp(ctx, &port, &size))
		return XDP_PASS;

	__u32 key = bucket_index(port);
	struct bucket *b = bpf_map_lookup_elem(&percpu_entries, &key);
	if (!b)
		return XDP_PASS;

	return charge(b, bpf_ktime_get_ns(), size) ? XDP_DROP : XDP_PASS;
}

/* The whole bank inside one per-CPU entry, indexed after the dereference. One lookup
 * instead of one per packet, and the index is attacker-influenced, which is exactly the
 * shape the verifier refuses when the bound is a mask. */
SEC("xdp")
int xdp_bucket_percpu_bank(struct xdp_md *ctx)
{
	__u32 port, size;
	if (parse_udp(ctx, &port, &size))
		return XDP_PASS;

	__u32 zero = 0;
	struct bank *bank = bpf_map_lookup_elem(&percpu_bank, &zero);
	if (!bank)
		return XDP_PASS;

	__u32 key = bucket_index(port);
	return charge(&bank->b[key], bpf_ktime_get_ns(), size) ? XDP_DROP : XDP_PASS;
}

/* One entry per bucket, shared across CPUs, one lock per entry. Exact at every instant,
 * and two helper calls more per packet than the per-CPU variants. Packets aiming at
 * different buckets take different locks, so this is the variant whose contention is
 * supposed to follow the distribution of the traffic. */
SEC("xdp")
int xdp_bucket_global_lock_entry(struct xdp_md *ctx)
{
	__u32 port, size;
	if (parse_udp(ctx, &port, &size))
		return XDP_PASS;

	__u32 key = bucket_index(port);
	struct locked_bucket *e = bpf_map_lookup_elem(&global_locked_entries, &key);
	if (!e)
		return XDP_PASS;

	__u64 now = bpf_ktime_get_ns();

	bpf_spin_lock(&e->lock);
	int over = charge(&e->b, now, size);
	bpf_spin_unlock(&e->lock);

	return over ? XDP_DROP : XDP_PASS;
}

/* The whole bank in one shared entry. A map value carries at most one lock, so there is
 * one lock for a thousand buckets and every packet serialises on the same cache line
 * even under a uniform distribution. Strictly worse than the pathology the design feared,
 * which was an attack concentrated on a single bucket. Measured, not assumed. */
SEC("xdp")
int xdp_bucket_global_lock_bank(struct xdp_md *ctx)
{
	__u32 port, size;
	if (parse_udp(ctx, &port, &size))
		return XDP_PASS;

	__u32 zero = 0;
	struct locked_bank *bank = bpf_map_lookup_elem(&global_locked_bank, &zero);
	if (!bank)
		return XDP_PASS;

	__u32 key = bucket_index(port);
	__u64 now = bpf_ktime_get_ns();

	bpf_spin_lock(&bank->lock);
	int over = charge(&bank->b[key], now, size);
	bpf_spin_unlock(&bank->lock);

	return over ? XDP_DROP : XDP_PASS;
}

/* Shared, one entry per bucket, and no guard at all: two cores charging the same bucket
 * can lose an update. The level is then approached from below, so the leak is bounded by
 * how many cores hit one bucket at once — which is the quantity this bench measures. It
 * costs nothing per packet, which is the whole reason to price it. */
SEC("xdp")
int xdp_bucket_global_race(struct xdp_md *ctx)
{
	__u32 port, size;
	if (parse_udp(ctx, &port, &size))
		return XDP_PASS;

	__u32 key = bucket_index(port);
	struct bucket *b = bpf_map_lookup_elem(&global_racing_entries, &key);
	if (!b)
		return XDP_PASS;

	return charge(b, bpf_ktime_get_ns(), size) ? XDP_DROP : XDP_PASS;
}

/* What a counter bump costs today: a per-CPU lookup and a plain add. */
SEC("xdp")
int xdp_counter_percpu(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *slot = bpf_map_lookup_elem(&counters_percpu, &key);
	if (!slot)
		return XDP_PASS;

	*slot += 1;
	return XDP_PASS;
}

/* What it would cost on a shared array, which is the only kind BPF_F_MMAPABLE offers:
 * an atomic add on a line every CPU wants. All packets bump slot zero, which is the
 * worst case and also the realistic one for a counter that counts everything. */
SEC("xdp")
int xdp_counter_shared(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *slot = bpf_map_lookup_elem(&counters_shared, &key);
	if (!slot)
		return XDP_PASS;

	__sync_fetch_and_add(slot, 1);
	return XDP_PASS;
}
