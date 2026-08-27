//! `BPF_MAP_*_BATCH` against the real maps of the program.
//!
//! The program itself is never loaded here: the verifier has five other files, and what
//! this one has to establish is that a raw syscall writing into a caller buffer agrees
//! with the kernel about how long that buffer is. So the maps are created from the
//! object, written through one path and read back through the other — aya's
//! single-element lookup on one side, the batch syscall on the other. Two disagreeing
//! implementations is the whole point; a batch read compared against itself proves
//! nothing.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    os::fd::BorrowedFd,
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, MapData,
        lpm_trie::{Key, LpmTrie},
    },
};
use lorica_common::{Action, CounterId, CounterLayout, LpmKey, LpmValue};
use lorica_dataplane::maps::{self, Counters, lpm};
use support::run::object_path;

/// Small and, above all, not a multiple of any batch size used below: the partial last
/// batch is where a length error lives.
const LIST_ENTRIES: u32 = 64;
const COUNTER_ENTRIES: u32 = CounterId::COUNT + LIST_ENTRIES;

thread_local! {
    /// Per thread, not global: the test harness runs these in parallel, and a shared
    /// counter would be measuring whichever other test happened to allocate. Const
    /// initialised and `Drop`-free, so reading it from inside the allocator cannot
    /// allocate on its own.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Counts allocations, so "allocates nothing per read" can be a test rather than a
/// sentence in a doc comment. The agent's tick is asserted the same way and cannot pass
/// if the counter read allocates, which makes this the cheapest place to catch a `Vec`
/// creeping back into the hot path.
struct Counting;

// SAFETY: every method forwards to the system allocator unchanged, with the same
// pointer and the same layout it was given. Counting has no state of its own that a
// caller could invalidate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        // SAFETY: layout comes from the caller and crosses unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr was returned by System.alloc for this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The maps of the program, sized here rather than taken from the object defaults, so a
/// change to `DEFAULT_LIST_ENTRIES` in `lorica-ebpf` cannot silently make the batch
/// sizes below divide evenly.
fn maps() -> Ebpf {
    let path = object_path();
    let object = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    let layout = layout();
    let mut loader = EbpfLoader::new();
    // Both halves of the counter map through one call: the entry count and the stripe width
    // the program indexes it with are one decision, and a fixture that set only the first
    // would be testing a reader against a map the program writes differently.
    maps::size_counters(&mut loader, &layout)
        .map_max_entries("UNIFIED_LIST", LIST_ENTRIES)
        .load(&object)
        .unwrap_or_else(|err| panic!("creating the maps of {} failed: {err}", path.display()))
}

/// The counter layout this file's map is created with, on this machine.
fn layout() -> CounterLayout {
    maps::counter_layout(COUNTER_ENTRIES).expect("no counter layout for this machine")
}

/// Writes one processor's copy of one slot, at the flat index the program would compute.
///
/// Writing every stripe of a slot with a **distinct** value is what a running packet could
/// never do — a packet touches the stripe of the one processor it ran on — and it is what makes
/// a wrong stride visible: over a map of zeros, any stride looks correct.
fn write_stripe(ebpf: &mut Ebpf, layout: CounterLayout, cpu: u32, slot: u32, value: u64) {
    let map = ebpf.map_mut("COUNTERS").expect("no COUNTERS map");
    let mut counters: Array<&mut MapData, u64> =
        Array::try_from(map).expect("COUNTERS is not a flat array");
    counters
        .set(layout.index(cpu, slot), value, 0)
        .unwrap_or_else(|err| panic!("writing stripe {cpu} of slot {slot} failed: {err}"));
}

/// Fills every stripe of every slot with a value derived from both, so a value read into the
/// wrong slot or out of the wrong stripe is visible. Returns the expected sum per slot.
fn fill(ebpf: &mut Ebpf, layout: CounterLayout) -> Vec<u64> {
    let mut expected = vec![0u64; layout.slots as usize];
    for cpu in 0..layout.cpus {
        for slot in 0..layout.slots {
            let value = u64::from(slot) * 1_000 + u64::from(cpu) + 1;
            write_stripe(ebpf, layout, cpu, slot, value);
            expected[slot as usize] += value;
        }
    }
    expected
}

fn counters_fd(ebpf: &Ebpf) -> BorrowedFd<'_> {
    maps::fd(ebpf, "COUNTERS").expect("no COUNTERS map in the object")
}

fn list_fd(ebpf: &Ebpf) -> BorrowedFd<'_> {
    maps::fd(ebpf, "UNIFIED_LIST").expect("no UNIFIED_LIST map in the object")
}

/// A local wrapper so `Pod` can be implemented for a foreign type, as in the shared
/// test support.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodValue(LpmValue);

// SAFETY: LpmValue is Copy and 'static, and every value read out of this map was
// written into it by this file.
unsafe impl aya::Pod for PodValue {}

fn entry(counter_slot: u32) -> LpmValue {
    let mut value = LpmValue::zeroed();
    value.action = Action::Drop;
    value.counter_idx = counter_slot;
    value
}

fn host(i: u32) -> LpmKey {
    LpmKey::v4([10, 0, (i >> 8) as u8, i as u8], 32)
}

/// The batch walk of the striped array against the kernel's own single-element lookup.
///
/// **What can go wrong and what this catches.** The map is one flat array of `stripe × cpus`
/// eight-byte values and a slot's total is the sum over every stripe, so the reader has to
/// reduce a flat index to a slot with the same arithmetic the program used to produce it. A
/// stride off by one puts one processor's values under another slot; a stripe width that
/// forgot its cache-line rounding folds padding into a real slot. Every stripe of every slot
/// is written with a distinct value, which no running packet could produce, because over a
/// map of zeros any arithmetic looks right.
#[test]
fn a_batch_read_sums_the_stripes_the_single_element_lookup_does() {
    let mut ebpf = maps();
    let layout = layout();
    let expected = fill(&mut ebpf, layout);

    // The kernel's own lookup, one element at a time, summed the same way. Two
    // implementations disagreeing is the whole point; a batch read compared against itself
    // proves nothing.
    for slot in [
        CounterId::LpmAllowExit.index(),
        CounterId::COUNT + 3,
        COUNTER_ENTRIES - 1,
    ] {
        let one_by_one = maps::counter_at(&ebpf, COUNTER_ENTRIES, slot)
            .expect("the single-element read of a slot failed");
        assert_eq!(
            one_by_one, expected[slot as usize],
            "slot {slot} has to read the sum of its {} stripes",
            layout.cpus
        );
    }

    // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout.
    let mut reader = unsafe { Counters::batched(counters_fd(&ebpf), layout, 16) };
    let read = reader.read().expect("the batch read of COUNTERS failed");
    assert_eq!(read.len(), COUNTER_ENTRIES as usize);
    assert_eq!(
        read,
        &expected[..],
        "the batch walk and the single-element lookup disagree about at least one slot"
    );
}

/// The mapped read and the batch walk, on the same known state.
///
/// This is the assertion that makes keeping two implementations defensible. The whole point
/// of `BPF_F_MMAPABLE` is that the agent stops asking the kernel for these numbers, and the
/// only way to know it is reading the same numbers is to read them both ways: the mapping has
/// to reduce a flat offset to a slot exactly as the batch walk reduces a flat *key*, and
/// nothing but a comparison catches an off-by-a-stripe in one of them.
///
/// The state is written from userspace rather than by running traffic, because what is under
/// test is the arithmetic of two readers and not what increments a counter.
#[test]
fn the_mapped_read_and_the_batch_walk_agree() {
    let mut ebpf = maps();
    let layout = layout();
    let expected = fill(&mut ebpf, layout);

    // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout, and it
    // carries BPF_F_MMAPABLE because that is how `lorica-ebpf` declares it.
    let mut mapped = unsafe { Counters::open(counters_fd(&ebpf), layout, 16) };
    assert!(
        mapped.is_mapped(),
        "the counter array refused to map, so this kernel or this object cannot carry the \
         design at all: {:?}",
        mapped.unmapped().map(ToString::to_string)
    );
    // SAFETY: as above.
    let mut batched = unsafe { Counters::batched(counters_fd(&ebpf), layout, 16) };

    let from_batch = batched.read().expect("the batch walk failed").to_vec();
    let from_mapping = mapped.read().expect("the mapped read failed");

    assert_eq!(
        from_mapping,
        &expected[..],
        "the mapped read disagrees with what was written"
    );
    assert_eq!(
        from_mapping,
        &from_batch[..],
        "the two read paths disagree, so one of them reduces a stripe wrong and the agent's \
         counters depend on which one the kernel allowed"
    );
    // The number the conversion was about: the mapped path asks the kernel for nothing.
    assert_eq!(mapped.walked(), 0);
    assert_eq!(batched.walked(), layout.entries() as usize);
}

/// The batch size decides how many elements one syscall asks for, never how many it gets.
/// The last batch of a walk is short, and a batch larger than the map is a single short
/// one: those are the two lengths at which a caller that trusts its own batch size
/// instead of the count the kernel wrote back reads — or writes — past the end.
#[test]
fn every_batch_size_reads_the_same_map() {
    let mut ebpf = maps();
    let layout = layout();
    let expected = fill(&mut ebpf, layout);

    let read = |batch| {
        // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout.
        let mut reader = unsafe { Counters::batched(counters_fd(&ebpf), layout, batch) };
        reader
            .read()
            .unwrap_or_else(|err| panic!("a batch of {batch} failed: {err}"))
            .to_vec()
    };
    assert_eq!(read(1), expected, "a batch of one read something else");

    // 7 and 13 divide neither the slot count nor the entry count; the last three cover a
    // batch just under the map, one exactly its size, and one larger than it exists.
    let entries = layout.entries();
    for batch in [7, 13, entries - 1, entries, entries + 5] {
        assert_eq!(
            read(batch),
            expected,
            "a batch of {batch} read something else"
        );
    }
}

/// Neither reader may allocate after its constructor. The tick holds one and is asserted to
/// allocate nothing at all, and aya's typed lookups box a value per slot: the naive path is
/// one allocation per counter per tick, fifty thousand of them ten times a second.
#[test]
fn a_read_after_the_first_allocates_nothing() {
    let ebpf = maps();
    let layout = layout();
    for name in ["mapped or batched", "batched"] {
        // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout.
        let mut reader = unsafe {
            if name == "batched" {
                Counters::batched(counters_fd(&ebpf), layout, 16)
            } else {
                Counters::open(counters_fd(&ebpf), layout, 16)
            }
        };
        // The first read is the one entitled to touch the allocator, and it does not either:
        // every buffer was sized by the constructor.
        reader.read().expect("the first read failed");

        let before = ALLOCATIONS.get();
        reader.read().expect("the second read failed");
        let after = ALLOCATIONS.get();
        assert_eq!(
            after, before,
            "the {name} reader allocated; the tick that holds it is asserted not to"
        );
    }
}

/// The unified list written by raw batch syscall, read back by the kernel's own
/// single-element lookup. The key layout is the risk: `prefix_len` is a `u32` in front
/// of the address, the kernel strides the buffer by its own key size, and a list that
/// went in shifted by four bytes would still return `Ok`.
#[test]
fn batch_written_list_entries_read_back_one_by_one() {
    let ebpf = maps();
    let entries: Vec<(LpmKey, LpmValue)> = (0..10).map(|i| (host(i), entry(i))).collect();

    // A chunk that does not divide ten, so the last syscall is a short one.
    lpm::load(list_fd(&ebpf), &entries, 3).expect("the batch update of UNIFIED_LIST failed");

    let map = ebpf.map("UNIFIED_LIST").expect("no UNIFIED_LIST map");
    let list: LpmTrie<&MapData, [u8; 16], PodValue> =
        LpmTrie::try_from(map).expect("UNIFIED_LIST is not an LPM trie");
    for (key, value) in &entries {
        let found = list
            .get(&Key::new(key.prefix_len, key.addr), 0)
            .unwrap_or_else(|err| panic!("{key:?} is not in the list: {err}"));
        assert_eq!(
            found.0, *value,
            "the entry read back is not the one written"
        );
    }

    let absent = host(4_000);
    assert!(
        list.get(&Key::new(absent.prefix_len, absent.addr), 0)
            .is_err(),
        "an address no entry covers has to miss, or the write went in at the wrong key"
    );
}

/// A list that does not fit is an error, not a truncated write. The kernel writes back
/// how many elements it managed and fails the call; a caller that reads only the return
/// code loads a blocklist missing its tail and never learns.
#[test]
fn a_list_longer_than_the_map_is_refused_rather_than_truncated() {
    let ebpf = maps();
    let entries: Vec<(LpmKey, LpmValue)> = (0..LIST_ENTRIES + 8)
        .map(|i| (host(i), entry(CounterId::COUNT + i)))
        .collect();

    let err = lpm::load(list_fd(&ebpf), &entries, entries.len())
        .expect_err("a list of 72 entries in a map of 64 has to fail");
    // The count is in the message because the operator's question is "how much of my
    // list is loaded", and errno alone does not answer it.
    assert!(
        err.to_string().contains(&LIST_ENTRIES.to_string()),
        "the error has to say how many entries went in, got: {err}"
    );
}

/// `memlock` is the kernel's own accounting of what a map costs, and it is the number
/// the memlock budget of a deployment profile is checked against. An `LPM_TRIE` is
/// `BPF_F_NO_PREALLOC`, so it starts at nothing and grows per inserted prefix: if this
/// field ever stops being readable, it has to fail here and not halfway through a
/// measurement campaign.
#[test]
fn the_list_memlock_grows_with_the_entries_written() {
    let ebpf = maps();
    let empty = maps::memlock_bytes(list_fd(&ebpf)).expect("cannot read the memlock of the list");

    let entries: Vec<(LpmKey, LpmValue)> = (0..LIST_ENTRIES).map(|i| (host(i), entry(i))).collect();
    lpm::load(list_fd(&ebpf), &entries, 16).expect("the batch update failed");

    let full = maps::memlock_bytes(list_fd(&ebpf)).expect("cannot read the memlock of the list");
    assert!(
        full > empty,
        "{LIST_ENTRIES} prefixes have to show up in memlock, went from {empty} to {full}"
    );

    // The counter array is preallocated, so its own memlock is already whole and is the one
    // place the processor count of the budget can be checked against a machine. Against
    // `entries()` and not against `slots`: the map carries one stripe per possible processor,
    // which is the whole reason the memlock model multiplies by a processor count.
    let layout = layout();
    let counters =
        maps::memlock_bytes(counters_fd(&ebpf)).expect("cannot read the memlock of the counters");
    assert!(
        counters >= layout.bytes(),
        "an array of {} u64 ({} slots x {} processors) cannot cost less than eight bytes each, \
         got {counters}",
        layout.entries(),
        layout.stripe,
        layout.cpus,
    );
}

/// A reader built for the named counters must read the named counters, and not the whole
/// map with the rest thrown away.
///
/// This is a cost assertion disguised as a correctness one, and it is here because the
/// first version of the agent paid for it: the read walked to the end of the map whatever
/// it was built for, so adding a cheap reader over eighteen slots doubled the CPU of the
/// tick instead of costing nothing. The cost is exactly linear in elements walked, so
/// elements walked is the thing to assert on.
///
/// **What "the whole map" now means.** The map is `stripe × cpus` elements and a slot's total
/// is the sum over its stripes, so a reader over the named counters does not read fewer
/// stripes — it reads a narrower window inside each of them. What it walks is therefore
/// `stripe(named) × cpus`, and the saving is the same one it always was: linear in the slots
/// asked for.
#[test]
fn a_reader_built_for_fewer_slots_walks_fewer_slots() {
    let ebpf = maps();

    let whole = maps::counter_layout(COUNTER_ENTRIES).expect("layout for the whole map");
    let named = maps::counter_layout(CounterId::COUNT).expect("layout for the named counters");
    assert!(
        named.entries() < whole.entries(),
        "a reader over {} slots has to be created for fewer elements than one over {}",
        CounterId::COUNT,
        COUNTER_ENTRIES
    );

    // The batch reader and not the mapped one: what is asserted is elements asked of the
    // kernel, and the mapped path asks for none either way.
    //
    // SAFETY: COUNTERS is the flat array of u64 `maps()` created, and both layouts describe a
    // prefix of it — the narrow one has a shorter stripe, so it walks a shorter map rather
    // than a differently shaped one.
    let mut whole_reader = unsafe { Counters::batched(counters_fd(&ebpf), whole, 1_000) };
    whole_reader.read().expect("read failed");
    assert_eq!(whole_reader.walked(), whole.entries() as usize);

    // SAFETY: as above.
    let mut named_reader = unsafe { Counters::batched(counters_fd(&ebpf), named, 1_000) };
    named_reader.read().expect("read failed");
    assert_eq!(
        named_reader.walked(),
        named.entries() as usize,
        "a reader over {} slots asked the kernel for {} elements against the {} the whole map \
         costs, so it either buys a fraction of the data for a fraction of the price or it \
         pays for all of it",
        CounterId::COUNT,
        named_reader.walked(),
        whole.entries(),
    );
}

/// The incremental sweep: `stride` reads have to see what one read sees, and each of them
/// has to cost about a `stride`-th of it.
///
/// Both halves matter and neither implies the other. A window that advanced by the wrong
/// amount would still cover the map eventually and would read some elements twice and others
/// never — so the sums are compared against what was written, slot by slot, and the element
/// counts are compared against the map size. A stride that quietly did nothing would pass the
/// first assertion on its own.
///
/// **Why the totals only appear at the end of a pass.** A slot's total is the sum over every
/// processor's stripe, and a partial pass has reached only some of them: publishing that would
/// report a collapse that did not happen. So a pass accumulates and the last completed pass is
/// what a caller reads, which is what makes the staleness a lower bound rather than a lie.
///
/// 5 divides neither the slot count nor the entry count, so the last window of a pass is short
/// and the pass wraps from a partial window rather than from an exact boundary. That is where
/// an off-by-one lives.
#[test]
fn a_strided_reader_covers_the_map_in_stride_reads() {
    let mut ebpf = maps();
    let layout = layout();
    let expected = fill(&mut ebpf, layout);

    const STRIDE: u32 = 5;
    // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout.
    let mut strided =
        unsafe { Counters::batched(counters_fd(&ebpf), layout, 16) }.with_stride(STRIDE);
    let entries = layout.entries() as usize;
    let window = entries.div_ceil(STRIDE as usize);

    // Two whole passes, so the wrap is exercised and not only the first pass.
    for pass in 0..2 {
        let mut asked = 0usize;
        for read in 0..STRIDE {
            let got = strided
                .read()
                .unwrap_or_else(|err| panic!("pass {pass}, read {read} failed: {err}"));
            assert_eq!(got.len(), layout.slots as usize);
            assert!(
                strided.walked() <= window,
                "pass {pass}, read {read} walked {} elements where a stride of {STRIDE} over \
                 {entries} allows {window}: the whole point is the divided cost",
                strided.walked()
            );
            asked += strided.walked();
        }
        // A pass is a pass: `stride` reads and the map is covered, no more and no less.
        assert_eq!(
            asked, entries,
            "pass {pass} asked the kernel for {asked} elements over {STRIDE} reads, and the map \
             has {entries}"
        );
        // The pass that just ended is the one published, so this read — the first of the next
        // one — hands back its totals.
        assert_eq!(
            strided.read().expect("a read past the pass failed"),
            expected.as_slice(),
            "after pass {pass} every slot has to carry the sum of its stripes; a window that \
             advanced wrong reads some elements twice and others never"
        );
    }
}

/// The reader that skips nothing is the default, and it stays the default.
///
/// The stride is a knob an operator sets, so the value it has when nobody sets it is part of
/// the contract: one, meaning the whole map per read, which is what every other assertion in
/// this file is written against.
#[test]
fn a_reader_covers_the_whole_map_unless_told_otherwise() {
    let ebpf = maps();
    let layout = layout();
    // SAFETY: COUNTERS is the flat array of u64 `maps()` created from this layout.
    let reader = unsafe { Counters::batched(counters_fd(&ebpf), layout, 16) };
    assert_eq!(reader.stride(), 1);
    // Zero would claim no elements and finish no pass. The agent refuses it at the flag; the
    // reader cannot be made to hold it either.
    assert_eq!(reader.with_stride(0).stride(), 1);

    // And the mapped path has no stride to spread: there is no per-element syscall cost, so
    // asking for one has to leave it reading everything rather than a fifth of it.
    //
    // SAFETY: as above.
    let mapped = unsafe { Counters::open(counters_fd(&ebpf), layout, 16) }.with_stride(5);
    assert!(mapped.is_mapped());
    assert_eq!(mapped.stride(), 1);
}
