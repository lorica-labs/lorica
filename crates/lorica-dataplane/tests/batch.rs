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
        MapData, PerCpuArray, PerCpuValues,
        lpm_trie::{Key, LpmTrie},
    },
    util::nr_cpus,
};
use lorica_common::{Action, CounterId, LpmKey, LpmValue};
use lorica_dataplane::maps::{self, lpm};
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
    EbpfLoader::new()
        .map_max_entries("UNIFIED_LIST", LIST_ENTRIES)
        .map_max_entries("COUNTERS", COUNTER_ENTRIES)
        .load(&object)
        .unwrap_or_else(|err| panic!("creating the maps of {} failed: {err}", path.display()))
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

/// A per-CPU batch lookup returns one value per **possible** processor for every key it
/// returns, so the caller buffer is `count × num_possible_cpus` values long and nothing
/// else. A stride short by one processor is an out-of-bounds write; a stride too long
/// reads the next key's values as if they belonged to this one.
///
/// Every processor slot is written with a distinct value, which running a packet could
/// never do — a packet touches the slot of the one processor it ran on, and a wrong
/// stride over a vector of zeros looks perfectly correct.
#[test]
fn a_batch_read_sums_the_same_processors_the_single_element_lookup_does() {
    let mut ebpf = maps();
    let cpus = nr_cpus().expect("cannot read the possible processor count");

    let written: Vec<(u32, Vec<u64>)> = [
        CounterId::LpmAllowExit.index(),
        CounterId::COUNT + 3,
        COUNTER_ENTRIES - 1,
    ]
    .into_iter()
    .map(|slot| {
        let values = (0..cpus)
            .map(|cpu| u64::from(slot) * 1_000 + cpu as u64 + 1)
            .collect();
        (slot, values)
    })
    .collect();

    {
        let map = ebpf.map_mut("COUNTERS").expect("no COUNTERS map");
        let mut counters: PerCpuArray<&mut MapData, u64> =
            PerCpuArray::try_from(map).expect("COUNTERS is not a per-CPU array");
        for (slot, values) in &written {
            counters
                .set(
                    *slot,
                    PerCpuValues::try_from(values.clone()).expect("wrong number of processors"),
                    0,
                )
                .expect("writing a counter slot failed");
        }
    }

    let mut reader =
        maps::counters(&ebpf, COUNTER_ENTRIES, 16).expect("cannot build the counter reader");
    let read = reader.read().expect("the batch read of COUNTERS failed");

    assert_eq!(read.len(), COUNTER_ENTRIES as usize);
    for (slot, values) in &written {
        assert_eq!(
            read[*slot as usize],
            values.iter().sum::<u64>(),
            "slot {slot} has to read the sum of its {cpus} processor values"
        );
    }
    // The one assertion a wrong stride cannot survive: anything read into a slot that
    // was never written means the values of one key landed under another key.
    assert_eq!(
        read.iter().sum::<u64>(),
        written.iter().map(|(_, v)| v.iter().sum::<u64>()).sum(),
        "every slot that was not written has to still read zero"
    );
}

/// The batch size decides how many keys one syscall asks for, never how many it gets.
/// The last batch of a walk is short, and a batch larger than the map is a single short
/// one: those are the two lengths at which a caller that trusts its own batch size
/// instead of the count the kernel wrote back reads — or writes — past the end.
#[test]
fn every_batch_size_reads_the_same_map() {
    let mut ebpf = maps();
    {
        let map = ebpf.map_mut("COUNTERS").expect("no COUNTERS map");
        let mut counters: PerCpuArray<&mut MapData, u64> =
            PerCpuArray::try_from(map).expect("COUNTERS is not a per-CPU array");
        let cpus = nr_cpus().expect("cannot read the possible processor count");
        for slot in 0..COUNTER_ENTRIES {
            let values: Vec<u64> = (0..cpus).map(|cpu| u64::from(slot) + cpu as u64).collect();
            counters
                .set(slot, PerCpuValues::try_from(values).unwrap(), 0)
                .expect("writing a counter slot failed");
        }
    }

    let read = |batch| {
        maps::counters(&ebpf, COUNTER_ENTRIES, batch)
            .unwrap_or_else(|err| panic!("cannot build a reader for a batch of {batch}: {err}"))
            .read()
            .unwrap_or_else(|err| panic!("a batch of {batch} failed: {err}"))
            .to_vec()
    };
    let reference = read(1);
    assert!(reference.iter().all(|&value| value != 0));

    // 7 and 13 do not divide 82; the last three cover a batch just under the map, one
    // exactly its size, and one larger than it exists.
    for batch in [
        7,
        13,
        COUNTER_ENTRIES - 1,
        COUNTER_ENTRIES,
        COUNTER_ENTRIES + 5,
    ] {
        assert_eq!(
            read(batch),
            reference,
            "a batch of {batch} read something else"
        );
    }
}

/// The reader exists so a tick can hold it and read through it forever. aya's
/// `PerCpuArray::get` boxes a slice per slot, so the naive path is one allocation per
/// counter per tick — fifty thousand of them, ten times a second — and the assertion
/// that the tick allocates nothing could never pass with it.
#[test]
fn a_read_after_the_first_allocates_nothing() {
    let ebpf = maps();
    let mut reader =
        maps::counters(&ebpf, COUNTER_ENTRIES, 16).expect("cannot build the counter reader");
    // The first read is the one entitled to touch the allocator, and it does not either:
    // every buffer was sized by the constructor.
    reader.read().expect("the first read failed");

    let before = ALLOCATIONS.get();
    reader.read().expect("the second read failed");
    let after = ALLOCATIONS.get();
    assert_eq!(
        after, before,
        "a read allocated; the tick that holds this reader is asserted not to"
    );
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

    // The per-CPU counter array is preallocated, so its own memlock is already whole
    // and is the one place the processor count of the budget can be checked against a
    // machine.
    let counters =
        maps::memlock_bytes(counters_fd(&ebpf)).expect("cannot read the memlock of the counters");
    assert!(
        counters >= u64::from(COUNTER_ENTRIES) * 8,
        "a per-CPU array of {COUNTER_ENTRIES} u64 cannot cost less than one value each, got {counters}"
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
#[test]
fn a_reader_built_for_fewer_slots_walks_fewer_slots() {
    let ebpf = maps();
    let slots = COUNTER_ENTRIES;

    let mut whole = maps::counters(&ebpf, slots, 1_000).expect("reader over the whole map");
    whole.read().expect("read failed");
    assert_eq!(whole.walked(), slots as usize);

    let named = CounterId::COUNT;
    let mut head = maps::counters(&ebpf, named, 1_000).expect("reader over the named counters");
    head.read().expect("read failed");
    assert_eq!(
        head.walked(),
        named as usize,
        "a reader over {named} slots asked the kernel for {} elements, so it costs what          the whole map costs and buys a fraction of it",
        head.walked()
    );
}

/// The incremental sweep: `stride` reads have to see what one read sees, and each of them
/// has to cost about a `stride`-th of it.
///
/// Both halves matter and neither implies the other. A window that advanced by the wrong
/// amount would still cover the map eventually and would read some slots twice and others
/// never — so the sums are compared against the whole-map read, slot by slot, and the
/// element counts are compared against the map size. A stride that quietly did nothing
/// would pass the first assertion on its own.
///
/// 5 does not divide 82, so the last window of a pass is short and the pass has to wrap from
/// a partial window rather than from an exact boundary. That is where an off-by-one lives.
#[test]
fn a_strided_reader_covers_the_map_in_stride_reads() {
    let mut ebpf = maps();
    let cpus = nr_cpus().expect("cannot read the possible processor count");
    {
        let map = ebpf.map_mut("COUNTERS").expect("no COUNTERS map");
        let mut counters: PerCpuArray<&mut MapData, u64> =
            PerCpuArray::try_from(map).expect("COUNTERS is not a per-CPU array");
        // Every slot non-zero and derived from its index, so a value read into the wrong
        // slot is visible and a slot never read stays at zero.
        for slot in 0..COUNTER_ENTRIES {
            let values: Vec<u64> = (0..cpus)
                .map(|cpu| u64::from(slot) * 1_000 + cpu as u64 + 1)
                .collect();
            counters
                .set(slot, PerCpuValues::try_from(values).unwrap(), 0)
                .expect("writing a counter slot failed");
        }
    }

    let reference = maps::counters(&ebpf, COUNTER_ENTRIES, 16)
        .expect("reader over the whole map")
        .read()
        .expect("the whole-map read failed")
        .to_vec();
    assert!(reference.iter().all(|&value| value != 0));

    const STRIDE: u32 = 5;
    let mut strided = maps::counters(&ebpf, COUNTER_ENTRIES, 16)
        .expect("strided reader")
        .with_stride(STRIDE);
    let window = (COUNTER_ENTRIES as usize).div_ceil(STRIDE as usize);

    // Two whole passes, so the wrap is exercised and not only the first pass.
    for pass in 0..2 {
        let mut fresh = 0usize;
        for read in 0..STRIDE {
            let got = strided
                .read()
                .unwrap_or_else(|err| panic!("pass {pass}, read {read} failed: {err}"));
            assert_eq!(got.len(), COUNTER_ENTRIES as usize);
            assert!(
                strided.walked() <= window,
                "pass {pass}, read {read} walked {} elements where a stride of {STRIDE} over \
                 {COUNTER_ENTRIES} slots allows {window}: the whole point is the divided cost",
                strided.walked()
            );
            fresh += strided.walked();
        }
        // A pass is a pass: `stride` reads and the map is covered, no more and no less.
        assert_eq!(
            fresh, COUNTER_ENTRIES as usize,
            "pass {pass} asked the kernel for {fresh} elements over {STRIDE} reads, and the \
             map has {COUNTER_ENTRIES} slots"
        );
        assert_eq!(
            strided.read().expect("a read past the pass failed"),
            reference.as_slice(),
            "after pass {pass} every slot has to carry what the whole-map read found; a \
             window that advanced wrong reads some slots twice and others never"
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
    let reader = maps::counters(&ebpf, COUNTER_ENTRIES, 16).expect("reader");
    assert_eq!(reader.stride(), 1);
    // Zero would claim no slots and finish no pass. The agent refuses it at the flag; the
    // reader cannot be made to hold it either.
    assert_eq!(reader.with_stride(0).stride(), 1);
}
