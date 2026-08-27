//! Loading the program and running one packet through it.
//!
//! `BPF_PROG_TEST_RUN` gives a verdict without a NIC, a generator or an attach. It
//! also runs the same packet against the same map entry every time, so it proves
//! correctness and never proves a cache behaviour: a map that grows from four
//! kilobytes to four megabytes is invisible here and expensive in production.

use std::{env, fs, path::PathBuf};

use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, MapData, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{TestRun, TestRunOptions, Xdp},
};
use lorica_common::{
    Action, BLOCKLIST_TRIE_SYMBOL, BUCKET_KEY_SYMBOLS, BUCKET_RATE_SYMBOLS, BUCKET_STALL_SYMBOL,
    Bucket, CLASS24_BYTES, CLASS24_SYMBOL, Class24, Clock, CounterId, DEFAULT_SETTINGS, LpmKey,
    LpmValue, MultiplyShift, OA_SLOTS, OA_TABLE_SYMBOL, OaSlot, PacketView, Rate, SETTINGS_SYMBOL,
    SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL,
    blocklist::{class24_set, oa_insert},
    key_words,
};
use lorica_dataplane::{clock, maps};

/// Counter slots every fixture in this suite sizes the map for.
///
/// The named counters and a thousand entry slots, which is the object's own default and more
/// than any case here uses. It is a constant rather than a parameter because the counter map
/// is striped by processor now: its entry count and the stripe width the program indexes it
/// with are one decision, so a per-case slot count would be a per-case decision to get wrong.
pub const COUNTER_SLOTS: u32 = CounterId::COUNT + 1024;

/// The layout of the counter map for this machine, at [`COUNTER_SLOTS`].
pub fn counter_layout() -> lorica_common::CounterLayout {
    maps::counter_layout(COUNTER_SLOTS).expect("no counter layout for this machine")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAction {
    Aborted,
    Drop,
    Pass,
    Tx,
    Redirect,
}

impl XdpAction {
    fn from_return_value(value: u32) -> Self {
        match value {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            other => panic!("the program returned {other}, which is not an XDP action"),
        }
    }
}

/// Helper calls actually executed for one packet, as opposed to the calls present in
/// the program. This is the budget the design is written against, and it only exists
/// in a build with the `count-helpers` feature.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HelperCounts {
    pub map_lookups: u64,
    pub clock_reads: u64,
    pub fib_lookups: u64,
}

impl HelperCounts {
    pub const fn total(&self) -> u64 {
        self.map_lookups + self.clock_reads + self.fib_lookups
    }

    /// What the last packet added, for a case that had to run the program for another
    /// reason first — calibrating the clock, which goes through the same counted wrapper.
    /// The counters only ever grow, so a difference is the whole of the arithmetic.
    pub const fn since(self, before: Self) -> Self {
        Self {
            map_lookups: self.map_lookups - before.map_lookups,
            clock_reads: self.clock_reads - before.clock_reads,
            fib_lookups: self.fib_lookups - before.fib_lookups,
        }
    }
}

/// The load-time globals of stage 7: the key its index is hashed with and the two
/// budgets it charges against.
///
/// A load and not a map write, like the policy word, so a case that wants another budget
/// is another load and nothing carries over.
#[derive(Clone, Copy)]
pub struct BucketGlobals {
    pub key: [u8; 16],
    pub normal: Rate,
    pub suspect: Rate,
}

impl BucketGlobals {
    /// A fixed key and the same budget on both sides, which is what most cases want: the
    /// budget a signature match routes to is stage 6's decision and not stage 7's, and a
    /// case that is not about that distinction should not have to state it.
    ///
    /// Fixed rather than drawn because a test whose bucket assignment changes per run is a
    /// test that fails one morning and passes the next. The cases that are about the draw
    /// ask for it explicitly.
    pub const fn fixed(rate: Rate) -> Self {
        Self {
            key: *b"lorica bucket ix",
            normal: rate,
            suspect: rate,
        }
    }

    /// Bucket a source address lands in under this key, computed the way the program
    /// computes it. This is what makes a steering case possible: the test has to be able to
    /// pick addresses that share a bucket.
    pub fn index_of(&self, src: &[u8; 16], buckets: u32) -> u32 {
        lorica_common::BankLayout { buckets, shards: 1 }
            .index(MultiplyShift::from_bytes(self.key).hash(src))
    }
}

/// The two blocklist tables a load writes into the program's `.bss`, and whether the trie
/// stays in the program beside them.
///
/// **Built with `class24_set` and `oa_insert` and never by hand.** Insertion decides where a
/// key lands, so a fixture that wrote its own slots would agree with the format and disagree
/// with the table: it would be testing a snapshot the builder cannot produce. These are the
/// same two functions the policy compiler calls.
///
/// A different snapshot is a different load, like the policy word and the two budgets.
/// Nothing carries over between cases, and the tables are patched before verification rather
/// than written afterwards because `aya` creates a `.bss` section as one `ARRAY` entry
/// holding the whole section, which `EbpfLoader` can splice a symbol into by name.
#[derive(Clone)]
pub struct Blocklist {
    class24: Vec<u8>,
    table: Vec<OaSlot>,
    trie: bool,
}

impl Blocklist {
    /// Both tables empty, and the trie still in the program — which is the program's own
    /// initialiser, so this is the load that changes nothing but the tables.
    pub fn empty() -> Self {
        Self {
            class24: vec![0; CLASS24_BYTES],
            table: vec![OaSlot::default(); OA_SLOTS],
            trie: true,
        }
    }

    /// The two tables exactly as the policy builder produced them.
    ///
    /// The fluent constructors above are for a fixture somebody wrote by hand; this is for a
    /// whole [`Snapshot`](lorica_policy::blocklist::Snapshot), which is what the equivalence
    /// harness compares the trie against. The lengths are asserted rather than trusted: a
    /// short vector splices into the head of the section and leaves the rest zeroed, which
    /// reads as a table that simply answers nothing.
    pub fn from_tables(class24: Vec<u8>, table: Vec<OaSlot>) -> Self {
        assert_eq!(
            class24.len(),
            CLASS24_BYTES,
            "a block table of {} bytes would splice into the head of the section and leave \
             the rest zeroed",
            class24.len()
        );
        assert_eq!(table.len(), OA_SLOTS, "the slot count is not OA_SLOTS");
        Self {
            class24,
            table,
            trie: true,
        }
    }

    /// Drops the `LPM_TRIE` stage out of the program, the way a configuration carrying no
    /// IPv6 entry and no armed agent does.
    pub fn without_trie(mut self) -> Self {
        self.trie = false;
        self
    }

    /// Marks the `/24` an address falls in.
    pub fn class(mut self, addr: [u8; 4], class: Class24) -> Self {
        class24_set(&mut self.class24, u32::from_be_bytes(addr), class);
        self
    }

    /// Places one `/32` in the open-addressed table.
    ///
    /// Panics when the probe sequence runs past `OA_PROBES`, which is what the builder does:
    /// a fixture that quietly failed to insert would assert a verdict against a key that is
    /// not in the table and read the miss as a pass.
    pub fn key(mut self, addr: [u8; 4], action: Action) -> Self {
        let key = u32::from_be_bytes(addr);
        oa_insert(&mut self.table, key, action).unwrap_or_else(|| {
            panic!("{addr:?} ran past OA_PROBES, so the fixture is not loadable")
        });
        self
    }

    /// The slot bytes as the map value holds them.
    fn table_bytes(&self) -> &[u8] {
        // SAFETY: `OaSlot` is `repr(C)`, eight bytes and no padding — asserted in
        // `lorica_common::blocklist` — so the vector is exactly its own bytes.
        unsafe {
            std::slice::from_raw_parts(
                self.table.as_ptr().cast::<u8>(),
                std::mem::size_of_val(self.table.as_slice()),
            )
        }
    }
}

/// A local wrapper so `Pod` can be implemented for a foreign type. Sound because
/// every byte pattern of `PacketView` is a valid value, which is the property the
/// trait requires and the reason the family and fragment fields are stored raw.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct ProbeView(PacketView);

// SAFETY: PacketView is Copy, 'static, and has no invalid byte pattern.
unsafe impl aya::Pod for ProbeView {}

/// The same wrapper for the list value. `Action` has invalid discriminants, so the
/// soundness here rests on the value only ever being read back after this crate wrote
/// it, which is true of a test map.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodLpmValue(LpmValue);

// SAFETY: LpmValue is Copy and 'static, and every value read out of this map was
// written into it through this type.
unsafe impl aya::Pod for PodLpmValue {}

/// The kernel-side envelope of a bucket, declared again here because the eBPF crate builds
/// for another target and cannot be depended on. The alignment is the whole point of the
/// layout, so it is asserted rather than assumed: a value size that drifted would make
/// every read of the bank silently return the wrong slot.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct PodBankSlot(Bucket);

// SAFETY: Bucket is Copy, 'static, two u64 and no invalid byte pattern; the padding is
// never read as anything.
unsafe impl aya::Pod for PodBankSlot {}

const _: () = assert!(std::mem::size_of::<PodBankSlot>() == 64);

pub struct TestProg {
    ebpf: Ebpf,
    name: String,
}

impl TestProg {
    pub fn load(name: &str) -> Self {
        Self::load_with(name, DEFAULT_SETTINGS)
    }

    /// Loads with a policy word. The settings are a load-time global rather than a
    /// map, so a different policy is a different load, which is also what a test
    /// wants: nothing carries over between cases.
    pub fn load_with(name: &str, settings: u32) -> Self {
        Self::load_object(&object_path(), name, settings)
    }

    /// Loads with a policy word and with the stage 7 globals stated, for the cases that
    /// are about the buckets. Everything else keeps the unconfigured budget the program
    /// carries in its own `.rodata`, which enforces nothing.
    pub fn load_buckets(name: &str, settings: u32, buckets: BucketGlobals) -> Self {
        Self::load_buckets_stalled(name, settings, buckets, 0)
    }

    /// The same load with the read-modify-write window of the bank widened by `stall` dead
    /// reads, which is the second axis of the contention measurement: the leak is a surface
    /// over the number of contending cores and the width of that window, and a point on it
    /// is worth what a point on any surface is worth.
    ///
    /// Zero is what every other load passes and what the program carries on its own, so it
    /// patches the initialiser with itself and the verifier removes the loop.
    pub fn load_buckets_stalled(
        name: &str,
        settings: u32,
        buckets: BucketGlobals,
        stall: u32,
    ) -> Self {
        Self::load_full(
            &object_path(),
            name,
            settings,
            Some(buckets),
            stall,
            SIGNATURE_VECTORS_ALL,
            None,
        )
    }

    /// Loads a named object rather than the one the environment points at, for the one
    /// measurement that has to compare two builds of the same program in one process.
    pub fn load_object(path: &std::path::Path, name: &str, settings: u32) -> Self {
        Self::load_full(path, name, settings, None, 0, SIGNATURE_VECTORS_ALL, None)
    }

    /// Loads with the two blocklist tables written into the program's `.bss` before
    /// verification, and with the trie kept or dropped as the snapshot asks.
    pub fn load_blocklist(name: &str, settings: u32, blocklist: &Blocklist) -> Self {
        Self::load_full(
            &object_path(),
            name,
            settings,
            None,
            0,
            SIGNATURE_VECTORS_ALL,
            Some(blocklist),
        )
    }

    /// Loads with only the named signature vectors in the program at all.
    ///
    /// The mask is not a run-time filter: a cleared bit means the verifier removed that
    /// vector before the program was JITed. So this is how the cost of a *configuration* is
    /// measured rather than the cost of the catalogue, and the two differ by more than the
    /// gates that survive.
    pub fn load_vectors(name: &str, settings: u32, vectors: u32) -> Self {
        Self::load_full(&object_path(), name, settings, None, 0, vectors, None)
    }

    fn load_full(
        path: &std::path::Path,
        name: &str,
        settings: u32,
        buckets: Option<BucketGlobals>,
        stall: u32,
        vectors: u32,
        blocklist: Option<&Blocklist>,
    ) -> Self {
        let object = fs::read(path).unwrap_or_else(|err| {
            panic!(
                "cannot read the eBPF object at {}: {err}\n\
                 build it with: cd crates/lorica-ebpf && cargo +nightly build --release\n\
                 or point LORICA_EBPF_OBJ at another one",
                path.display()
            )
        });

        let layout = counter_layout();
        let mut loader = EbpfLoader::new();
        // The counter map's entry count and the stripe width the program indexes it with are
        // one decision, and this is the function that makes it. A fixture that set only the
        // size would load a program counting into slot zero of every stripe.
        maps::size_counters(&mut loader, &layout);
        loader.override_global(SETTINGS_SYMBOL, &settings, true);
        // The whole catalogue by default, which is what a case about a vector wants and
        // what a case about anything else wants not to think about. The program's own
        // initialiser is none of it, so a vector left unpatched is not merely off — it is
        // not in the verified program, and every counter assertion about it would read zero.
        loader.override_global(SIGNATURE_VECTORS_SYMBOL, &vectors, true);
        // Zero for every load but a window sweep, and zero is the program's own initialiser:
        // the verifier folds it and the widening loop is not in the JITed program at all.
        loader.override_global(BUCKET_STALL_SYMBOL, &stall, true);
        // Kept alive past the borrow: `override_global` records a reference, and the
        // patching happens in `load`.
        let words = buckets.map(|b| {
            let key = key_words(b.key);
            [
                key[0],
                key[1],
                b.normal.drain.into_raw(),
                b.normal.burst,
                b.suspect.drain.into_raw(),
                b.suspect.burst,
            ]
        });
        if let Some(words) = words.as_ref() {
            loader.override_global(BUCKET_KEY_SYMBOLS[0], &words[0], true);
            loader.override_global(BUCKET_KEY_SYMBOLS[1], &words[1], true);
            loader.override_global(BUCKET_RATE_SYMBOLS[0][0], &words[2], true);
            loader.override_global(BUCKET_RATE_SYMBOLS[0][1], &words[3], true);
            loader.override_global(BUCKET_RATE_SYMBOLS[1][0], &words[4], true);
            loader.override_global(BUCKET_RATE_SYMBOLS[1][1], &words[5], true);
        }
        // Twenty mebibytes of `.bss` spliced in by symbol name, so no test has to know where
        // one table sits relative to the other. The trie word rides with them because a
        // snapshot and the stage it makes redundant are one decision.
        let trie_armed = u32::from(blocklist.is_none_or(|b| b.trie));
        if let Some(blocklist) = blocklist {
            loader.override_global(CLASS24_SYMBOL, &blocklist.class24[..], true);
            loader.override_global(OA_TABLE_SYMBOL, blocklist.table_bytes(), true);
            loader.override_global(BLOCKLIST_TRIE_SYMBOL, &trie_armed, true);
        }
        let mut ebpf = loader
            .load(&object)
            // Debug and not Display: aya wraps the cause, and the outer message alone says
            // only that a relocation failed and not which symbol it failed on.
            .unwrap_or_else(|err| panic!("loading {} failed: {err:?}", path.display()));
        let program: &mut Xdp = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("no program named {name} in {}", path.display()))
            .try_into()
            .expect("the program is not an XDP program");
        program
            .load()
            .unwrap_or_else(|err| panic!("the verifier rejected {name}: {err}"));

        Self {
            ebpf,
            name: name.to_owned(),
        }
    }

    fn program(&self) -> &Xdp {
        self.ebpf
            .program(&self.name)
            .expect("the program disappeared")
            .try_into()
            .expect("the program is not an XDP program")
    }

    pub fn run(&self, pkt: &[u8]) -> XdpAction {
        let result = self
            .program()
            .test_run(TestRunOptions {
                data_in: Some(pkt),
                ..Default::default()
            })
            .unwrap_or_else(|err| panic!("test_run on {} bytes failed: {err}", pkt.len()));
        XdpAction::from_return_value(result.return_value)
    }

    /// The same run, with the frame presented as if it had arrived on `ifindex`.
    ///
    /// `BPF_PROG_TEST_RUN` otherwise hands the program the loopback receive queue of the
    /// current namespace, so `ingress_ifindex` is 1 whatever the test does — which is
    /// exactly the reading that makes a reverse-path lookup answer `FWD_DISABLED` on a
    /// machine that does not route, and it is why the plain [`Self::run`] cannot exercise
    /// stage 5 at all. The context is passed in instead: the six words of `struct xdp_md`,
    /// of which the kernel insists `data_end` equal the frame length and the metadata
    /// length be zero. The interface must exist in this namespace; its receive queue 0 is
    /// registered for XDP by the generic device code, so no attach is needed.
    pub fn run_from(&self, pkt: &[u8], ifindex: u32) -> XdpAction {
        let ctx = xdp_md(pkt.len() as u32, ifindex);
        let result = self
            .program()
            .test_run(TestRunOptions {
                data_in: Some(pkt),
                ctx_in: Some(&ctx),
                ..Default::default()
            })
            .unwrap_or_else(|err| panic!("test_run on ifindex {ifindex} failed: {err}"));
        XdpAction::from_return_value(result.return_value)
    }

    /// Average nanoseconds per invocation, chronometered by the kernel around the
    /// loop. It excludes the syscall, the driver, the NAPI poll and the DMA, and it
    /// does not need `bpf_stats_enabled`, whose instrumentation on this hardware
    /// costs more than the budget being measured.
    pub fn ns_per_run(&self, pkt: &[u8], repeat: u32) -> u128 {
        let result = self
            .program()
            .test_run(TestRunOptions {
                data_in: Some(pkt),
                repeat,
                ..Default::default()
            })
            .expect("test_run failed");
        result.duration.as_nanos()
    }

    /// Bytes of the program the CPU actually runs, `bpf_prog_info.jited_prog_len`.
    ///
    /// The ceiling assertion reads the same field of a raw load; this reads it off a loaded
    /// [`TestProg`], which is what lets one measurement print the size of the very program
    /// it timed. That is the whole evidence that a load-time global costs nothing when it is
    /// zero: the number does not move.
    pub fn jited_len(&self) -> u32 {
        self.program()
            .info()
            .expect("reading the program info failed")
            .size_jitted()
    }

    /// Bytes of BPF bytecode the verifier left in the program, `bpf_prog_info.xlated_len`.
    ///
    /// The number that shows whether a `.rodata` word *removed* a branch or merely skips it:
    /// the JITed length also moves with the x86 encoding of whatever survived, and the
    /// translated length is instructions the verifier kept. Zero would be a false pass, so it
    /// is reported as such rather than as a small program.
    pub fn translated_len(&self) -> u32 {
        self.program()
            .info()
            .expect("reading the program info failed")
            .size_translated()
            .expect("the kernel did not report xlated_len")
    }

    /// The descriptor of one of the program's maps, under the name the ELF gives it.
    ///
    /// `.bss` is the one no other method can reach: it is not a map anybody declared, so
    /// there is no typed wrapper for it, and its value is the whole data section — which is
    /// what makes a full blocklist reload one write and what makes the kernel cost of the two
    /// tables readable off a descriptor. The panic lists what the object does carry, because
    /// a section aya spells differently would otherwise read as a missing table.
    pub fn map_fd(&self, name: &str) -> std::os::fd::BorrowedFd<'_> {
        lorica_dataplane::maps::fd(&self.ebpf, name).unwrap_or_else(|| {
            let carried: Vec<&str> = self.ebpf.maps().map(|(name, _)| name).collect();
            panic!("no map named {name} is reachable by descriptor; the object carries {carried:?}")
        })
    }

    pub fn counter(&self, name: &str) -> u64 {
        let id = CounterId::from_name(name)
            .unwrap_or_else(|| panic!("no counter named {name} in CounterId"));
        self.counter_at(id.index())
    }

    /// A raw slot, summed over every processor's stripe. The ones above `CounterId::COUNT`
    /// belong to individual entries of the unified list.
    pub fn counter_at(&self, index: u32) -> u64 {
        maps::counter_at(&self.ebpf, COUNTER_SLOTS, index).expect("reading a counter failed")
    }

    /// Writes one entry of the unified list, the way the loader will.
    pub fn insert(&mut self, key: LpmKey, value: LpmValue) {
        let map = self
            .ebpf
            .map_mut("UNIFIED_LIST")
            .expect("no UNIFIED_LIST map");
        let mut list: LpmTrie<&mut MapData, [u8; 16], PodLpmValue> =
            LpmTrie::try_from(map).expect("UNIFIED_LIST is not an LPM trie");
        list.insert(&Key::new(key.prefix_len, key.addr), PodLpmValue(value), 0)
            .expect("inserting into the unified list failed");
    }

    /// Reads an entry back out of the unified list.
    ///
    /// Half of the TTL criterion is that an expired entry is *still in the map* and
    /// merely stops being applied. A verdict alone cannot tell that apart from an
    /// entry the test failed to insert, so the read exists.
    pub fn list_get(&self, key: LpmKey) -> Option<LpmValue> {
        let map = self.ebpf.map("UNIFIED_LIST").expect("no UNIFIED_LIST map");
        let list: LpmTrie<&MapData, [u8; 16], PodLpmValue> =
            LpmTrie::try_from(map).expect("UNIFIED_LIST is not an LPM trie");
        list.get(&Key::new(key.prefix_len, key.addr), 0)
            .ok()
            .map(|value| value.0)
    }

    /// The parsed view of the last packet run. Only present in a build with the
    /// `parse-probe` feature of lorica-ebpf.
    pub fn parsed(&self) -> PacketView {
        let map = self.ebpf.map("PARSE_PROBE").unwrap_or_else(|| {
            panic!(
                "no PARSE_PROBE map: the object was built without the parse-probe                  feature of lorica-ebpf"
            )
        });
        let probe: PerCpuArray<&MapData, ProbeView> =
            PerCpuArray::try_from(map).expect("PARSE_PROBE is not a per-CPU array");
        let values = probe.get(&0, 0).expect("reading the parse probe failed");
        // test_run runs on one CPU, so one slot is written. Pick it by its non-zero
        // packet length rather than assuming which CPU ran.
        values
            .iter()
            .map(|probe| probe.0)
            .find(|view| view.packet_len != 0)
            .expect("no CPU slot of the parse probe was written")
    }

    /// The clock the program compares deadlines against: the rate it ticks at, measured,
    /// and one reading of it.
    ///
    /// It goes through the probe of the object under test, so a deadline a test builds
    /// sits on exactly the counter the packet path will read. Nothing in userspace reports
    /// either number, which is why this is a program run and not a file read.
    pub fn clock(&mut self) -> Clock {
        clock::calibrate(&mut self.ebpf).expect("calibrating the kernel clock failed")
    }

    fn bank(&self) -> Array<&MapData, PodBankSlot> {
        let map = self.ebpf.map("BUCKET_BANK").expect("no BUCKET_BANK map");
        Array::try_from(map).expect("BUCKET_BANK is not an array")
    }

    /// How many buckets the bank holds, read from the map rather than from a constant.
    ///
    /// The program computes its index modulo a compile-time count in the eBPF crate, which
    /// this crate cannot see. Reading the map length is the only way for a test to agree
    /// with it, and a disagreement shows up as a steering case that steers nowhere.
    pub fn bank_len(&self) -> u32 {
        self.bank().len()
    }

    /// The level of every bucket, in the sub-byte units the arithmetic counts in.
    ///
    /// The one observable that says *which* bucket a packet landed in. A verdict cannot:
    /// two different indices both answer pass.
    pub fn bank_levels(&self) -> Vec<u64> {
        let bank = self.bank();
        (0..bank.len())
            .map(|index| {
                bank.get(&index, 0)
                    .expect("reading a bucket failed")
                    .0
                    .level
            })
            .collect()
    }

    pub fn helper_counts(&self) -> HelperCounts {
        let map = self.ebpf.map("HELPER_COUNTS").unwrap_or_else(|| {
            panic!(
                "no HELPER_COUNTS map: the object was built without the count-helpers \
                 feature of lorica-ebpf"
            )
        });
        let counts: PerCpuArray<&MapData, u64> =
            PerCpuArray::try_from(map).expect("HELPER_COUNTS is not a per-CPU array");
        let read = |index: u32| -> u64 {
            counts
                .get(&index, 0)
                .expect("reading a helper count failed")
                .iter()
                .sum()
        };
        HelperCounts {
            map_lookups: read(0),
            clock_reads: read(1),
            fib_lookups: read(2),
        }
    }
}

/// `struct xdp_md` as the kernel reads it back out of `ctx_in`: data, data_end,
/// data_meta, ingress_ifindex, rx_queue_index, egress_ifindex.
///
/// Queue zero, because a device created by a test has one and the kernel refuses an index
/// at or past `real_num_rx_queues`. An egress index other than zero is refused outright.
fn xdp_md(len: u32, ifindex: u32) -> [u8; 24] {
    let mut ctx = [0u8; 24];
    ctx[4..8].copy_from_slice(&len.to_ne_bytes());
    ctx[12..16].copy_from_slice(&ifindex.to_ne_bytes());
    ctx
}

/// Where the eBPF object comes from.
///
/// Named here rather than in each test: the object is a different target built by a
/// different toolchain, so cargo cannot produce it as a dependency and the path has
/// to be agreed on once.
pub fn object_path() -> PathBuf {
    if let Ok(path) = env::var("LORICA_EBPF_OBJ") {
        return PathBuf::from(path);
    }
    default_object_path()
}

/// The object without instrumentation, which is the one that ships.
///
/// Anything measured as a property of the program — its call budget, its JITed size —
/// comes from this one: the instrumented build adds a map write per counted call, so
/// measuring that build would be measuring the instrumentation.
pub fn plain_object_path() -> PathBuf {
    if let Ok(path) = env::var("LORICA_EBPF_PLAIN_OBJ") {
        return PathBuf::from(path);
    }
    default_object_path()
}

fn default_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
}

/// Loads an object into the kernel without the test-run wrapper, for the tests that
/// attach it to a real interface rather than feeding it packets.
///
/// The signature catalogue is left at the program's own initialiser, which is empty, so
/// what this loads is the program with stage 6 pruned out of it. None of the callers
/// asserts anything about a vector — they attach, they fault, they route — but the size
/// ceiling reads its number from here, and the number it reads is therefore a program
/// without the catalogue. Patching [`SIGNATURE_VECTORS_ALL`] here is the honest thing the
/// moment the ceiling is re-baselined: `signature_pruning` prints what the whole catalogue
/// costs, and it is above the ceiling standing today.
pub fn load_raw(path: &std::path::Path, settings: u32) -> Ebpf {
    load_raw_vectors(path, settings, None)
}

/// The same load with the signature catalogue stated, for the assertion about what the
/// verifier leaves in the program: the vectors a mask omits are not skipped at run time,
/// they are removed before the program is JITed, so the mask is what makes two loads of one
/// object two different programs.
pub fn load_raw_vectors(path: &std::path::Path, settings: u32, vectors: Option<u32>) -> Ebpf {
    let object = fs::read(path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    let layout = counter_layout();
    let mut loader = EbpfLoader::new();
    maps::size_counters(&mut loader, &layout);
    loader.override_global(SETTINGS_SYMBOL, &settings, true);
    if let Some(vectors) = vectors.as_ref() {
        loader.override_global(SIGNATURE_VECTORS_SYMBOL, vectors, true);
    }
    loader
        .load(&object)
        .unwrap_or_else(|err| panic!("loading {} failed: {err}", path.display()))
}

/// Verifies one program of a loaded object and hands it back ready to attach.
pub fn xdp_program<'a>(ebpf: &'a mut Ebpf, name: &str) -> &'a mut Xdp {
    let program: &mut Xdp = ebpf
        .program_mut(name)
        .unwrap_or_else(|| panic!("no program named {name}"))
        .try_into()
        .expect("the program is not an XDP program");
    program
        .load()
        .unwrap_or_else(|err| panic!("the verifier rejected {name}: {err}"));
    program
}
