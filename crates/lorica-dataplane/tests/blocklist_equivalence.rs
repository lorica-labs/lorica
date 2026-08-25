//! The two flat tables against the trie they replace, on a corpus nobody chose.
//!
//! **What this replaces, and the number that makes it necessary.** The obvious way to
//! authorise the replacement is a list of cases somebody wrote: an allow inside a deny, a
//! `/31`, the zero address. `stage_blocklist.rs` is that list, and it is worth what it is
//! worth — it tests the eleven situations its author thought of. What it cannot do is fail on
//! the twelfth, and the structure under test resolves longest-prefix-match at **construction**
//! rather than at lookup, so a divergence lives in a combination of prefix lengths and not in
//! any single line. The trie costs 414 ns at a million entries and the tables cost the same at
//! one entry as at ten million; that is the whole reason for the swap, and it is only allowed
//! if the answer does not move. So the corpus here is drawn from a written-down seed, and so
//! is the configuration both structures are loaded with.
//!
//! **The same configuration into both, or the comparison means nothing.** One `Vec` of
//! `(prefix, length, verdict)` goes to [`lorica_policy::blocklist::build`] and, prefix for
//! prefix, into the `LPM_TRIE`. The flat program is loaded with the trie dropped, so its
//! answers come from the two tables alone; the trie program is loaded with both tables empty,
//! so `CLASS24` answers `None` for every address and the verdict comes from the trie alone.
//! Each side is therefore the *only* thing answering, which is what makes a disagreement
//! locatable.
//!
//! **What the two are allowed to disagree about, and it is not a verdict.** A prefix at or
//! shorter than `/24` carrying `Continue`, `RateLimit` or `Mark` is **refused at
//! construction**: two bits spell four codes and all four are taken. The trie can represent
//! it. That is a refusal, not a divergence, and it is asserted as a refusal here rather than
//! excluded from the draw — excluding it would leave the one case where the two structures
//! genuinely differ untested, which is the case a reader would ask about first.
//!
//! **Why the corpus is not uniform over the address space.** A configuration of a hundred
//! prefixes covers a vanishing fraction of 2^32, so a uniform draw is 99.99 % trivial misses
//! and the equivalence would hold without either structure being consulted. Three quarters of
//! the keys are therefore drawn inside a random *ancestor* of a random configured prefix —
//! which lands them inside the prefix, just outside it, or a few scales away, without anybody
//! choosing which — and one quarter uniformly over the whole space, which is what keeps the
//! trivial-miss path in the comparison. The counts of both, and of the keys that reached the
//! second table at all, are printed: an equivalence proved on a corpus that never reached the
//! open-addressed table would be a green result about nothing, and this harness has to be
//! unable to give one.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{collections::BTreeSet, env, fs, io, os::fd::AsRawFd};

use lorica_common::{
    Action, CLASS24_BYTES, CLASS24_SYMBOL, Class24, CounterId, DEFAULT_SETTINGS, Deadline, LpmKey,
    LpmValue, OA_TABLE_SYMBOL,
    blocklist::{CLASS24_PREFIX_BITS, class24_get},
};
use lorica_policy::blocklist::{BuildError, Snapshot, build};
use object::{Object, ObjectSection, ObjectSymbol};
use support::{
    Blocklist, PktBuilder, TestProg, XdpAction, program_with_blocklist, run::object_path,
};

/// Written down so a failure is reproducible. A seed taken from the clock turns one
/// divergence into a story nobody can re-run.
const SEED: u64 = 0xb10c_1157_5eed_0001;

/// Keys compared. Two `test_run` syscalls each, so the whole comparison is a couple of
/// seconds, and the count is printed rather than assumed: a harness that can report a pass
/// on zero keys invalidates every pass it ever gave, which has happened twice here on a full
/// disk.
const CORPUS: usize = 20_000;

/// One key in this many is drawn uniformly over the whole v4 space. The rest are drawn near
/// the configuration — see the module note.
const UNIFORM_IN: u32 = 4;

/// Prefixes drawn on top of the one-per-length pass. Enough that several lengths carry more
/// than one prefix and the block fills overlap, few enough to fit the trie's default 1 024
/// entries with room to spare.
const EXTRA_PREFIXES: usize = 96;

/// Generous on purpose: the bound is a policy dial and this harness is not testing it. What
/// it must not do is refuse a drawn configuration for a reason that has nothing to do with
/// equivalence.
const EXPANSION_BUDGET: usize = 1 << 20;

const GAME_PORT: u16 = 30_120;

/// `BPF_MAP_UPDATE_ELEM`. libc carries no `bpf_cmd` enum; the number is ABI.
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;

/// splitmix64, written out rather than pulled in.
///
/// The requirement is that a seed names a stream **for ever**, and a generator crate does not
/// promise that across a minor version: the day the stream changes, a recorded failing seed
/// stops reproducing the failure it was recorded for. Sixteen lines of arithmetic frozen in
/// this file do promise it, and no distribution property beyond uniformity is needed here.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The high half, which is the well-mixed end of any multiply.
    fn word(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }

    fn below(&mut self, bound: u32) -> u32 {
        self.word() % bound
    }
}

/// Host bits of a prefix length. `u32::MAX >> 32` is an overflowing shift in Rust, and the
/// `/32` case is the one every corpus draw goes through.
fn host_mask(len: u32) -> u32 {
    u32::MAX.checked_shr(len).unwrap_or(0)
}

fn masked(addr: u32, len: u32) -> u32 {
    addr & !host_mask(len)
}

fn dotted(addr: u32) -> String {
    let octets = addr.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// A verdict two bits can spell, for the prefixes `CLASS24` has to answer alone.
fn short_verdict(rng: &mut Rng) -> Action {
    if rng.below(2) == 0 {
        Action::Drop
    } else {
        Action::Allow
    }
}

/// Any verdict, for the `/25` to `/32` the three tag bits can hold.
///
/// `Continue`, `RateLimit` and `Mark` are in the draw deliberately: both structures route
/// them to "no verdict from this stage", by different code, and that agreement is a claim
/// worth drawing rather than a case worth skipping.
fn long_verdict(rng: &mut Rng) -> Action {
    const EVERY: [Action; 5] = [
        Action::Drop,
        Action::Allow,
        Action::Continue,
        Action::RateLimit,
        Action::Mark,
    ];
    EVERY[rng.below(EVERY.len() as u32) as usize]
}

fn verdict(rng: &mut Rng, len: u32) -> Action {
    if len <= CLASS24_PREFIX_BITS {
        short_verdict(rng)
    } else {
        long_verdict(rng)
    }
}

/// The configuration both structures are loaded with.
///
/// One prefix per length so no length is missing — including `/0`, which paints all 16.7
/// million blocks and forces a block fill under every long prefix, and `/25` to `/31`, which
/// are the expansions. Then the extra draws, so several lengths carry more than one prefix.
/// Then two structural guarantees, both taken from the same seed: an exception carrying the
/// *opposite* verdict inside a drawn short prefix, which is the case the tag exists for and
/// which a purely uniform draw would only usually produce; and the zero address, which is the
/// bit pattern a free slot and `0.0.0.0` would share if occupancy lived in the key.
///
/// Duplicates are dropped. Two rules on one prefix are the policy compiler's refusal, and
/// `build` resolves such a pair by declaration order while the trie resolves it by whichever
/// write landed last — a disagreement about a configuration neither side is meant to receive.
fn draw_config(rng: &mut Rng) -> Vec<(u32, u32, Action)> {
    let mut out: Vec<(u32, u32, Action)> = Vec::new();
    for len in 0..=32 {
        out.push((masked(rng.word(), len), len, verdict(rng, len)));
    }
    for _ in 0..EXTRA_PREFIXES {
        let len = rng.below(33);
        out.push((masked(rng.word(), len), len, verdict(rng, len)));
    }
    let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
    out.retain(|&(prefix, len, _)| seen.insert((prefix, len)));

    let short: Vec<(u32, u32, Action)> = out
        .iter()
        .copied()
        .filter(|&(_, len, _)| len <= CLASS24_PREFIX_BITS)
        .collect();
    let (base, len, covering) = short[rng.below(short.len() as u32) as usize];
    let exception = base | (rng.word() & host_mask(len));
    let opposite = match covering {
        Action::Drop => Action::Allow,
        _ => Action::Drop,
    };
    force(&mut out, exception, 32, opposite);
    force(&mut out, 0, 32, long_verdict(rng));

    out
}

/// The verdict of one prefix, whether or not the draw already produced that prefix.
///
/// Overwriting rather than appending, because appending would make the configuration carry two
/// rules for one prefix — which is the policy compiler's refusal
/// (`CompileError::DuplicatePrefix`) and not a configuration either structure is meant to
/// receive. It is also what makes the two structural guarantees guarantees: an exception the
/// draw happened to produce already would otherwise be silently dropped and the case would go
/// untested on exactly the runs where it looked covered.
fn force(config: &mut Vec<(u32, u32, Action)>, prefix: u32, len: u32, action: Action) {
    match config
        .iter_mut()
        .find(|&&mut (held, held_len, _)| held == prefix && held_len == len)
    {
        Some(entry) => entry.2 = action,
        None => config.push((prefix, len, action)),
    }
}

/// Keys to compare. See the module note for the mixture and why it is not uniform.
fn draw_corpus(rng: &mut Rng, config: &[(u32, u32, Action)]) -> (Vec<u32>, usize) {
    let mut out = Vec::with_capacity(CORPUS);
    let mut uniform = 0;
    while out.len() < CORPUS {
        if rng.below(UNIFORM_IN) == 0 {
            uniform += 1;
            out.push(rng.word());
        } else {
            let (prefix, len, _) = config[rng.below(config.len() as u32) as usize];
            // A random ancestor of the prefix, then a random address inside that ancestor:
            // the same draw produces addresses inside the rule, just outside it, and a few
            // scales away, and nothing here decides which.
            let scope = rng.below(len + 1);
            out.push(masked(prefix, scope) | (rng.word() & host_mask(scope)));
        }
    }
    (out, uniform)
}

fn udp_from(addr: u32) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(addr.to_be_bytes())
        .udp(1111, GAME_PORT)
        .build()
}

/// The flat program: both tables as the builder produced them, and no trie behind them.
fn flat_program(snapshot: &Snapshot) -> TestProg {
    let blocklist =
        Blocklist::from_tables(snapshot.class24.clone(), snapshot.oa.clone()).without_trie();
    program_with_blocklist(DEFAULT_SETTINGS, &blocklist)
}

/// The trie program: the same configuration, prefix for prefix, and both tables empty so
/// `CLASS24` answers `None` for every address and the trie is the only thing deciding.
fn trie_program(config: &[(u32, u32, Action)]) -> TestProg {
    let mut prog = program_with_blocklist(DEFAULT_SETTINGS, &Blocklist::empty());
    for (index, &(prefix, len, action)) in config.iter().enumerate() {
        let mut value = LpmValue::zeroed();
        value.action = action;
        // Explicitly never. A value built by hand carries deadline zero, zero is expired,
        // and a trie of expired entries answers `Continue` for everything — which would
        // agree with an empty flat table and prove nothing.
        value.deadline = Deadline::never();
        value.counter_idx = CounterId::COUNT + index as u32;
        prog.insert(LpmKey::v4(prefix.to_be_bytes(), len), value);
    }
    prog
}

/// The comparison itself, over one configuration, returning how many drawn keys each
/// `CLASS24` code answered.
///
/// It is called on two subsets of one draw, and the reason is arithmetic rather than taste. A
/// configuration carrying one prefix per length covers the whole address space: the `/1` alone
/// is half of it, the `/2` a quarter, and the series closes. So on the whole draw the `None`
/// code — no configured prefix covers this `/24`, which is the 94 % production path and the
/// reason the block table is not merely a filter ahead of the second one — **never occurs**,
/// and it was measured at zero of 20 000 keys before this split existed. The second subset is
/// the same draw keeping only its `/25`-to-`/32`, which is the shape the design is quoted for:
/// a million scattered hosts leaving about 6 % of the blocks marked. Neither subset is a case
/// somebody chose; both are one draw read through two filters.
fn compare(
    label: &str,
    config: &[(u32, u32, Action)],
    corpus: &[u32],
    uniform: usize,
) -> [usize; 4] {
    let snapshot = build(config, EXPANSION_BUDGET).unwrap_or_else(|err| {
        panic!(
            "the drawn {label} configuration of {} prefixes was refused: {err}\nseed {SEED:#x}",
            config.len()
        )
    });

    let flat = flat_program(&snapshot);
    let trie = trie_program(&config);

    let mut compared = 0usize;
    let mut classes = [0usize; 4];
    let mut drops = 0usize;
    let mut diverged: Vec<(u32, XdpAction, XdpAction)> = Vec::new();
    for &addr in corpus {
        let pkt = udp_from(addr);
        let tables = flat.run(&pkt);
        let walked = trie.run(&pkt);
        compared += 1;
        classes[class24_get(&snapshot.class24, addr) as usize] += 1;
        if tables == XdpAction::Drop {
            drops += 1;
        }
        if tables != walked && diverged.len() < 8 {
            diverged.push((addr, tables, walked));
        }
    }

    println!(
        "blocklist-equivalence set={label} seed={SEED:#x} keys={compared} uniform={uniform} \
         near={} prefixes={} oa_keys={} expanded={} worst_psl={} \
         class_none={} class_deny={} class_allow={} class_table={} drops={} diverged={}",
        compared - uniform,
        config.len(),
        snapshot.keys,
        snapshot.expanded,
        snapshot.worst_psl,
        classes[Class24::None as usize],
        classes[Class24::Deny as usize],
        classes[Class24::Allow as usize],
        classes[Class24::Table as usize],
        drops,
        diverged.len()
    );

    assert!(
        compared > 0,
        "the {label} set compared no key at all, so this is a green result about nothing"
    );
    // Two ways this comparison could be vacuous, each refused by name. Two empty structures
    // agree on everything, and so do two structures nothing ever consulted.
    assert!(
        drops > 0 && drops < compared,
        "the {label} set dropped {drops} of {compared} keys, so one verdict answers the whole \
         corpus and the agreement is about the pipeline rather than about the tables"
    );
    assert!(
        classes[Class24::Table as usize] > 0,
        "no drawn key fell in a /24 the {label} set marked Table, so the open-addressed table \
         was never consulted and half the structure is untested"
    );

    assert!(
        diverged.is_empty(),
        "on the {label} set the two structures disagree, seed {SEED:#x}:\n{}",
        diverged
            .iter()
            .map(|(addr, tables, walked)| format!(
                "  {} class {:?}: tables say {tables:?}, the trie says {walked:?}",
                dotted(*addr),
                class24_get(&snapshot.class24, *addr)
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    classes
}

#[test]
fn the_two_tables_answer_what_the_trie_answers_on_a_drawn_corpus() {
    let mut rng = Rng::new(SEED);
    let config = draw_config(&mut rng);
    let (corpus, uniform) = draw_corpus(&mut rng, &config);
    let hosts: Vec<(u32, u32, Action)> = config
        .iter()
        .copied()
        .filter(|&(_, len, _)| len > CLASS24_PREFIX_BITS)
        .collect();

    let whole = compare("whole", &config, &corpus, uniform);
    let hosts = compare("hosts_only", &hosts, &corpus, uniform);

    // All four codes over the two subsets. A code no drawn key ever met is a quarter of the
    // block table this comparison says nothing about, and `None` is the one carrying
    // production.
    for code in [Class24::None, Class24::Deny, Class24::Allow, Class24::Table] {
        let seen = whole[code as usize] + hosts[code as usize];
        assert!(
            seen > 0,
            "no drawn key was answered by the {code:?} code in either subset, so that quarter \
             of the block table is outside this comparison"
        );
    }
}

/// The one thing the two structures genuinely do not agree about, asserted as a refusal.
///
/// The trie can hold `RateLimit` on a `/16`; two bits cannot spell it. So the builder refuses
/// the whole snapshot, which is the honest answer — rounding it to the nearest verdict would
/// silently change what the operator's rule does. The same verdict on a `/25` to `/32` is
/// accepted, and that half is asserted too: a refusal that fired on everything would pass
/// this test while making the format useless.
#[test]
fn a_verdict_two_bits_cannot_spell_is_refused_on_a_short_prefix_and_taken_on_a_long_one() {
    let mut rng = Rng::new(SEED ^ 0x5c04_7e57);
    const UNSPELLABLE: [Action; 3] = [Action::Continue, Action::RateLimit, Action::Mark];
    let mut refused = 0usize;
    let mut accepted = 0usize;
    for _ in 0..64 {
        let action = UNSPELLABLE[rng.below(3) as usize];

        let len = rng.below(CLASS24_PREFIX_BITS + 1);
        let prefix = masked(rng.word(), len);
        match build(&[(prefix, len, action)], EXPANSION_BUDGET) {
            Err(BuildError::ShortPrefixAction { .. }) => refused += 1,
            other => panic!(
                "{}/{len} carrying {action:?} was answered {other:?} and not refused",
                dotted(prefix)
            ),
        }

        let len = CLASS24_PREFIX_BITS + 1 + rng.below(32 - CLASS24_PREFIX_BITS);
        let prefix = masked(rng.word(), len);
        match build(&[(prefix, len, action)], EXPANSION_BUDGET) {
            Ok(snapshot) => {
                assert!(snapshot.keys > 0);
                accepted += 1;
            }
            Err(err) => panic!(
                "{}/{len} carrying {action:?} was refused, and the tag has three bits for it: {err}",
                dotted(prefix)
            ),
        }
    }
    println!("blocklist-refusal short_refused={refused} long_accepted={accepted}");
    assert_eq!(refused, 64);
    assert_eq!(accepted, 64);
}

/// Where the two tables sit inside the one data section aya materialises them in.
struct Bss {
    bytes: usize,
    class24_at: usize,
    oa_at: usize,
}

/// Read off the ELF rather than written down. The claim being measured is that a full reload
/// is **one** write of the whole section, which only means anything if the offsets inside it
/// are the linker's and not this file's guess at them.
fn bss_layout() -> Bss {
    let path = object_path();
    let bytes = fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read the eBPF object at {}: {err}", path.display()));
    let elf = object::File::parse(&*bytes).expect("the eBPF object does not parse as an ELF");
    let bss = elf
        .section_by_name(".bss")
        .expect("the object carries no .bss section, so the tables are not where this test looks");
    let section = bss.index();
    let at = |name: &str| -> usize {
        let symbol = elf
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .unwrap_or_else(|| panic!("no {name} symbol in the object"));
        assert_eq!(
            symbol.section_index(),
            Some(section),
            "{name} is not in .bss, so one write of that section would not publish it"
        );
        symbol.address() as usize
    };
    Bss {
        bytes: bss.size() as usize,
        class24_at: at(CLASS24_SYMBOL),
        oa_at: at(OA_TABLE_SYMBOL),
    }
}

/// The whole section as one value, which is what the map holds.
fn section_image(layout: &Bss, snapshot: &Snapshot) -> Vec<u8> {
    // SAFETY: `OaSlot` is `repr(C)`, eight bytes and no padding — asserted in
    // `lorica_common::blocklist` — so the vector is exactly its own bytes.
    let oa = unsafe {
        std::slice::from_raw_parts(
            snapshot.oa.as_ptr().cast::<u8>(),
            std::mem::size_of_val(snapshot.oa.as_slice()),
        )
    };
    let mut image = vec![0u8; layout.bytes];
    image[layout.class24_at..][..CLASS24_BYTES].copy_from_slice(&snapshot.class24);
    image[layout.oa_at..][..oa.len()].copy_from_slice(oa);
    image
}

/// One `bpf(BPF_MAP_UPDATE_ELEM)` against the section map.
///
/// The `elem` arm of `union bpf_attr`, field for field: the kernel reads it by offset, so the
/// layout is the contract and the padding after `map_fd` is part of it.
fn write_section(fd: std::os::fd::BorrowedFd<'_>, image: &[u8]) -> io::Result<()> {
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let key: u32 = 0;
    let mut attr = Attr {
        map_fd: fd.as_raw_fd() as u32,
        pad: 0,
        key: (&raw const key) as usize as u64,
        value: image.as_ptr() as usize as u64,
        flags: 0,
    };
    // SAFETY: the key points at four live bytes, which is the map's key size, and the value
    // at `image.len()` live bytes, which is asserted equal to the map's value size by the
    // caller reading the same number off the ELF the map was created from.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            (&raw mut attr).cast::<libc::c_void>(),
            std::mem::size_of::<Attr>() as libc::c_ulong,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a full blocklist reload costs in system calls, and whether it reaches the packet path.
///
/// **The number this contradicts or confirms.** Filling the trie was a batch of
/// `BPF_MAP_UPDATE_BATCH` calls, one per chunk of entries. `aya-obj` 0.3 gives `.bss` no
/// `BPF_F_MMAPABLE` — it maps `EbpfSectionKind::Bss` to `map_flags: 0` — but it does
/// materialise the whole section as an `ARRAY` of **one** entry, so the prediction is that a
/// reload of both tables is one `bpf_map_update_elem` whatever the number of keys. This test
/// performs exactly `LORICA_BLOCKLIST_RELOADS` of them, so `strace -c -e trace=bpf` over two
/// runs differing only in that variable counts the syscalls of a reload by subtraction
/// instead of attributing them among the load's own.
///
/// The assertion is not the count — a count this process makes of itself proves nothing. It is
/// that the packet path answers the *new* snapshot afterwards: a write that lands in a map the
/// program no longer reads would be one syscall and no reload at all.
#[test]
fn a_full_reload_is_one_write_of_the_section() {
    let reloads: usize = env::var("LORICA_BLOCKLIST_RELOADS")
        .ok()
        .map(|raw| {
            raw.parse()
                .unwrap_or_else(|err| panic!("LORICA_BLOCKLIST_RELOADS={raw:?}: {err}"))
        })
        .unwrap_or(1);

    let mut rng = Rng::new(SEED ^ 0x5e10_ad00);
    let config = draw_config(&mut rng);
    let probe = rng.word();

    let mut before = config.clone();
    before.push((probe, 32, Action::Drop));
    let mut after = config;
    after.push((probe, 32, Action::Allow));
    let before = build(&before, EXPANSION_BUDGET).expect("the drawn configuration was refused");
    let after = build(&after, EXPANSION_BUDGET).expect("the drawn configuration was refused");

    let layout = bss_layout();
    let image = section_image(&layout, &after);
    let prog = flat_program(&before);
    let pkt = udp_from(probe);
    assert_eq!(
        prog.run(&pkt),
        XdpAction::Drop,
        "{} is a /32 deny in the loaded snapshot",
        dotted(probe)
    );

    let fd = prog.map_fd(".bss");
    for _ in 0..reloads {
        write_section(fd, &image).unwrap_or_else(|err| {
            panic!(
                "writing {} bytes at key 0 of the section map failed: {err}",
                image.len()
            )
        });
    }
    println!(
        "blocklist-reload section_bytes={} class24_at={} oa_at={} writes={reloads} \
         keys_before={} keys_after={}",
        layout.bytes, layout.class24_at, layout.oa_at, before.keys, after.keys
    );

    if reloads > 0 {
        assert_eq!(
            prog.run(&pkt),
            XdpAction::Pass,
            "{} still drops after the section was rewritten with a snapshot that allows it, \
             so the write did not reach the program",
            dotted(probe)
        );
    }
}
