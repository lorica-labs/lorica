//! The call budget, both halves of it.
//!
//! The static half: how many helper calls are *present* in the program, all branches
//! counted, read from the compiled object before it is ever loaded. Deterministic,
//! independent of the kernel, and it protects from the first commit.
//!
//! The per-packet half: how many calls one packet actually executes, read out of the
//! instrumented build. Neither replaces the other. The static count sees the branches a
//! packet never takes, which is how stage 5 is in it at all; the per-packet count sees
//! which of them the steady state pays for, and that is the figure the design states.
//!
//! `bpftool prog dump xlated` is not a source for either. The verifier inlines
//! `bpf_map_lookup_elem` on ARRAY, HASH and PERCPU_*, so the dump undercounts, and by
//! how much depends on the kernel version: the assertion would break on the first
//! upgrade of a runner.

use std::{env, fs, path::PathBuf};

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
mod support;

#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
use lorica_common::setting;
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
use support::{
    PktBuilder, XdpAction,
    net::{self, Link},
    program, program_with,
};

/// Calls present in the packet path, entry point and subprograms together.
///
/// Six, not the two lookups and one clock read a legitimate packet pays. This ceiling
/// counts every branch at once, including the ones a given packet never takes: the
/// reverse-path lookup of stage 5 is in the object on every host and on the path only
/// where the loader set `URPF_ENFORCE`.
///
/// **Five are present today**, and they are the wrappers of the data path: the list, the
/// bank, the counters, the clock, the reverse path. One slot of headroom, and it is a real
/// one — see [`OFF_PACKET_PATH`] for the call this deliberately does not count and why.
const BUDGET: usize = 6;

/// The entry points whose calls this budget does not count, because no packet reaches
/// them.
///
/// `lorica_clock` reads `CLOCK_PROBE` so the agent can turn a TTL in seconds into a
/// deadline, since the kernel exposes neither `CONFIG_HZ` nor the current jiffy to
/// userspace. Its one helper call is in the same object as the data path and would
/// otherwise fill the last slot of a ceiling whose whole meaning is per-packet — a budget
/// that a program which never sees a packet can exhaust is measuring the wrong thing, and
/// the next call added anywhere would have failed an assertion that exists to catch calls
/// added to the *packet path*.
///
/// An exclusion is a hole in an assertion, so [`the_excluded_program_is_the_one_named`]
/// pins what is behind it: the symbol has to exist and to contribute exactly one call. A
/// second call appearing there is a change worth seeing rather than one worth hiding.
const OFF_PACKET_PATH: &[&str] = &["lorica_clock"];

/// Not an intention, an assertion. Zero kfuncs on the core program is what guarantees
/// no dependency on netfilter conntrack and no dependency on a git version of aya.
const KFUNC_BUDGET: usize = 0;

/// The per-packet ceiling, and the one the design is written against.
///
/// Settled by the bank layout campaign, `docs/mesures/09-contention-banc.md` §4, where it
/// moved in neither direction: the bank adds one lookup whatever the layout, per-CPU or
/// shared, because it is a map entry to read. A lock would have taken the path to three
/// lookups and *three* helpers, above this ceiling, and that is one of the reasons it was
/// not taken.
///
/// The budget is not a cost. The verifier inlines `bpf_map_lookup_elem` on ARRAY and
/// PERCPU_*, so the counter bump and the bank charge are a few instructions rather than
/// two function calls, and it inlines `bpf_jiffies64` into a load of the kernel's jiffy
/// counter. The unified-list lookup is an `LPM_TRIE`, which is not inlinable, and is the
/// only one of the three that is a real call. What this ceiling counts is chances to get
/// it wrong, not nanoseconds.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
const LOOKUP_BUDGET: u64 = 3;

/// One reading of the clock per packet, taken in `stage::run` and passed down. Counted
/// although the verifier inlines it, because the number a stage can get wrong is how many
/// times it reads the clock and not how many calls that costs.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
const CLOCK_BUDGET: u64 = 1;

/// What the steady state actually pays: the unified-list lookup and the bank lookup, two
/// of the three the ceiling allows.
///
/// Asserted as an equality and not only against the ceiling. A test that checks a ceiling
/// alone stops noticing when a stage quietly adds a lookup underneath it, and the third
/// slot is exactly the room such a stage would grow into.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
const OBSERVED_LOOKUPS: u64 = 2;

const CALL_OPCODE: u8 = 0x85;
const INSN_LEN: usize = 8;

#[derive(Default, Debug, PartialEq, Eq)]
struct Calls {
    helper: usize,
    bpf_to_bpf: usize,
    kfunc: usize,
}

/// An eBPF instruction is eight bytes: opcode, then a byte holding the destination
/// register in the low nibble and the source register in the high one, then a 16-bit
/// offset and a 32-bit immediate. On a call, the source register says what kind of
/// call it is.
fn count(code: &[u8]) -> Calls {
    let mut calls = Calls::default();
    for insn in code.chunks_exact(INSN_LEN) {
        if insn[0] != CALL_OPCODE {
            continue;
        }
        match insn[1] >> 4 {
            0 => calls.helper += 1,
            1 => calls.bpf_to_bpf += 1,
            2 => calls.kfunc += 1,
            other => panic!("a call with source register {other} is not a call kind we know"),
        }
    }
    calls
}

/// Per-function counts, so a failure names the function that grew.
fn program_calls(object_bytes: &[u8]) -> Vec<(String, Calls)> {
    let file = object::File::parse(object_bytes).expect("the eBPF object is not a valid ELF");
    let mut per_function = Vec::new();

    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
            continue;
        }
        let Some(index) = symbol.section_index() else {
            continue;
        };
        let section = file
            .section_by_index(index)
            .expect("a symbol pointed at a section that is not there");
        let data = section.data().expect("a text section without data");

        let start = symbol.address() as usize;
        let end = start + symbol.size() as usize;
        assert!(
            end <= data.len(),
            "{} runs past the end of section {}",
            symbol.name().unwrap_or("<unnamed>"),
            section.name().unwrap_or("<unnamed>")
        );

        let name = symbol.name().unwrap_or("<unnamed>").to_owned();
        per_function.push((name, count(&data[start..end])));
    }

    per_function
}

/// The total over the packet path only. [`OFF_PACKET_PATH`] says which symbols are left
/// out and why the exclusion is not a way of making the number smaller.
fn total(per_function: &[(String, Calls)]) -> Calls {
    per_function
        .iter()
        .filter(|(name, _)| !OFF_PACKET_PATH.contains(&name.as_str()))
        .fold(Calls::default(), |mut sum, (_, calls)| {
            sum.helper += calls.helper;
            sum.bpf_to_bpf += calls.bpf_to_bpf;
            sum.kfunc += calls.kfunc;
            sum
        })
}

/// The object without instrumentation. The budget is a property of the program that
/// ships, not of the build the tests read counters out of, which adds a map write per
/// counted call on purpose.
fn plain_object() -> Vec<u8> {
    let path = env::var("LORICA_EBPF_PLAIN_OBJ").map_or_else(
        |_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../lorica-ebpf/target/bpfel-unknown-none/release/lorica-ebpf")
        },
        PathBuf::from,
    );
    fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "cannot read the eBPF object at {}: {err}\n\
             build it with: cd crates/lorica-ebpf && cargo +nightly build --release\n\
             or point LORICA_EBPF_PLAIN_OBJ at one built without features",
            path.display()
        )
    })
}

#[test]
fn the_program_stays_inside_its_call_budget() {
    let per_function = program_calls(&plain_object());
    let calls = total(&per_function);

    assert!(
        calls.helper <= BUDGET,
        "{} helper calls present, budget {BUDGET}\n{}",
        calls.helper,
        breakdown(&per_function)
    );
}

/// What the exclusion of [`OFF_PACKET_PATH`] covers, stated so it cannot quietly widen.
///
/// A name that stopped matching would silently put the calibration call back inside the
/// budget; a name that started covering more would silently take calls out of it. Both are
/// caught here rather than in whichever assertion happened to move.
#[test]
fn the_excluded_program_is_the_one_named() {
    let per_function = program_calls(&plain_object());

    for name in OFF_PACKET_PATH {
        let (_, calls) = per_function
            .iter()
            .find(|(symbol, _)| symbol == name)
            .unwrap_or_else(|| {
                panic!("{name} is excluded from the call budget but is not in the object")
            });
        assert_eq!(
            calls.helper, 1,
            "{name} is excluded from the call budget and makes {} helper calls, not 1",
            calls.helper
        );
    }
}

#[test]
fn the_program_calls_no_kfunc() {
    let per_function = program_calls(&plain_object());
    let calls = total(&per_function);

    assert_eq!(
        calls.kfunc,
        KFUNC_BUDGET,
        "the core data path must reach no kfunc\n{}",
        breakdown(&per_function)
    );
}

/// The guard that makes the other two mean something. A counter that read the wrong
/// section, or the wrong symbol range, would return zero for everything and pass the
/// budget without ever looking at the program.
#[test]
fn the_count_is_actually_read_from_the_object() {
    let per_function = program_calls(&plain_object());
    let calls = total(&per_function);

    assert!(
        calls.helper > 0,
        "no helper call found at all, so this guard is measuring nothing\n{}",
        breakdown(&per_function)
    );
    assert!(
        calls.bpf_to_bpf > 0,
        "no bpf-to-bpf call found, but every helper wrapper is a subprogram\n{}",
        breakdown(&per_function)
    );
}

/// The three kinds are told apart by the source register, and getting that wrong
/// would report kfuncs as helpers or the reverse.
#[test]
fn the_counter_tells_the_three_call_kinds_apart() {
    let mut code = Vec::new();
    for src_reg in [0u8, 1, 2] {
        code.extend_from_slice(&[CALL_OPCODE, src_reg << 4, 0, 0, 0, 0, 0, 0]);
    }
    // A non-call instruction whose second byte would look like a kfunc call if the
    // opcode were ignored.
    code.extend_from_slice(&[0xb7, 0x20, 0, 0, 0, 0, 0, 0]);

    assert_eq!(
        count(&code),
        Calls {
            helper: 1,
            bpf_to_bpf: 1,
            kfunc: 1,
        }
    );
}

/// A legitimate UDP frame on the game port, from a source no list entry covers.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
fn legit_udp(src: [u8; 4]) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(1111, 30_120)
        .build()
}

/// The steady state: a legitimate packet that matches nothing, stage 5 disarmed, and the
/// bank present so the charge is a real lookup. Two lookups and one clock read against a
/// ceiling of three and one.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
#[test]
fn a_legitimate_packet_stays_inside_the_per_packet_budget() {
    let prog = program();
    assert_eq!(prog.run(&legit_udp([203, 0, 113, 1])), XdpAction::Pass);
    let counts = prog.helper_counts();

    assert!(
        counts.map_lookups <= LOOKUP_BUDGET,
        "the ceiling is {LOOKUP_BUDGET} lookups, got {counts:?}"
    );
    assert_eq!(
        counts.map_lookups, OBSERVED_LOOKUPS,
        "expected the unified list and the bank, got {counts:?}"
    );
    assert_eq!(
        counts.clock_reads, CLOCK_BUDGET,
        "the clock is read once in stage::run and passed down, got {counts:?}"
    );
    assert_eq!(
        counts.fib_lookups, 0,
        "URPF_ENFORCE is clear, so the reverse-path lookup must not be on this path: \
         {counts:?}"
    );
}

/// The one call the uRPF criterion exists to avoid paying for, asserted on its own rather
/// than folded into a total a lookup could hide in: arming stage 5 costs **+140 ns** on a
/// legitimate path that otherwise costs 210 ns above the 15 ns floor.
///
/// The interface forwards and holds a connected route to the source, so the answer is
/// `SUCCESS` on the ingress interface and no counter is bumped. Without it the answer is
/// `FWD_DISABLED`, which bumps one, and the two paths would then differ by a lookup that
/// is not stage 5's.
#[cfg(all(feature = "kernel-tests", feature = "count-helpers"))]
#[test]
fn arming_the_reverse_path_buys_one_call_and_no_lookup() {
    let name = "budget-urpf";
    let _link = Link::dummy(name);
    if let Err(err) = net::ip(&["addr", "add", "10.90.61.1/24", "dev", name]) {
        eprintln!("SKIP {name}: cannot address the interface: {err}");
        return;
    }
    if let Err(err) = fs::write(format!("/proc/sys/net/ipv4/conf/{name}/forwarding"), "1") {
        eprintln!("SKIP {name}: cannot enable forwarding: {err}");
        return;
    }
    let ifindex = net::ifindex(name);
    let pkt = legit_udp([10, 90, 61, 5]);

    let idle = program();
    assert_eq!(idle.run_from(&pkt, ifindex), XdpAction::Pass);
    let idle_counts = idle.helper_counts();

    let armed = program_with(setting::URPF_ENFORCE);
    assert_eq!(armed.run_from(&pkt, ifindex), XdpAction::Pass);
    let armed_counts = armed.helper_counts();

    assert_eq!(
        idle_counts.fib_lookups, 0,
        "the gate did not keep the lookup out of the path: {idle_counts:?}"
    );
    assert_eq!(
        armed_counts.fib_lookups, 1,
        "one lookup per packet, and only one: {armed_counts:?}"
    );
    assert_eq!(
        armed_counts.map_lookups, idle_counts.map_lookups,
        "arming stage 5 bought a lookup as well as the call: {armed_counts:?} against \
         {idle_counts:?}"
    );
    assert_eq!(
        armed_counts.map_lookups, OBSERVED_LOOKUPS,
        "expected the unified list and the bank, got {armed_counts:?}"
    );
    assert_eq!(
        armed_counts.clock_reads, CLOCK_BUDGET,
        "got {armed_counts:?}"
    );
}

fn breakdown(per_function: &[(String, Calls)]) -> String {
    let mut out = String::from("per function:\n");
    for (name, calls) in per_function {
        if calls.helper + calls.bpf_to_bpf + calls.kfunc == 0 {
            continue;
        }
        out.push_str(&format!(
            "  {name}: {} helper, {} bpf-to-bpf, {} kfunc\n",
            calls.helper, calls.bpf_to_bpf, calls.kfunc
        ));
    }
    out
}
