//! Static call budget: how many helper calls are *present* in the program, all
//! branches counted, read from the compiled object before it is ever loaded.
//!
//! Deterministic, independent of the kernel, and it protects from the first commit.
//! It is a different guard from the instrumented count, which measures how many calls
//! one packet actually executes; both are needed and neither replaces the other.
//!
//! `bpftool prog dump xlated` is not a source for either. The verifier inlines
//! `bpf_map_lookup_elem` on ARRAY, HASH and PERCPU_*, so the dump undercounts, and by
//! how much depends on the kernel version: the assertion would break on the first
//! upgrade of a runner.

use std::{env, fs, path::PathBuf};

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

/// Calls present in the whole program, entry point and subprograms together.
///
/// Six, not the two-lookups-plus-one-helper of the per-packet budget. This ceiling
/// counts every branch at once, including the ones a given packet never takes; the
/// per-packet budget is asserted by the instrumented build on a specific packet.
const BUDGET: usize = 6;

/// Not an intention, an assertion. Zero kfuncs on the core program is what guarantees
/// no dependency on netfilter conntrack and no dependency on a git version of aya.
const KFUNC_BUDGET: usize = 0;

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

fn total(per_function: &[(String, Calls)]) -> Calls {
    per_function
        .iter()
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
    let path = env::var("CARAPACE_EBPF_PLAIN_OBJ").map_or_else(
        |_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../carapace-ebpf/target/bpfel-unknown-none/release/carapace-ebpf")
        },
        PathBuf::from,
    );
    fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "cannot read the eBPF object at {}: {err}\n\
             build it with: cd crates/carapace-ebpf && cargo +nightly build --release\n\
             or point CARAPACE_EBPF_PLAIN_OBJ at one built without features",
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
        "no bpf-to-bpf call found, but the parsers are subprograms\n{}",
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
