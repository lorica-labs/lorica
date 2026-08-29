//! `.bss` holds the two blocklist tables and nothing else.
//!
//! The agent publishes a blocklist by writing the whole `.bss` section as one value, which is
//! what makes a reload one system call instead of one per prefix. That is only correct while
//! the section is only the tables: a zero-initialised `static` added to the program would land
//! here too, and every publish would silently zero it. The failure would not be a crash — it
//! would be a global that reads zero after the first reload and correct before it, which is the
//! shape of bug that takes a week.
//!
//! So the check is on the shipped object rather than on the source. `SETTINGS`,
//! `SIGNATURE_VECTORS`, `COUNTER_STRIPE` and the bucket words are all initialised non-zero or
//! patched at load and live in `.rodata`; nothing enforces that but the compiler's own
//! placement, and this test is what notices when the placement changes.

use std::{env, fs, path::PathBuf};

use lorica_common::blocklist::{CLASS24_BYTES, CLASS24_SYMBOL, OA_BYTES, OA_TABLE_SYMBOL};
use lorica_dataplane::maps::blocklist::SECTION;
use object::{Object, ObjectSection, ObjectSymbol};

fn object_bytes() -> Vec<u8> {
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
             build it with: cd crates/lorica-ebpf && cargo +nightly build --release",
            path.display()
        )
    })
}

#[test]
fn the_section_is_exactly_the_two_tables() {
    let bytes = object_bytes();
    let elf = object::File::parse(&*bytes).expect("the eBPF object parses as an ELF");
    let bss = elf
        .section_by_name(SECTION)
        .expect("the object carries a .bss section");

    assert_eq!(
        bss.size() as usize,
        CLASS24_BYTES + OA_BYTES,
        "{SECTION} is {} bytes and the two tables account for {}: something else is in the \
         section the agent overwrites whole on every blocklist publish",
        bss.size(),
        CLASS24_BYTES + OA_BYTES
    );

    let index = bss.index();
    let inhabitants: Vec<&str> = elf
        .symbols()
        .filter(|symbol| symbol.section_index() == Some(index))
        .filter_map(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
        .collect();
    assert_eq!(
        inhabitants,
        [CLASS24_SYMBOL, OA_TABLE_SYMBOL],
        "the symbols in {SECTION} are {inhabitants:?}; a publish writes over all of them, so \
         anything here that is not a blocklist table is a global zeroed by the next reload"
    );
}

/// The other half of the same invariant: the globals the loader patches are somewhere else.
///
/// Named individually rather than counted, because the point is not how many there are — it is
/// that each of these is read by the packet path after a reload has overwritten `.bss`.
#[test]
fn the_patched_globals_are_not_in_the_overwritten_section() {
    let bytes = object_bytes();
    let elf = object::File::parse(&*bytes).expect("the eBPF object parses as an ELF");
    let bss = elf
        .section_by_name(SECTION)
        .expect("the object carries a .bss section")
        .index();

    for name in [
        lorica_common::SETTINGS_SYMBOL,
        lorica_common::SIGNATURE_VECTORS_SYMBOL,
        lorica_common::COUNTER_STRIPE_SYMBOL,
        lorica_common::BUCKET_KEY_SYMBOLS[0],
        lorica_common::BUCKET_KEY_SYMBOLS[1],
    ] {
        let symbol = elf
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .unwrap_or_else(|| panic!("no {name} symbol in the object"));
        assert_ne!(
            symbol.section_index(),
            Some(bss),
            "{name} is patched by the loader and sits in {SECTION}, which a blocklist publish \
             overwrites: the program would read it correctly until the first reload and zero \
             after it"
        );
    }
}
