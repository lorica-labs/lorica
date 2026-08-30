//! The annotated configuration shipped in `examples/` compiles.
//!
//! It is the first file anyone copies, so an example that does not parse is worse than no
//! example at all: it teaches a syntax that does not exist and it does it to someone who has
//! no way to tell. `deny_unknown_fields` makes that easy to do by accident — renaming a field
//! in the struct leaves the example silently wrong until somebody tries it.
//!
//! The assertions are about what the file *demonstrates*, not about its values. An example
//! that compiled but armed nothing and refused nothing would parse fine and teach nothing.

use std::{fs, path::PathBuf};

use lorica_common::Clock;
use lorica_policy::{Config, MemlockModel, Mode, compile};

const CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 1_000_000,
};

fn example() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/lorica.toml");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

#[test]
fn the_shipped_example_parses_and_compiles() {
    let text = example();
    let config = Config::from_toml(&text)
        .unwrap_or_else(|err| panic!("examples/lorica.toml does not parse: {err}"));
    let compiled = compile(&config, CLOCK, MemlockModel::MEASURED)
        .unwrap_or_else(|err| panic!("examples/lorica.toml does not compile: {err}"));

    // The example is the safe default it tells the reader it is. An example that shipped
    // `mode = "armed"` would put a first-time operator's traffic behind a policy they have
    // not watched run.
    assert_eq!(config.mode, Mode::Observe);
    assert_eq!(
        compiled.settings, 0,
        "the example arms a stage, and the file says every knob in it is off"
    );

    // It demonstrates the rule shapes and the scope requirement, which is the whole reason to
    // read it rather than the struct.
    assert!(
        compiled.entries.len() + compiled.flat.len() >= 4,
        "the example compiles {} trie entries and {} flat prefixes: it is meant to show a          scoped allow, a deny with a TTL and a deny that reaches the flat tables",
        compiled.entries.len(),
        compiled.flat.len()
    );

    // **Both halves of stage 3 are demonstrated, and that is the part a reader most needs.**
    // Which table a rule compiles into is decided by the rule and never written in the file,
    // so an example that exercised only one would teach that the choice does not exist.
    assert!(
        !compiled.flat.is_empty(),
        "no rule of the example reaches the flat tables, so it does not show that an IPv4          deny with no scope and no TTL goes somewhere different from the rest"
    );
    assert!(
        !compiled.entries.is_empty(),
        "no rule of the example stays in the trie, so it does not show what the flat tables          cannot hold"
    );
    assert!(
        !compiled.bogons.is_empty(),
        "no bogon table, so the example does not show that one comes for free"
    );

    // The budget it names is the one it fits in, which is the refusal a reader is most likely
    // to hit first and least likely to expect.
    let needed = compiled.sizes.memlock_bytes(MemlockModel::MEASURED);
    let budget = compiled.profile.memlock_budget();
    assert!(
        needed <= budget,
        "the example needs {needed} bytes of locked memory and its own profile allows {budget}"
    );
}

/// Every service the example names is used by a rule, or is one a reader would recognise.
///
/// A `[services]` block whose names go nowhere teaches that the block is decorative.
#[test]
fn the_example_uses_a_service_name_it_declares() {
    let config = Config::from_toml(&example()).expect("parses");
    assert!(!config.services.is_empty(), "no services to demonstrate");
    let referenced: Vec<&String> = config
        .rules
        .iter()
        .flat_map(|rule| rule.scopes.iter())
        .collect();
    assert!(
        referenced.iter().any(|scope| config.services.contains_key(scope.as_str())),
        "the example declares services {:?} and no rule refers to one by name, so it does not \
         show what the block is for",
        config.services.keys().collect::<Vec<_>>()
    );
}
