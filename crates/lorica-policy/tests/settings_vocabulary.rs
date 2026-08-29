//! The words the configuration file uses against the words the command line uses.
//!
//! The same six policy bits are spelled three times in this tree: as fields of
//! `config::Settings`, as arms of `compile::settings_word`, and as rows of
//! `lorica_common::OPERATOR_SETTINGS`, which is what `loricad --policy` reads. Two of them
//! had already drifted — `enforce_buckets` was in the bits and in the program and in neither
//! the file nor the compiler, so the leaky-bucket bank could not be armed from a
//! configuration at all and nothing said so.
//!
//! `lorica-common`'s own `settings_names.rs` proves the table complete against the bits.
//! This one proves the file complete against the table, which is the half that decides
//! whether `enforce_buckets = true` in a file and `--policy enforce-buckets` on a command
//! line reach the same program.

use lorica_common::{Clock, OPERATOR_SETTINGS};
use lorica_policy::{Config, MemlockModel, compile};

const CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 1_000_000,
};

/// The field name a command-line name is spelled with in TOML.
fn field(name: &str) -> String {
    name.replace('-', "_")
}

/// The policy word a `[settings]` body compiles to, or the parse error, so that a name with
/// no field is reported as the missing field it is rather than as an unwrap.
fn word_of(body: &str) -> Result<u32, String> {
    let text = format!("profile = \"vps\"\n[settings]\n{body}");
    let config = Config::from_toml(&text).map_err(|err| err.to_string())?;
    compile(&config, CLOCK, MemlockModel::MEASURED)
        .map(|compiled| compiled.settings)
        .map_err(|err| err.to_string())
}

#[test]
fn every_name_the_command_line_takes_is_a_field_of_the_file() {
    for (name, bit) in OPERATOR_SETTINGS {
        let word = word_of(&format!("{} = true\n", field(name))).unwrap_or_else(|err| {
            panic!(
                "`{name}` is a policy an operator can set on the command line and `{}` is not \
                 a field of [settings], so the same policy cannot be written in a file: {err}",
                field(name)
            )
        });
        assert_eq!(
            word,
            bit,
            "`{}` in the file compiles to {word:#x} and `--policy {name}` sets {bit:#x}, so \
             the two spellings of one policy reach different programs",
            field(name)
        );
    }
}

/// The other direction: a field that sets a bit nobody can name on the command line.
///
/// `deny_unknown_fields` means the file cannot carry a field the struct has not declared,
/// so the whole word a maximal file spells has to be the whole word the table spells.
#[test]
fn a_file_that_sets_everything_spells_exactly_the_tables_word() {
    let all: u32 = OPERATOR_SETTINGS
        .iter()
        .fold(0, |word, (_, bit)| word | bit);
    let body: String = OPERATOR_SETTINGS
        .iter()
        .map(|(name, _)| format!("{} = true\n", field(name)))
        .collect();
    let word = word_of(&body).expect("a file naming every policy parses and compiles");
    assert_eq!(
        word, all,
        "a file setting every named policy compiles to {word:#x} and the table spells \
         {all:#x}: a field of [settings] sets a bit the command line cannot, or sets none"
    );
}
