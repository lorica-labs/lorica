//! The names an operator types against the bits they set.
//!
//! `OPERATOR_SETTINGS` restates by hand which of the policy bits are the operator's, and a
//! bit added to `setting` without a line in the table is a knob that exists in the program
//! and cannot be reached from the command line. That is the quiet direction of the drift:
//! nothing fails, the stage simply never enforces, and the operator finds out during the
//! attack the stage was for.
//!
//! So the table is checked against the two properties that make it complete rather than
//! against a second list of names, which would be the same defect one level up.

use lorica_common::{DEFAULT_SETTINGS, OPERATOR_SETTINGS, setting, settings_word};

/// Every bit the loader owns, and why it is not the operator's to type.
///
/// `URPF_ENFORCE` is a criterion the loader evaluates against the routing table of the
/// ingress interface; `MARK_OVER_BUDGET` is a capability the loader asks the kernel about. A
/// name for either would let an operator claim a verdict the machine cannot deliver.
const LOADER_OWNED: u32 = setting::URPF_ENFORCE | setting::MARK_OVER_BUDGET;

#[test]
fn the_table_names_every_bit_that_is_not_the_loaders() {
    let named = OPERATOR_SETTINGS
        .iter()
        .fold(0, |word, (_, bit)| word | bit);

    // The eight bits the word currently spells. Written as a mask rather than counted, so
    // that a ninth bit added to neither side is caught by the assertion below and not by
    // arithmetic that happens to still add up.
    let all = named | LOADER_OWNED;
    assert_eq!(
        all, 0xff,
        "the policy word spells {all:#x} between the table and the loader's own bits: a bit \
         belongs to one of the two, and one that belongs to neither is a knob nobody can set"
    );
    assert_eq!(
        named & LOADER_OWNED,
        0,
        "a bit is both named for the operator and set by the loader, so whichever runs last \
         decides and the command line is a suggestion"
    );
}

#[test]
fn no_two_names_set_the_same_bit() {
    for (i, (name, bit)) in OPERATOR_SETTINGS.iter().enumerate() {
        for (other, other_bit) in &OPERATOR_SETTINGS[i + 1..] {
            assert_ne!(
                bit, other_bit,
                "{name} and {other} set the same bit, so one of them does nothing an \
                 operator can observe"
            );
        }
    }
}

#[test]
fn a_list_sets_exactly_the_bits_it_names() {
    assert_eq!(settings_word(""), Ok(DEFAULT_SETTINGS));
    assert_eq!(
        settings_word("enforce-signatures"),
        Ok(setting::ENFORCE_SIGNATURES)
    );
    assert_eq!(
        settings_word("enforce-signatures,enforce-buckets"),
        Ok(setting::ENFORCE_SIGNATURES | setting::ENFORCE_BUCKETS)
    );
    // Whitespace and a trailing comma are how a shell-quoted list arrives, not a mistake.
    assert_eq!(
        settings_word(" enforce-buckets , drop-icmp-echo ,"),
        Ok(setting::ENFORCE_BUCKETS | setting::DROP_ICMP_ECHO)
    );
    // Naming one twice is not an error: the word is a set, and refusing would be a rule an
    // operator has to know before a generated command line works.
    assert_eq!(
        settings_word("enforce-buckets,enforce-buckets"),
        Ok(setting::ENFORCE_BUCKETS)
    );
}

#[test]
fn an_unknown_name_is_refused_and_named() {
    // The whole point of the refusal: `enforce-signature` is one character from a real bit,
    // and accepting it would leave the stage observing while the operator believes otherwise.
    assert_eq!(
        settings_word("enforce-buckets,enforce-signature"),
        Err("enforce-signature")
    );
    // A bit the loader owns is refused by the same path, which is what stops it being
    // documented into existence.
    assert_eq!(settings_word("urpf-enforce"), Err("urpf-enforce"));
    assert_eq!(settings_word("mark-over-budget"), Err("mark-over-budget"));
}

/// The upper half of the word is the measurement build's stage cutoff.
///
/// A name that reached into it would truncate the pipeline on a production load, which is
/// the one failure in this file that changes what the program does to a packet rather than
/// what it reports.
#[test]
fn no_name_reaches_the_stage_cutoff_half() {
    for (name, bit) in OPERATOR_SETTINGS {
        assert_eq!(
            bit >> lorica_common::STAGE_CUTOFF_SHIFT,
            0,
            "{name} sets {bit:#x}, which overlaps the stage cutoff"
        );
    }
}
