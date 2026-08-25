//! The catalogue is written twice — here for the operator, and in `lorica-ebpf` for
//! the data path — because the two crates build for different targets and cannot see
//! each other. These tests are what stands in for the compiler across that gap.

use lorica_common::{Action, Clock, CounterId, SIGNATURE_VECTORS_ALL, setting};
use lorica_policy::{
    Config, MemlockModel, compile,
    compile::{CompileError, Compiled, signature},
};

/// The rate and the reading the compiler turns a TTL in seconds into a deadline with. 250 Hz
/// rather than 1000, as the other policy tests use: a deadline built by multiplying by the
/// wrong constant is off by a factor of four here and exactly right at 1000.
const CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 1_000_000,
};

fn settings_word(text: &str) -> u32 {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, CLOCK, MemlockModel::MEASURED)
        .expect("the configuration did not compile")
        .settings
}

fn compiled(text: &str) -> Result<Compiled, CompileError> {
    let config = Config::from_toml(text).expect("the configuration did not parse");
    compile(&config, CLOCK, MemlockModel::MEASURED)
}

fn signature_counters() -> Vec<CounterId> {
    CounterId::ALL
        .into_iter()
        .filter(|id| id.name().starts_with("signature_"))
        .collect()
}

/// The join between the two copies of the catalogue. A vector added to the counter list
/// without a verdict here, or a verdict here for a counter nobody bumps, fails from this
/// one assertion — which is the only reason writing the table twice is acceptable.
#[test]
fn the_catalogue_covers_every_signature_counter_exactly_once() {
    let counters = signature_counters();
    let rows: Vec<CounterId> = signature::CATALOG
        .iter()
        .map(|vector| vector.counter)
        .collect();

    assert_eq!(
        rows, counters,
        "the catalogue and the Signature* counters disagree, in content or in order"
    );
}

/// The order is load-bearing: the data path numbers its vectors by their position in the
/// same list, so a row inserted in the middle here and appended there would give two
/// crates two different ordinals for one vector.
#[test]
fn the_catalogue_is_in_counter_declaration_order() {
    let indices: Vec<u32> = signature::CATALOG
        .iter()
        .map(|vector| vector.counter.index())
        .collect();
    let mut sorted = indices.clone();
    sorted.sort_unstable();
    assert_eq!(indices, sorted, "the catalogue is not in counter order");
}

/// A row whose verdict let the packet through would be a vector that does not belong in
/// the catalogue at all: the counter alone is what observation mode has to say, and the
/// verdict exists only for the armed case.
#[test]
fn every_vector_either_drops_or_rate_limits() {
    for vector in signature::CATALOG {
        assert!(
            matches!(vector.action, Action::Drop | Action::RateLimit),
            "{} answers {:?}, which is not a verdict a signature can reach",
            vector.counter.name(),
            vector.action
        );
    }
    assert_eq!(
        signature::verdict(CounterId::BogonRefused),
        None,
        "a counter that is not a vector must not have a verdict"
    );
    assert_eq!(
        signature::verdict(CounterId::SignatureFragAbuse),
        Some(Action::Drop)
    );
}

/// Both halves of the catalogue exist. An all-drop table would make stage 6's third
/// answer unreachable, and an all-rate-limit table would give away the licence to drop
/// without the buckets that is the reason the stage sits where it does.
#[test]
fn the_catalogue_uses_both_verdicts() {
    assert!(
        signature::CATALOG
            .iter()
            .any(|vector| vector.action == Action::Drop)
    );
    assert!(
        signature::CATALOG
            .iter()
            .any(|vector| vector.action == Action::RateLimit)
    );
}

/// A vector left out of the activation word is not in the loaded program at all, so the
/// three answers a configuration can give have to stay distinguishable: silence is the
/// whole catalogue, a list is that list, and an empty list is nothing.
#[test]
fn the_activation_word_says_what_the_configuration_asked_for() {
    let quiet = compiled("profile = \"host\"\n").expect("it did not compile");
    assert_eq!(quiet.signature_vectors, SIGNATURE_VECTORS_ALL);

    let empty = compiled("profile = \"host\"\nsignatures = []\n").expect("it did not compile");
    assert_eq!(empty.signature_vectors, 0);

    // The bit is the row's place in the catalogue, which is where the data path reads it.
    let two = compiled("profile = \"host\"\nsignatures = [\"amp_ntp\", \"frag_abuse\"]\n")
        .expect("it did not compile");
    assert_eq!(two.signature_vectors, (1 << 1) | (1 << 7));
}

/// A name nobody recognises is refused while the file is being read. Taking it as "leave
/// that vector out" would be a defense missing from the program with nothing anywhere
/// saying so — the counter would read zero and read zero honestly.
#[test]
fn a_misspelt_vector_is_refused_rather_than_dropped() {
    assert_eq!(
        compiled("profile = \"host\"\nsignatures = [\"amp_dsn\"]\n").unwrap_err(),
        CompileError::UnknownSignatureVector {
            name: "amp_dsn".to_owned()
        }
    );
    // The counter name itself, prefix included, is not the spelling either: one name per
    // vector, and it is the one an operator writes.
    assert!(compiled("profile = \"host\"\nsignatures = [\"signature_amp_dns\"]\n").is_err());
}

/// Observation is the default, and it is the default in the compiler and not only in the
/// program: a configuration that says nothing about signatures must not arm them.
#[test]
fn signatures_are_unarmed_unless_the_operator_says_otherwise() {
    let quiet = settings_word("profile = \"host\"\n");
    assert_eq!(quiet & setting::ENFORCE_SIGNATURES, 0);

    let armed = settings_word(
        r#"
        profile = "host"
        [settings]
        enforce_signatures = true
        "#,
    );
    assert_eq!(
        armed & setting::ENFORCE_SIGNATURES,
        setting::ENFORCE_SIGNATURES
    );
}
