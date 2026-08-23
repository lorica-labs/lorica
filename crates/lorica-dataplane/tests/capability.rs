//! The capability table, and the assertions about it that survive maintenance.

#![cfg(feature = "kernel-tests")]

use lorica_dataplane::capability::{matrix, probe};

/// A capability without a reference path is a capability that changes the response tier
/// reached depending on the kernel — the one thing the project never allows. The compiler
/// already refuses a variant that has no row, `Capability::row` being an exhaustive match;
/// this catches the row that exists but says nothing.
#[test]
fn every_capability_names_a_reference_path_that_reaches_the_same_tier() {
    for entry in &matrix::ROWS {
        assert!(!entry.name.is_empty(), "a row has no name");
        assert!(
            !entry.fallback.is_empty(),
            "{} has no reference path: absent, it would change the tier reached",
            entry.name
        );
        assert_eq!(
            entry.cap.row().cap,
            entry.cap,
            "{} is not at its own index in ROWS",
            entry.name
        );
    }
}

/// A capability the probe never answers for is announced neither present nor absent, and
/// the table lies by omission instead of failing.
#[test]
fn the_probe_answers_for_every_row_of_the_matrix() {
    let detected = probe::detect_all();
    assert_eq!(detected.len(), matrix::ROWS.len());
    for (found, row) in detected.iter().zip(&matrix::ROWS) {
        assert_eq!(found.cap, row.cap);
        assert_eq!(found.fallback, row.fallback);
    }
}

/// The floor of the project is 6.8. A probe that cannot read the running release answers
/// "absent" for every capability decided by release number, which understates the kernel
/// silently — exactly the failure a table meant to announce the colour cannot have.
#[test]
fn the_running_release_is_readable_and_at_or_above_the_kernel_floor() {
    let release = probe::running_release().expect("/proc/sys/kernel/osrelease unreadable");
    assert!(
        release >= (6, 8),
        "running {release:?}, below the 6.8 floor"
    );
}
