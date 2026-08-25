//! The usage line against the flags the agent actually accepts.
//!
//! `USAGE` restates by hand what the `match` in `parse_options` decides, and it had already
//! drifted: `--sweep-every` was accepted, exercised by CI, and absent from the line an
//! operator reads after a typo. That is the third restatement in this tree to go stale in a
//! day — a ceiling of 765 against a program of 1 317, a comment claiming a guard that had been
//! overwritten, and this.
//!
//! So the flags are read out of the source of the file itself rather than listed again here.
//! A list in a test is the same defect one level up.

const MAIN: &str = include_str!("../src/main.rs");

/// Every `"--flag"` literal in the source, in order, deduplicated.
///
/// The `match` arms are the only place a double-dashed string literal appears in this file
/// besides `USAGE` itself, and the extraction takes both — which is what makes the two
/// comparable without parsing Rust.
fn flags(from: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for (start, _) in from.match_indices("\"--") {
        let rest = &from[start + 1..];
        if let Some(end) = rest.find('"') {
            let flag = &rest[..end];
            // `--flag` and nothing else: no spaces, so a usage fragment is not mistaken for
            // an accepted flag.
            if !flag.contains(' ') && !found.contains(&flag) {
                found.push(flag);
            }
        }
    }
    found
}

#[test]
fn the_usage_line_names_every_flag_the_agent_accepts() {
    let accepted = flags(MAIN);
    assert!(
        accepted.len() >= 8,
        "only {} flags found in the source, so the extraction is broken rather than the \
         usage line: {accepted:?}",
        accepted.len()
    );

    let usage = MAIN
        .split_once("const USAGE: &str =")
        .expect("main.rs declares USAGE")
        .1
        .split_once(";\n")
        .expect("the USAGE declaration ends")
        .0;

    for flag in accepted {
        assert!(
            usage.contains(flag),
            "`{flag}` is accepted by parse_options and absent from the usage line, so an \
             operator who mistypes is told about every option but that one"
        );
    }
}
