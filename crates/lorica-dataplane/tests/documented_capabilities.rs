//! The capability table in `docs/limits.md` against the one the code detects.
//!
//! **Why this exists.** That table restates seven names and seven kernel releases that live in
//! [`matrix::ROWS`], and a number copied from code into prose goes stale silently — this
//! project has done it twice, once with a ceiling of 765 standing against a program of 1 317
//! and once with eighteen named counters against thirty-four. A public document promising a
//! capability the binary no longer detects, or omitting one it gained, is the same defect
//! aimed at somebody who cannot read the source to check.
//!
//! It is a text search and not a generator on purpose. Generating the page would put the
//! prose under the build, and the prose is the part a human has to write: what the fallback
//! costs an operator is a judgement, not a field.

use lorica_dataplane::capability::matrix;

fn limits_page() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/limits.md");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn every_detected_capability_is_named_on_the_limits_page() {
    let page = limits_page();
    for entry in matrix::ROWS {
        let (major, minor) = entry.since;
        assert!(
            page.contains(entry.name),
            "docs/limits.md never names the capability `{}`, which the agent detects and \
             reports. An operator reading that page cannot know what an older kernel costs \
             them for it.",
            entry.name
        );
        let since = format!("{major}.{minor}");
        assert!(
            page.contains(&since),
            "docs/limits.md names `{}` but not the release {since} it arrives in, which is \
             the whole reason the row is on that page",
            entry.name
        );
    }
}

#[test]
fn the_limits_page_names_no_capability_the_agent_does_not_detect() {
    let page = limits_page();
    // Row cells, so a capability mentioned in prose does not have to be a detected one.
    for line in page.lines().filter(|l| l.starts_with("| `")) {
        let name = line
            .trim_start_matches("| `")
            .split('`')
            .next()
            .expect("a backticked first cell");
        assert!(
            matrix::ROWS.iter().any(|row| row.name == name),
            "docs/limits.md lists `{name}` in the capability table, and nothing detects it. \
             Either the row is stale or the detection was dropped; both are a promise the \
             binary does not keep."
        );
    }
}
