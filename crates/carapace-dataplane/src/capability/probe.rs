//! What this kernel actually has, from two kinds of evidence: a symbol the capability
//! cannot exist without, and failing that the release number.

use super::{Detected, matrix};

const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const KALLSYMS: &str = "/proc/kallsyms";

/// `(major, minor)` of the running kernel, `None` when the file is unreadable or does not
/// parse. The patch level is dropped: no capability of the matrix hangs on it.
pub fn running_release() -> Option<(u32, u32)> {
    parse_release(&std::fs::read_to_string(OSRELEASE).ok()?)
}

/// Every capability of the matrix, in matrix order.
pub fn detect_all() -> Vec<Detected> {
    let release = running_release();
    // Read once: the table is a few megabytes and every symbol probe walks the same copy.
    let symbols = std::fs::read_to_string(KALLSYMS).ok();

    matrix::ROWS
        .iter()
        .map(|row| Detected {
            cap: row.cap,
            available: match (row.symbol, symbols.as_deref()) {
                (Some(symbol), Some(table)) => defines(table, symbol),
                // No symbol tells this one apart, or kallsyms is closed to us. The release
                // number is the only evidence left, and it misses a backport.
                _ => release.is_some_and(|running| running >= row.since),
            },
            fallback: row.fallback,
        })
        .collect()
}

fn parse_release(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim().split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// A line of `/proc/kallsyms` is `address type name [\t[module]]`. The name column is
/// compared whole, never as a substring: `bpf_qdisc_init` is not evidence of
/// `bpf_Qdisc_ops`, and `__pfx_` and `__ksymtab_` prefixes would match everything.
fn defines(table: &str, symbol: &str) -> bool {
    table
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some(symbol))
}
