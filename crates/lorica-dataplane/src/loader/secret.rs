//! The secret the bucket index is keyed with, drawn at load and never written down.

use std::{fs::File, io::Read};

/// Sixteen bytes from `/dev/urandom`.
///
/// Read with `std::fs` and not with a crate: neither `rand` nor `getrandom` is in this
/// workspace, and sixteen bytes read once per load do not justify adding one.
///
/// Nothing persists the result, and that is the property rather than an omission. A key
/// that survives a reload is a key whose collisions an attacker has had time to find, and
/// keying the index is worth doing precisely because the addresses that shared a bucket
/// before a reload do not share one after it.
pub fn draw_index_key() -> std::io::Result<[u8; 16]> {
    let mut key = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}
