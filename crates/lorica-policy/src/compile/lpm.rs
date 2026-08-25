//! Prefixes into keys of the unified list.
//!
//! Precedence is the specificity of the address and never the order of declaration.
//! That is a property of the trie, not of this code: the kernel returns the longest
//! match. What this code owes the operator is a refusal when two rules land on the
//! same prefix, because there the trie has no answer and picking one silently is a
//! false positive nobody can see.

use std::net::IpAddr;

use lorica_common::{LpmKey, V4_MAPPED_PREFIX_BITS};

use crate::compile::CompileError;

/// Parses `10.90.1.0/24`, `2001:db8::/32`, or a bare address as a single host.
///
/// IPv4 lands in the mapped range, so an IPv4 `/24` becomes a 120-bit prefix and one
/// trie holds both families behind one lookup.
pub fn parse_prefix(spec: &str) -> Result<LpmKey, CompileError> {
    let bad = || CompileError::BadPrefix {
        spec: spec.to_owned(),
    };

    let (addr_text, len_text) = match spec.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (spec, None),
    };

    let addr: IpAddr = addr_text.parse().map_err(|_| bad())?;
    let width = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    let declared = match len_text {
        Some(text) => text.parse::<u32>().map_err(|_| bad())?,
        None => width,
    };
    if declared > width {
        return Err(CompileError::PrefixTooLong {
            spec: spec.to_owned(),
            declared,
            width,
        });
    }

    // Host bits outside the prefix are refused rather than masked away. Masking them
    // would accept 10.90.1.7/24 and quietly turn it into 10.90.1.0/24, which is not
    // what the line says.
    let key = match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if has_bits_past(&octets, declared) {
                return Err(CompileError::PrefixHasHostBits {
                    spec: spec.to_owned(),
                });
            }
            LpmKey::v4(octets, declared)
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if has_bits_past(&octets, declared) {
                return Err(CompileError::PrefixHasHostBits {
                    spec: spec.to_owned(),
                });
            }
            LpmKey::v6(octets, declared)
        }
    };
    Ok(key)
}

/// Whether any bit past `prefix_len` is set.
fn has_bits_past(octets: &[u8], prefix_len: u32) -> bool {
    let full_bytes = (prefix_len / 8) as usize;
    let spare_bits = prefix_len % 8;

    if spare_bits != 0 {
        let mask = 0xffu8 >> spare_bits;
        if octets.get(full_bytes).is_some_and(|byte| byte & mask != 0) {
            return true;
        }
    }
    let first_whole_tail = full_bytes + usize::from(spare_bits != 0);
    octets[first_whole_tail.min(octets.len())..]
        .iter()
        .any(|byte| *byte != 0)
}

/// How a key reads back to a human, for the text of a refusal.
pub fn describe(key: &LpmKey) -> String {
    if key.prefix_len >= V4_MAPPED_PREFIX_BITS && key.addr[..12] == MAPPED_HEADER {
        let v4 = &key.addr[12..];
        format!(
            "{}.{}.{}.{}/{}",
            v4[0],
            v4[1],
            v4[2],
            v4[3],
            key.prefix_len - V4_MAPPED_PREFIX_BITS
        )
    } else {
        let addr = std::net::Ipv6Addr::from(key.addr);
        format!("{addr}/{}", key.prefix_len)
    }
}

const MAPPED_HEADER: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv4_prefix_lands_in_the_mapped_range() {
        let key = parse_prefix("10.90.1.0/24").unwrap();
        assert_eq!(key.prefix_len, 120);
        assert_eq!(&key.addr[12..], &[10, 90, 1, 0]);
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        assert_eq!(parse_prefix("10.90.1.7").unwrap().prefix_len, 128);
        assert_eq!(parse_prefix("2001:db8::1").unwrap().prefix_len, 128);
    }

    #[test]
    fn an_ipv6_prefix_keeps_its_length() {
        let key = parse_prefix("2001:db8::/32").unwrap();
        assert_eq!(key.prefix_len, 32);
    }

    /// Masking would accept the line and mean something else, which is worse than
    /// refusing it.
    #[test]
    fn host_bits_outside_the_prefix_are_refused() {
        assert!(parse_prefix("10.90.1.7/24").is_err());
        assert!(parse_prefix("2001:db8::1/32").is_err());
        assert!(parse_prefix("10.90.1.0/24").is_ok());
    }

    #[test]
    fn a_prefix_longer_than_its_family_is_refused() {
        assert!(parse_prefix("10.90.1.0/40").is_err());
        assert!(parse_prefix("2001:db8::/129").is_err());
    }

    #[test]
    fn a_key_reads_back_the_way_it_was_written() {
        assert_eq!(
            describe(&parse_prefix("10.90.1.0/24").unwrap()),
            "10.90.1.0/24"
        );
        assert_eq!(
            describe(&parse_prefix("2001:db8::/32").unwrap()),
            "2001:db8::/32"
        );
    }
}
