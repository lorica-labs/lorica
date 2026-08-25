//! Scopes: what a rule applies to, resolved from a name or read literally.
//!
//! A scope is `proto:ports`, where ports is a single port, an inclusive range, or
//! `any`. A service catalogue is names for those strings and nothing else, so a rule
//! can say `game` where it would otherwise repeat `udp:30120`.

use std::collections::BTreeMap;

use lorica_common::Scope;

use crate::compile::CompileError;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// Resolves one entry of a rule scope list.
pub fn resolve(spec: &str, services: &BTreeMap<String, String>) -> Result<Scope, CompileError> {
    // A name is looked up once and not recursively: a catalogue that can refer to
    // itself is a catalogue that can loop.
    let literal = services.get(spec).map_or(spec, String::as_str);
    parse(literal).map_err(|kind| CompileError::BadScope {
        spec: spec.to_owned(),
        resolved: literal.to_owned(),
        kind,
    })
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BadScope {
    NoColon,
    UnknownProtocol,
    BadPorts,
    ReversedRange,
    PortsOnProtocolWithout,
}

fn parse(literal: &str) -> Result<Scope, BadScope> {
    let (proto_name, ports) = literal.split_once(':').ok_or(BadScope::NoColon)?;

    let proto = match proto_name {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        "icmp" => IPPROTO_ICMP,
        "icmpv6" => IPPROTO_ICMPV6,
        _ => return Err(BadScope::UnknownProtocol),
    };

    // ICMP has no ports at all, so a port range on it would be a scope that matches
    // nothing, silently.
    let carries_ports = matches!(proto, IPPROTO_TCP | IPPROTO_UDP);
    if !carries_ports && ports != "any" {
        return Err(BadScope::PortsOnProtocolWithout);
    }

    let (lo, hi) = match ports {
        "any" => (0, u16::MAX),
        range => match range.split_once('-') {
            Some((lo, hi)) => (
                lo.parse().map_err(|_| BadScope::BadPorts)?,
                hi.parse().map_err(|_| BadScope::BadPorts)?,
            ),
            None => {
                let port = range.parse().map_err(|_| BadScope::BadPorts)?;
                (port, port)
            }
        },
    };
    if lo > hi {
        return Err(BadScope::ReversedRange);
    }

    Ok(Scope::new(proto, lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_services() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn a_single_port_becomes_a_range_of_one() {
        let scope = resolve("udp:30120", &no_services()).unwrap();
        assert_eq!(scope, Scope::new(IPPROTO_UDP, 30_120, 30_120));
    }

    #[test]
    fn any_covers_every_port() {
        let scope = resolve("tcp:any", &no_services()).unwrap();
        assert_eq!(scope, Scope::new(IPPROTO_TCP, 0, u16::MAX));
    }

    #[test]
    fn a_service_name_resolves_to_its_literal() {
        let mut services = no_services();
        services.insert("game".to_owned(), "udp:30120-30130".to_owned());
        let scope = resolve("game", &services).unwrap();
        assert_eq!(scope, Scope::new(IPPROTO_UDP, 30_120, 30_130));
    }

    #[test]
    fn a_reversed_range_is_refused() {
        assert!(resolve("tcp:500-100", &no_services()).is_err());
    }

    /// A port range on ICMP would be a scope that matches nothing at all, and it would
    /// do so silently.
    #[test]
    fn ports_on_icmp_are_refused() {
        assert!(resolve("icmp:0-255", &no_services()).is_err());
        assert!(resolve("icmp:any", &no_services()).is_ok());
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        assert!(resolve("sctp:80", &no_services()).is_err());
        assert!(resolve("udp", &no_services()).is_err());
    }
}
