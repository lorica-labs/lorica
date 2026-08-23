//! The uRPF criterion, replayed against routing tables written out by hand.
//!
//! Synthetic tables and no kernel: the criterion takes the table as data precisely so
//! that the four geometries that matter can be stated here rather than built with `ip
//! route add` on a machine that has one uplink and one answer.

use carapace_dataplane::fib::{
    Discrimination, Family, Route,
    criterion::{RT_TABLE_LOCAL, RT_TABLE_MAIN},
    discriminates,
};

/// The ingress interface every case below judges, and a second one to route away through.
const ETH0: u32 = 2;
const ETH1: u32 = 3;

fn route(dst_len: u8, oif: u32) -> Route {
    Route {
        family: Family::V4,
        dst_len,
        table: RT_TABLE_MAIN,
        oif: Some(oif),
    }
}

fn assert_answer(table: &[Route], expected: Discrimination) {
    let answer = discriminates(table, ETH0);
    assert_eq!(answer, expected, "got: {answer}");
}

/// The tier-1 target of the product, and the reason the stage is conditional at all. The
/// reverse route of every address on earth is the default route, so the reverse route of
/// every address on earth is eth0, so the check passes every spoofed source.
#[test]
fn a_default_route_alone_decides_nothing() {
    assert_answer(
        &[route(0, ETH0), route(24, ETH0)],
        Discrimination::DefaultRouteOnIngress,
    );
}

/// More specific routes do not narrow what the default route lets through: they only
/// reject sources inside the prefixes they name. Here that is one /24 out of the whole
/// address space, and the attacker picks from the rest of it. A check that rejects a
/// measure-zero slice of the sources it is given is not a defence, so the answer is the
/// same as with the default route alone.
#[test]
fn a_default_route_with_more_specific_routes_still_decides_nothing() {
    assert_answer(
        &[
            route(0, ETH0),
            route(24, ETH0),
            route(16, ETH1),
            route(8, ETH1),
        ],
        Discrimination::DefaultRouteOnIngress,
    );
}

/// The case the stage exists for: every prefix is named, so a source outside all of them
/// has no reverse route at all and a source inside one that leaves through eth1 resolves
/// away from eth0. Both are drops, and there is no residue of address space the check
/// waves through. The local-table entries are there to show they are skipped — they are
/// our own addresses, not a path to anywhere.
#[test]
fn a_full_table_without_a_default_route_discriminates() {
    assert_answer(
        &[
            route(8, ETH0),
            route(12, ETH0),
            route(24, ETH0),
            route(16, ETH1),
            Route {
                table: RT_TABLE_LOCAL,
                ..route(32, ETH0)
            },
            Route {
                table: RT_TABLE_LOCAL,
                ..route(32, ETH1)
            },
        ],
        Discrimination::Discriminates,
    );
}

/// The one that has to be decided deliberately, because both readings are defensible and
/// only one is safe.
///
/// The reading that says "enable it": a spoofed source arriving on eth0 whose reverse
/// lookup lands on eth1 is dropped, so the check does discriminate. That is true, and it
/// is true for exactly as long as the kernel's nexthop hash keeps pointing that way — the
/// hash is over the addresses, so which of the two paths any given source resolves to is
/// not a property of the routing at all, and a metric change or a nexthop going down
/// reshuffles all of it.
///
/// The reading that decides it: the same hash applies to legitimate traffic. A packet
/// that genuinely arrived on eth0 from a source the hash resolves to eth1 is dropped, and
/// on a multihomed edge that is most of the traffic on whichever side the hash disfavours.
/// This is the multihoming false positive RFC 3704 names as the reason strict mode is not
/// recommended there, and the product cannot pay a drop of legitimate traffic to gain a
/// filter that holds only until the next reshuffle. So: off.
#[test]
fn a_multihomed_default_route_is_refused() {
    assert_answer(
        &[
            route(0, ETH0),
            route(0, ETH1),
            route(24, ETH0),
            route(24, ETH1),
        ],
        Discrimination::MultiplePaths,
    );
}

/// An interface nothing leaves through — an unaddressed one, or one whose subnet route
/// went away with its address. Strict uRPF there resolves every source to somewhere else
/// and drops all of it, which is discrimination in the sense that matters least.
#[test]
fn an_interface_no_route_leaves_through_is_refused() {
    assert_answer(
        &[route(0, ETH1), route(24, ETH1)],
        Discrimination::NoPathOnIngress,
    );
}

/// A table only an `ip rule` reaches — a VRF, a second uplink selected by mark. Which
/// table the reverse lookup consults is then a function of selectors that are evaluated
/// per packet, so the table alone cannot say whether the check discriminates. Refused
/// rather than guessed.
#[test]
fn routes_parked_behind_a_rule_are_refused() {
    assert_answer(
        &[
            route(8, ETH0),
            route(16, ETH1),
            Route {
                table: 100,
                ..route(0, ETH0)
            },
        ],
        Discrimination::PolicyRouting,
    );
}

/// One bit arms both families, so the family that cannot decide decides for both. Here
/// IPv6 has the table the stage was built for and IPv4 has a default route through the
/// ingress interface; arming would buy the v6 filter and spend the per-packet cost on
/// every v4 packet for nothing.
#[test]
fn a_family_that_cannot_decide_vetoes_the_one_that_can() {
    let mut table = vec![route(0, ETH0), route(24, ETH0)];
    table.extend([8, 16, 24].map(|dst_len| Route {
        family: Family::V6,
        ..route(dst_len, ETH0)
    }));
    assert_answer(&table, Discrimination::DefaultRouteOnIngress);
}

/// A default route that leads nowhere on purpose is not a default route the check has to
/// give up on: the reverse lookup of an arbitrary source fails, and a failed lookup is a
/// drop. It is the one case where a route with no output interface still decides, which is
/// why it is spelled differently from a route whose interface the kernel did not state.
#[test]
fn a_blackhole_default_route_still_discriminates() {
    assert_answer(
        &[
            route(24, ETH0),
            Route {
                oif: Some(0),
                ..route(0, ETH0)
            },
        ],
        Discrimination::Discriminates,
    );
}

/// Nexthop objects — what a modern host builds its router-advertised routes out of. The
/// interface is in the object and not in the route, so reading the route as "leads
/// nowhere" would count a live default route as one the reverse lookup fails on, and arm
/// the stage on a host where every packet then has to survive a check nobody validated.
#[test]
fn a_route_through_a_nexthop_object_is_refused() {
    assert_answer(
        &[
            route(24, ETH0),
            Route {
                oif: None,
                ..route(0, ETH0)
            },
        ],
        Discrimination::UnresolvedNexthop,
    );
}

/// A table with nothing in it is not a discriminating table, it is an unreadable one. The
/// answer has to be the one that leaves the stage off.
#[test]
fn an_empty_table_arms_nothing() {
    assert_answer(&[], Discrimination::NoPathOnIngress);
    assert!(!Discrimination::NoPathOnIngress.enforce());
}
