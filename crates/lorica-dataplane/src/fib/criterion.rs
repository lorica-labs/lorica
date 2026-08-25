//! Does strict reverse-path filtering decide anything on this interface?
//!
//! On the tier-1 target of this product the answer is no, and the reason is geometry
//! rather than implementation: with `0.0.0.0/0 via eth0` the reverse route of *any*
//! address is the default route, hence the ingress interface, so the check passes for
//! every spoofed source. `BPF_FIB_LOOKUP_SRC` makes the lookup feasible in XDP; it does
//! not move the default route.
//!
//! So the criterion is binary and deterministic — a predicate over a routing table, not
//! a sample of a few sources. Sampling would answer differently depending on which
//! addresses were drawn, and the addresses an attacker draws are the ones nobody sampled.
//!
//! The function is pure and takes the table as data. Reading the kernel lives next door
//! in `netlink`, which is what leaves this decision testable on a machine that has no
//! routes worth speaking of.

use std::fmt;

/// The main table, where a leaf host's routes live.
pub const RT_TABLE_MAIN: u32 = 254;
/// Consulted after `main`, and empty on every machine that has not been told otherwise.
pub const RT_TABLE_DEFAULT: u32 = 253;
/// Our own addresses and the broadcast entries the kernel keeps for them. Not a path to
/// anywhere, so the criterion skips it.
pub const RT_TABLE_LOCAL: u32 = 255;

/// The two FIBs. They are separate tables with separate default routes, and there is one
/// `URPF_ENFORCE` bit for both, which is what makes [`discriminates`] combine them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    V4,
    V6,
}

/// One route, reduced to the fields this decision reads plus the one that tells two
/// routes apart.
///
/// The criterion itself reads four: which table a route sits in, whether it is the least
/// specific one there is, and where it leaves. `dst` is not one of them and no branch of
/// `discriminates` looks at it. It is carried because the incremental table of the watcher
/// uses equality on this type as set identity, and without the prefix two different
/// routes of the same length on the same interface are one entry — measured on
/// `10.90.78.0/24` and `10.91.78.0/24`, where deleting either emptied the entry that stood
/// for both.
///
/// Not the gateway, though: two routes to the same prefix through the same interface by
/// different gateways answer the same question and are the same route here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub family: Family,
    /// Destination prefix length. Zero is the default route.
    pub dst_len: u8,
    /// The destination prefix, zero-padded, and all zeroes when the message carried none —
    /// which is what a default route looks like, consistently with `dst_len == 0`. Held
    /// for identity only.
    pub dst: [u8; 16],
    pub table: u32,
    /// Where the route leaves. `Some(0)` is a route that deliberately leads nowhere — a
    /// blackhole, an unreachable — which the reverse lookup fails on, and failing is
    /// exactly what makes the check discriminate. `None` is a route whose interface the
    /// kernel did not state, which today means a nexthop object: the route leaves
    /// somewhere and finding out where needs a dump this does not do.
    pub oif: Option<u32>,
}

/// Whether the stage is worth arming on an interface, and if not, why not.
///
/// Only the first variant arms it. The others are not degrees of the same thing: one says
/// the check would decide nothing, the rest say it would decide wrongly and drop traffic
/// that belongs on the wire. An operator who sees the stage stay off is owed which it was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Discrimination {
    /// No route resolves an arbitrary source back to the ingress interface, so a spoofed
    /// source either resolves elsewhere or resolves nowhere. Both are a drop.
    Discriminates,
    /// A default route leaves through the ingress interface itself. Every address on
    /// earth resolves back to it, so the check passes everything.
    DefaultRouteOnIngress,
    /// Several paths carry the default route. The kernel picks one by nexthop hash and
    /// by metric, so a legitimate packet can resolve to the path it did not arrive on —
    /// the multihoming false positive of RFC 3704, and the one this product cannot pay.
    MultiplePaths,
    /// Nothing at all leaves through the ingress interface, so the check would drop
    /// every packet arriving there.
    NoPathOnIngress,
    /// Routes are parked in a table that only an `ip rule` reaches. Which table the
    /// reverse lookup consults then depends on selectors — fwmark, input interface,
    /// source — that this decision cannot evaluate ahead of the packet.
    PolicyRouting,
    /// A route leaves through a nexthop object, so the table does not say which interface
    /// it leaves through. Reading it as "leads nowhere" would count a live default route
    /// as a route the reverse lookup fails on, which is the one mistake that arms the
    /// stage on a host where it drops. The ceiling is deliberate: resolving them means an
    /// `RTM_GETNEXTHOP` dump and a second subscription, and a host that hands out
    /// nexthop objects for its default route has a default route, which is the answer
    /// anyway.
    UnresolvedNexthop,
}

impl Discrimination {
    pub fn enforce(self) -> bool {
        self == Self::Discriminates
    }
}

impl fmt::Display for Discrimination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Discriminates => "strict reverse-path filtering discriminates here",
            Self::DefaultRouteOnIngress => {
                "a default route leaves through the ingress interface, so the check passes \
                 every source"
            }
            Self::MultiplePaths => {
                "several paths carry the default route, so the check would drop legitimate \
                 traffic that arrived on the other one"
            }
            Self::NoPathOnIngress => {
                "no route leaves through the ingress interface, so the check would drop \
                 everything arriving there"
            }
            Self::PolicyRouting => {
                "routes sit in a table reached by rule, so which table the reverse lookup \
                 consults is not decidable from the table alone"
            }
            Self::UnresolvedNexthop => {
                "a route leaves through a nexthop object, so the table does not say which \
                 interface it leaves through"
            }
        })
    }
}

/// The criterion: what strict reverse-path filtering would do to traffic arriving on
/// `ingress`, given `table`.
///
/// Each family is judged on its own and the first one that cannot decide vetoes the
/// answer, because `URPF_ENFORCE` is one bit for both. A family with no route outside
/// the local table is not configured and abstains; when both abstain the answer is
/// [`Discrimination::NoPathOnIngress`], which is the honest reading of an empty table.
pub fn discriminates(table: &[Route], ingress: u32) -> Discrimination {
    let mut decided = None;
    for family in [Family::V4, Family::V6] {
        match per_family(table, ingress, family) {
            Some(answer) if !answer.enforce() => return answer,
            Some(answer) => decided = Some(answer),
            None => {}
        }
    }
    decided.unwrap_or(Discrimination::NoPathOnIngress)
}

fn per_family(table: &[Route], ingress: u32, family: Family) -> Option<Discrimination> {
    let mut configured = false;
    let mut policy = false;
    let mut unresolved = false;
    let mut on_ingress = false;
    let mut default_oif = None;
    let mut several_defaults = false;

    for route in table
        .iter()
        .filter(|route| route.family == family && route.table != RT_TABLE_LOCAL)
    {
        configured = true;
        if route.table != RT_TABLE_MAIN && route.table != RT_TABLE_DEFAULT {
            policy = true;
        }
        match route.oif {
            None => unresolved = true,
            Some(oif) if oif == ingress => on_ingress = true,
            Some(_) => {}
        }
        if let (0, Some(oif)) = (route.dst_len, route.oif) {
            match default_oif {
                None => default_oif = Some(oif),
                Some(known) if known != oif => several_defaults = true,
                Some(_) => {}
            }
        }
    }

    if !configured {
        return None;
    }
    // Ordered by what would go wrong, not by likelihood. The "would decide wrongly"
    // answers come first so that a table which is both useless and dangerous is reported
    // as dangerous: an operator who reads "passes every source" goes looking for a way
    // to tighten the routing, and here that would arm a stage that drops.
    Some(if policy {
        Discrimination::PolicyRouting
    } else if unresolved {
        Discrimination::UnresolvedNexthop
    } else if !on_ingress {
        Discrimination::NoPathOnIngress
    } else if several_defaults {
        Discrimination::MultiplePaths
    } else if default_oif == Some(ingress) {
        Discrimination::DefaultRouteOnIngress
    } else {
        Discrimination::Discriminates
    })
}
