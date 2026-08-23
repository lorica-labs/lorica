//! The FIB moves, so the criterion is re-evaluated, and a flip is only reported once it
//! has held.
//!
//! A DHCP lease that moves the gateway, a failover, a gateway that speaks BGP: the table
//! the criterion reads is not a startup property. Most drifts are fail-open, but one is
//! not — a route convergence transiently loses the default route, the criterion then
//! reads "discriminates", and arming on that reading drops legitimate traffic whose
//! prefix is briefly absent. That is the RFC 3704 false positive, and the hold time
//! below exists for it.
//!
//! `URPF_ENFORCE` is a load-time global, so a reported flip is a program reload. That is
//! the production path anyway — detached by default, attached on detection — and the
//! hold time is what keeps a flapping route from becoming a flapping reload.
//!
//! No netlink crate. `RTM_GETROUTE` plus a group subscription is the same shape as the
//! `RTM_GETLINK` in `loader::hook_probe`, against the same header layout, and adding a
//! dependency tree to this crate to save one message parser is not a trade.
//!
//! **Why this one file is long.** It is one wire format and the socket that carries it:
//! `rtmsg`, the attributes nested in it, the nexthop array nested in those, and the
//! decision the whole lot exists to feed. Splitting the parser out would put half of
//! `rtmsg` in each file, with the constants in one and the offsets they name in the
//! other. A third of what follows is the test module, which builds the messages the
//! kernel would send so the parser can be held to the wire format without one, and what
//! is left is about two hundred lines of code.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use super::criterion::{self, Discrimination, Family, Route};

/// How long a changed criterion must hold before it is reported.
///
/// Thirty seconds is set by the longest transient the FIB is expected to show: a BGP
/// session re-establishing and reloading its table, which is tens of seconds on the
/// routers this sits behind. A DHCP renewal that replaces the default route and a VRRP
/// failover are both an order of magnitude shorter, so one window covers all three. The
/// price is half a minute without one of eight stages, against the alternative of arming
/// a dropping stage during a convergence.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(30);

/// A dump answer is read at construction and cannot hang the caller for longer than this.
const DUMP_TIMEOUT: Duration = Duration::from_secs(2);

/// Netlink multicast groups, as a bind-time bitmask. libc names the `RTNLGRP_*` ordinals
/// on some targets and not others; these two are the shifted form, and they are uapi.
const RTMGRP_IPV4_ROUTE: u32 = 1 << 6;
const RTMGRP_IPV6_ROUTE: u32 = 1 << 10;

const NLMSG_HDR_LEN: usize = 16;
/// `rtm_family`, `rtm_dst_len`, `rtm_src_len`, `rtm_tos`, `rtm_table`, `rtm_protocol`,
/// `rtm_scope`, `rtm_type`, then `rtm_flags`.
const RTMSG_LEN: usize = 12;
const RTM_DST_LEN_OFFSET: usize = 1;
const RTM_TABLE_OFFSET: usize = 4;
const RTM_TYPE_OFFSET: usize = 7;

/// `RTN_BLACKHOLE`, `RTN_UNREACHABLE`, `RTN_PROHIBIT`, `RTN_THROW`. These four have no
/// output interface because leading nowhere is the point, which is different from a route
/// whose interface the kernel simply did not state.
const RTN_LEADS_NOWHERE: std::ops::RangeInclusive<u8> = 6..=9;

/// `nlattr` carries flag bits in the high end of its type field.
const NLA_TYPE_MASK: u16 = 0x3fff;
const RTA_OIF: u16 = 4;
const RTA_MULTIPATH: u16 = 9;
/// The table id when it does not fit the byte in `rtmsg`, which is every table above 255
/// and, from iproute2, most of the ones below it too.
const RTA_TABLE: u16 = 15;

/// `rtnexthop`: `rtnh_len`, `rtnh_flags`, `rtnh_hops`, `rtnh_ifindex`.
const RTNEXTHOP_LEN: usize = 8;
const RTNH_IFINDEX_OFFSET: usize = 4;

/// A subscription to route changes, drained on the agent tick.
///
/// The table is maintained incrementally rather than re-dumped, and a stale table is
/// safe in a way worth stating: the stage does its own live FIB lookup, so a model that
/// wrongly says "discriminates" arms a check that then passes everything, and a model
/// that wrongly says otherwise leaves the stage off. Neither drops a packet. The one way
/// to be wrong dangerously is to *lose* a message, which on a netlink multicast socket
/// means `ENOBUFS` — refused below rather than absorbed.
pub struct RouteWatcher {
    socket: OwnedFd,
    /// Allocated once. The tick must not allocate, and a netlink message is never split
    /// across two datagrams, so a buffer that holds the largest one the kernel emits
    /// makes every read a whole number of messages.
    buffer: Vec<u8>,
    table: Vec<Route>,
    ingress: u32,
    hold: Hold,
    lost_messages: bool,
}

impl RouteWatcher {
    /// Subscribes, dumps the current table, and answers the criterion for it.
    ///
    /// The dump happens here and not on the tick: it is the one blocking read, and it is
    /// bounded by a receive timeout so a kernel that says nothing cannot hang a startup.
    pub fn new(ingress: u32, window: Duration) -> io::Result<Self> {
        let socket = subscribe()?;
        let mut buffer = vec![0u8; 32 * 1024];
        let mut table = Vec::new();
        dump(&socket, &mut buffer, &mut table)?;
        // Room for the routes a convergence adds before it settles, so the common case
        // reaches steady state without a reallocation on a tick.
        table.reserve(table.len().max(32));
        let hold = Hold {
            window,
            reported: criterion::discriminates(&table, ingress),
            pending: None,
        };
        Ok(Self {
            socket,
            buffer,
            table,
            ingress,
            hold,
            lost_messages: false,
        })
    }

    /// What the criterion last said, which is what a loaded program reflects.
    pub fn decision(&self) -> Discrimination {
        self.hold.reported
    }

    /// Drains every pending route change and returns the new decision when one has held
    /// for the hold time.
    ///
    /// Cannot block: every read passes `MSG_DONTWAIT` and the drain stops at `EAGAIN`.
    /// Allocates nothing in steady state — the read buffer is owned and the table only
    /// grows when the FIB gains a route, which is an event and not a tick.
    pub fn poll(&mut self) -> io::Result<Option<Discrimination>> {
        if self.lost_messages {
            return Err(io::Error::other(
                "the route subscription overflowed and its table is no longer the kernel's; \
                 rebuild the watcher",
            ));
        }
        self.drain()?;
        let current = criterion::discriminates(&self.table, self.ingress);
        Ok(self.hold.settle(current, Instant::now()))
    }

    fn drain(&mut self) -> io::Result<()> {
        loop {
            // SAFETY: writes at most buffer.len() bytes into a buffer we own.
            let read = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if read > 0 {
                apply(&mut self.table, &self.buffer[..read as usize]);
                continue;
            }
            if read == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                // Nothing left in the socket, which is where every tick ends.
                io::ErrorKind::WouldBlock => return Ok(()),
                _ if err.raw_os_error() == Some(libc::ENOBUFS) => {
                    self.lost_messages = true;
                    return Err(err);
                }
                _ => return Err(err),
            }
        }
    }
}

/// The hysteresis, and nothing else, so that the rule can be read without a socket.
struct Hold {
    window: Duration,
    reported: Discrimination,
    pending: Option<(Discrimination, Instant)>,
}

impl Hold {
    /// Returns the new decision once it has held for the window, and `None` while it has
    /// not.
    ///
    /// Only arming waits. A decision that stops discriminating is either useless or
    /// actively dropping, and sitting on either for half a minute buys nothing; the flap
    /// the window protects against is the one that costs a program reload, and that is
    /// the arming direction. Waiting on the way out would also mean holding a stage that
    /// has just become the RFC 3704 false positive, which is the opposite of the point.
    fn settle(&mut self, current: Discrimination, now: Instant) -> Option<Discrimination> {
        if current == self.reported {
            self.pending = None;
            return None;
        }
        let held_long_enough = match self.pending {
            Some((pending, since)) if pending == current => {
                now.saturating_duration_since(since) >= self.window
            }
            _ => {
                self.pending = Some((current, now));
                false
            }
        };
        if !held_long_enough && current.enforce() {
            return None;
        }
        self.pending = None;
        self.reported = current;
        Some(current)
    }
}

fn subscribe() -> io::Result<OwnedFd> {
    // SAFETY: a plain socket creation; the fd is taken over by OwnedFd right after.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a fresh, valid, owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    // SAFETY: a correctly sized sockaddr_nl for an AF_NETLINK socket.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let timeout = libc::timeval {
        tv_sec: DUMP_TIMEOUT.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: a correctly sized timeval for SO_RCVTIMEO.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// `RTM_GETROUTE` over both families, read until the kernel says it is done.
fn dump(socket: &OwnedFd, buffer: &mut [u8], table: &mut Vec<Route>) -> io::Result<()> {
    const REQUEST_LEN: usize = NLMSG_HDR_LEN + RTMSG_LEN;
    let mut request = [0u8; REQUEST_LEN];
    request[0..4].copy_from_slice(&(REQUEST_LEN as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&libc::RTM_GETROUTE.to_ne_bytes());
    request[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[NLMSG_HDR_LEN] = libc::AF_UNSPEC as u8;

    // SAFETY: the buffer is initialised and its length is passed unchanged.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    loop {
        // SAFETY: writes at most buffer.len() bytes into a buffer the caller owns.
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        match apply(table, &buffer[..read as usize]) {
            Progress::More => {}
            Progress::Done => return Ok(()),
            // A refused dump would otherwise read as a machine with no routes, which the
            // criterion answers with a confident "nothing leaves through this interface".
            Progress::Refused(code) => return Err(io::Error::from_raw_os_error(-code)),
        }
    }
}

enum Progress {
    More,
    Done,
    Refused(i32),
}

/// Applies one datagram's worth of messages.
///
/// Stops at the first malformed header rather than guessing past it, for the same reason
/// the link parser does: a half-walked message reads as an absent route, and an absent
/// default route is the one wrong answer that arms the stage.
fn apply(table: &mut Vec<Route>, mut messages: &[u8]) -> Progress {
    while messages.len() >= NLMSG_HDR_LEN {
        let length = u32::from_ne_bytes(messages[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(messages[4..6].try_into().unwrap());
        if length < NLMSG_HDR_LEN || length > messages.len() {
            return Progress::Done;
        }
        if kind == libc::NLMSG_DONE as u16 {
            return Progress::Done;
        }
        if kind == libc::NLMSG_ERROR as u16 && length >= NLMSG_HDR_LEN + 4 {
            let at = NLMSG_HDR_LEN;
            let code = i32::from_ne_bytes(messages[at..at + 4].try_into().unwrap());
            // Zero is an acknowledgement, which a dump ends with when it carries no error.
            return if code == 0 {
                Progress::Done
            } else {
                Progress::Refused(code)
            };
        }
        let adding = kind == libc::RTM_NEWROUTE;
        if (adding || kind == libc::RTM_DELROUTE) && length >= NLMSG_HDR_LEN + RTMSG_LEN {
            record(table, &messages[NLMSG_HDR_LEN..length], adding);
        }
        messages = &messages[length.next_multiple_of(4).min(messages.len())..];
    }
    Progress::More
}

fn record(table: &mut Vec<Route>, body: &[u8], adding: bool) {
    let Some(family) = (match body[0] as i32 {
        libc::AF_INET => Some(Family::V4),
        libc::AF_INET6 => Some(Family::V6),
        // MPLS, bridge, and the rest. Neither family the stage looks at.
        _ => None,
    }) else {
        return;
    };

    let mut route = Route {
        family,
        dst_len: body[RTM_DST_LEN_OFFSET],
        table: u32::from(body[RTM_TABLE_OFFSET]),
        // Not zero: until an attribute says otherwise the interface is unstated, and the
        // criterion is owed the difference between that and a route that leads nowhere.
        oif: RTN_LEADS_NOWHERE
            .contains(&body[RTM_TYPE_OFFSET])
            .then_some(0),
    };
    let mut multipath = None;
    for (kind, payload) in attributes(&body[RTMSG_LEN..]) {
        match (kind, payload.len()) {
            (RTA_OIF, 4..) => {
                route.oif = Some(u32::from_ne_bytes(payload[0..4].try_into().unwrap()));
            }
            (RTA_TABLE, 4..) => {
                route.table = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
            }
            (RTA_MULTIPATH, _) => multipath = Some(payload),
            _ => {}
        }
    }

    match multipath {
        // An equal-cost route carries no `RTA_OIF`; its interfaces are one per nexthop.
        // Expanding them here is what lets the criterion see a multihomed default as the
        // several paths it is rather than as one route nobody can place.
        Some(nexthops) => {
            for oif in interfaces_of(nexthops) {
                store(
                    table,
                    Route {
                        oif: Some(oif),
                        ..route
                    },
                    adding,
                );
            }
        }
        None => store(table, route, adding),
    }
}

/// Identity is the four fields the criterion reads, so a duplicate is not stored twice.
///
/// That is what makes `ip route replace` — which is what a DHCP client does to the
/// default route — land on the entry it replaces instead of beside it. The cost is that
/// two defaults through one interface differing only in metric are one entry here, and
/// the model then loses both on the first deletion. It reads as a table with no default,
/// which arms a stage that the live lookup then passes everything through.
fn store(table: &mut Vec<Route>, route: Route, adding: bool) {
    match (adding, table.iter().position(|known| *known == route)) {
        (true, None) => table.push(route),
        (false, Some(at)) => {
            table.swap_remove(at);
        }
        _ => {}
    }
}

fn interfaces_of(mut nexthops: &[u8]) -> impl Iterator<Item = u32> {
    std::iter::from_fn(move || {
        if nexthops.len() < RTNEXTHOP_LEN {
            return None;
        }
        let length = u16::from_ne_bytes(nexthops[0..2].try_into().unwrap()) as usize;
        if length < RTNEXTHOP_LEN || length > nexthops.len() {
            return None;
        }
        let at = RTNH_IFINDEX_OFFSET;
        let oif = u32::from_ne_bytes(nexthops[at..at + 4].try_into().unwrap());
        nexthops = &nexthops[length.next_multiple_of(4).min(nexthops.len())..];
        Some(oif)
    })
}

/// Walks a run of `nlattr`, yielding the masked type and the payload.
fn attributes(mut buffer: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    const HEADER: usize = 4;
    std::iter::from_fn(move || {
        if buffer.len() < HEADER {
            return None;
        }
        let length = u16::from_ne_bytes(buffer[0..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buffer[2..4].try_into().unwrap()) & NLA_TYPE_MASK;
        if length < HEADER || length > buffer.len() {
            return None;
        }
        let payload = &buffer[HEADER..length];
        buffer = &buffer[length.next_multiple_of(4).min(buffer.len())..];
        Some((kind, payload))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A convergence that transiently loses the default route reads as "discriminates",
    /// and arming on that reading is the RFC 3704 false positive. So the window has to
    /// pass first, and the report has to arrive once it has.
    #[test]
    fn arming_waits_out_the_window() {
        let start = Instant::now();
        let mut hold = Hold {
            window: DEFAULT_HOLD,
            reported: Discrimination::DefaultRouteOnIngress,
            pending: None,
        };
        assert_eq!(hold.settle(Discrimination::Discriminates, start), None);
        assert_eq!(
            hold.settle(Discrimination::Discriminates, start + DEFAULT_HOLD / 2),
            None
        );
        assert_eq!(
            hold.settle(Discrimination::Discriminates, start + DEFAULT_HOLD),
            Some(Discrimination::Discriminates)
        );
        assert_eq!(hold.reported, Discrimination::Discriminates);
    }

    /// The route that came back inside the window is the flap the window exists for: not
    /// one reload, not a delayed reload, none at all.
    #[test]
    fn a_flap_inside_the_window_reports_nothing() {
        let start = Instant::now();
        let mut hold = Hold {
            window: DEFAULT_HOLD,
            reported: Discrimination::DefaultRouteOnIngress,
            pending: None,
        };
        assert_eq!(hold.settle(Discrimination::Discriminates, start), None);
        assert_eq!(
            hold.settle(
                Discrimination::DefaultRouteOnIngress,
                start + DEFAULT_HOLD / 2
            ),
            None
        );
        assert_eq!(
            hold.settle(Discrimination::Discriminates, start + DEFAULT_HOLD),
            None,
            "the window has to restart from the second change, not from the first"
        );
    }

    /// A stage that has stopped discriminating is at best useless and at worst dropping
    /// legitimate traffic, so it comes off on the same tick.
    #[test]
    fn disarming_does_not_wait() {
        let start = Instant::now();
        let mut hold = Hold {
            window: DEFAULT_HOLD,
            reported: Discrimination::Discriminates,
            pending: None,
        };
        assert_eq!(
            hold.settle(Discrimination::MultiplePaths, start),
            Some(Discrimination::MultiplePaths)
        );
        assert_eq!(hold.settle(Discrimination::MultiplePaths, start), None);
    }

    /// Builds one `RTM_NEWROUTE`/`RTM_DELROUTE` the way the kernel lays it out, so the
    /// parser can be held to the wire format without a kernel to produce it.
    fn message(kind: u16, dst_len: u8, attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = libc::AF_INET as u8;
        body[RTM_DST_LEN_OFFSET] = dst_len;
        body[RTM_TABLE_OFFSET] = criterion::RT_TABLE_MAIN as u8;
        for (attribute, payload) in attributes {
            body.extend(((payload.len() + 4) as u16).to_ne_bytes());
            body.extend(attribute.to_ne_bytes());
            body.extend(payload);
            body.resize(body.len().next_multiple_of(4), 0);
        }
        let mut message = Vec::with_capacity(NLMSG_HDR_LEN + body.len());
        message.extend(((NLMSG_HDR_LEN + body.len()) as u32).to_ne_bytes());
        message.extend(kind.to_ne_bytes());
        message.resize(NLMSG_HDR_LEN, 0);
        message.extend(body);
        message
    }

    fn nexthop(oif: u32) -> Vec<u8> {
        let mut entry = (RTNEXTHOP_LEN as u16).to_ne_bytes().to_vec();
        entry.resize(RTNH_IFINDEX_OFFSET, 0);
        entry.extend(oif.to_ne_bytes());
        entry
    }

    /// A route arrives, the criterion answers for it, the route goes away again. The
    /// deletion is the half the dump never exercises, and a deletion that does not land
    /// leaves a default route in the model that the kernel no longer has.
    #[test]
    fn a_deleted_route_leaves_the_table() {
        let oif = (2u32).to_ne_bytes().to_vec();
        let mut table = Vec::new();
        apply(
            &mut table,
            &message(libc::RTM_NEWROUTE, 0, &[(RTA_OIF, oif.clone())]),
        );
        assert_eq!(
            criterion::discriminates(&table, 2),
            Discrimination::DefaultRouteOnIngress
        );
        apply(
            &mut table,
            &message(libc::RTM_DELROUTE, 0, &[(RTA_OIF, oif)]),
        );
        assert!(table.is_empty(), "{table:?}");
    }

    /// An equal-cost default route is one message with its interfaces in `RTA_MULTIPATH`
    /// and no `RTA_OIF` at all. Expanding it is what turns the multihomed table into the
    /// several paths the criterion refuses to arm on; not expanding it would read as one
    /// route nobody can place, which is a different answer for the same wire bytes.
    #[test]
    fn an_equal_cost_default_route_expands_to_its_nexthops() {
        let mut multipath = nexthop(2);
        multipath.extend(nexthop(3));
        let mut table = Vec::new();
        apply(
            &mut table,
            &message(libc::RTM_NEWROUTE, 0, &[(RTA_MULTIPATH, multipath.clone())]),
        );
        assert_eq!(table.len(), 2, "{table:?}");
        assert_eq!(
            criterion::discriminates(&table, 2),
            Discrimination::MultiplePaths
        );
        apply(
            &mut table,
            &message(libc::RTM_DELROUTE, 0, &[(RTA_MULTIPATH, multipath)]),
        );
        assert!(table.is_empty(), "{table:?}");
    }

    /// The dump, the parser and the criterion against the kernel's own table.
    ///
    /// The assertions are about the shape of what came back rather than about the verdict:
    /// the verdict depends on the machine — this one has a VPN interface with its own
    /// table, so it answers `PolicyRouting` — while a `rtm_dst_len` read at the wrong
    /// offset shows up as a prefix length no address family has, and an `RTA_OIF` read at
    /// the wrong one as a default route that leaves through nothing. What *is* asserted
    /// about the verdict is that a machine reached through its default route does not arm
    /// the stage, which is the whole premise of the criterion.
    #[test]
    #[cfg(feature = "kernel-tests")]
    fn the_kernels_own_table_parses_and_answers() {
        // Interface index zero belongs to no interface, so this first watcher is only
        // asked for the table it dumped.
        let dumped = RouteWatcher::new(0, DEFAULT_HOLD).expect("the route dump failed");
        assert!(
            !dumped.table.is_empty(),
            "the kernel dumped no route at all"
        );
        for route in &dumped.table {
            let ceiling = match route.family {
                Family::V4 => 32,
                Family::V6 => 128,
            };
            assert!(route.dst_len <= ceiling, "{route:?} has no prefix length");
        }

        let uplink = dumped
            .table
            .iter()
            .find(|route| route.dst_len == 0 && route.family == Family::V4)
            .expect("no IPv4 default route on this machine")
            .oif
            .expect("the IPv4 default route leaves through no interface");
        assert_ne!(uplink, 0, "the IPv4 default route names interface zero");

        let mut watcher = RouteWatcher::new(uplink, DEFAULT_HOLD).expect("the route dump failed");
        assert!(
            !watcher.decision().enforce(),
            "the interface carrying the default route arms the stage: {}",
            watcher.decision()
        );

        // Nothing has changed and nothing is queued, so the drain has to come straight
        // back. A blocking read here would show up as a tick that never returns.
        let before = Instant::now();
        assert_eq!(watcher.poll().expect("the drain failed"), None);
        assert!(before.elapsed() < Duration::from_millis(100));
    }
}
