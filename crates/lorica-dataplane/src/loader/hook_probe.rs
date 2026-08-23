//! Who holds the XDP hook of an interface, and in which mode.
//!
//! The kernel only tells this over netlink. `BPF_PROG_QUERY` does not cover XDP, and
//! enumerating bpf links misses every program attached the legacy way — which is how
//! most of the programs one collides with in the field were attached. So the query is
//! a hand-rolled `RTM_GETLINK`, which is also where the attach mode comes from: the
//! mode rendered by `ip -d link show` is the only thing that attests a native attach,
//! since on this kernel an attach disables no virtio offload at all and a diff of
//! `ethtool -k` proves nothing either way.

use std::{
    ffi::CString,
    fmt, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use aya::programs::loaded_programs;

/// Attributes nested inside `IFLA_XDP`. libc exposes the outer one only, and these are
/// stable uapi numbers.
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_XDP_PROG_ID: u16 = 4;

/// `nlattr` carries flag bits in the high end of its type field.
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_HDR_LEN: usize = 16;
/// `ifi_family`, a pad byte, `ifi_type`, `ifi_index`, `ifi_flags`, `ifi_change`.
const IFINFOMSG_LEN: usize = 16;
/// Offset of `ifi_index` inside `ifinfomsg`.
const IFI_INDEX_OFFSET: usize = 4;

/// How a program sits on the hook. The distinction is the whole point: generic mode
/// runs after the stack has built an skb, so a drop there costs most of what it was
/// supposed to save, and a throughput figure taken in that mode says nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachMode {
    None,
    Native,
    Generic,
    Hardware,
    /// More than one mode occupied at once, which the kernel reports without saying
    /// which is which.
    Multiple,
    Unknown(u8),
}

impl AttachMode {
    fn from_kernel(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Native,
            2 => Self::Generic,
            3 => Self::Hardware,
            4 => Self::Multiple,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for AttachMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Native => f.write_str("native"),
            Self::Generic => f.write_str("generic"),
            Self::Hardware => f.write_str("hardware offload"),
            Self::Multiple => f.write_str("several modes at once"),
            Self::Unknown(raw) => write!(f, "mode {raw} this build does not know"),
        }
    }
}

/// What the hook of an interface currently holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HookState {
    pub prog_id: Option<u32>,
    pub mode: AttachMode,
}

/// The program in the way, named the three ways an operator can act on.
///
/// The id lets them run `bpftool prog show id N`, the name is what they will recognise,
/// and the tag survives a reload with a different id — it is the only one of the three
/// that identifies the *code* rather than the instance.
#[derive(Clone, Debug)]
pub struct Occupant {
    pub prog_id: u32,
    pub name: String,
    pub tag: u64,
    pub mode: AttachMode,
}

impl fmt::Display for Occupant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "program id {} named {:?}, tag {:016x}, attached in {} mode",
            self.prog_id, self.name, self.tag, self.mode
        )
    }
}

pub fn probe(iface: &str) -> io::Result<HookState> {
    let reply = query_link(if_index(iface)?)?;
    parse(&reply)
}

/// The hook state, resolved to a named program when one is there.
///
/// Returns `Ok(None)` for a free hook. A hook that is held by a program the kernel will
/// not name — it can be gone between the two queries — still yields an `Occupant`, with
/// the fields the netlink answer did carry, because "something is there and I cannot
/// tell you what" is a more useful thing to report than nothing.
pub fn occupant(iface: &str) -> io::Result<Option<Occupant>> {
    let state = probe(iface)?;
    let Some(prog_id) = state.prog_id else {
        return Ok(None);
    };
    let named = loaded_programs()
        .flatten()
        .find(|info| info.id() == prog_id);
    Ok(Some(Occupant {
        prog_id,
        name: named
            .as_ref()
            .and_then(|info| info.name_as_str())
            .unwrap_or("<unnamed>")
            .to_owned(),
        tag: named.as_ref().map_or(0, |info| info.tag()),
        mode: state.mode,
    }))
}

fn if_index(iface: &str) -> io::Result<u32> {
    let name = CString::new(iface).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name has a nul byte")
    })?;
    // SAFETY: the pointer is a valid nul-terminated string for the duration of the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface named {iface}"),
        ));
    }
    Ok(index)
}

fn query_link(index: u32) -> io::Result<Vec<u8>> {
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

    const REQUEST_LEN: usize = NLMSG_HDR_LEN + IFINFOMSG_LEN;
    let mut request = [0u8; REQUEST_LEN];
    request[0..4].copy_from_slice(&(REQUEST_LEN as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    request[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[NLMSG_HDR_LEN] = libc::AF_UNSPEC as u8;
    let index_at = NLMSG_HDR_LEN + IFI_INDEX_OFFSET;
    request[index_at..index_at + 4].copy_from_slice(&(index as i32).to_ne_bytes());

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

    // One link, and the answer to a targeted RTM_GETLINK is a single message. Sized
    // well above what an interface with every attribute set produces; a truncated
    // answer would silently look like an absent attribute, so a short read is refused
    // below rather than parsed.
    let mut buffer = vec![0u8; 32 * 1024];
    // SAFETY: writes at most buffer.len() bytes into a buffer we own.
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(received as usize);
    Ok(buffer)
}

fn parse(reply: &[u8]) -> io::Result<HookState> {
    if reply.len() < NLMSG_HDR_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the netlink answer is shorter than its own header",
        ));
    }
    let length = u32::from_ne_bytes(reply[0..4].try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes(reply[4..6].try_into().unwrap());
    if length > reply.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the netlink answer claims {length} bytes and carries {}",
                reply.len()
            ),
        ));
    }

    if kind == libc::NLMSG_ERROR as u16 {
        // The error code sits right after the header, negated.
        let code = i32::from_ne_bytes(reply[NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4].try_into().unwrap());
        return Err(io::Error::from_raw_os_error(-code));
    }
    if kind != libc::RTM_NEWLINK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected RTM_NEWLINK from the kernel, got message type {kind}"),
        ));
    }

    let body = &reply[NLMSG_HDR_LEN + IFINFOMSG_LEN..length];
    let mut state = HookState {
        prog_id: None,
        mode: AttachMode::None,
    };
    for (kind, payload) in attributes(body) {
        if kind != libc::IFLA_XDP {
            continue;
        }
        for (kind, payload) in attributes(payload) {
            match (kind, payload.len()) {
                (IFLA_XDP_ATTACHED, 1..) => state.mode = AttachMode::from_kernel(payload[0]),
                (IFLA_XDP_PROG_ID, 4..) => {
                    let id = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
                    // The kernel reports a zero id for a hook it considers free.
                    state.prog_id = (id != 0).then_some(id);
                }
                _ => {}
            }
        }
    }
    Ok(state)
}

/// Walks a run of `nlattr`, yielding the type with its flag bits masked off and the
/// payload. Stops at the first malformed header rather than guessing past it: a
/// half-parsed attribute list would report an absent attribute, which reads as "no XDP
/// program here" and is the one wrong answer that gets a program replaced.
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
        let stride = length.next_multiple_of(4).min(buffer.len());
        buffer = &buffer[stride..];
        Some((kind, payload))
    })
}
