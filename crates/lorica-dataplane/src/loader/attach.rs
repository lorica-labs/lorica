//! Attach in native mode, or refuse and say why.
//!
//! Two refusals, and neither is a fallback. A busy hook is refused because XDP takes
//! one program per interface: replacing the occupant would stop whatever it was doing
//! without telling anyone, and being replaced in turn would stop Lorica the same way.
//! A driver without native support is refused because generic XDP runs after the stack
//! has already built an skb, so it costs most of what the drop was meant to save and
//! yields a throughput that varies too much to measure against.

use std::time::{Duration, Instant};

use aya::programs::{ProgramError, Xdp, XdpMode, xdp::XdpLinkId};
use thiserror::Error;

use super::hook_probe;

#[derive(Debug, Error)]
pub enum AttachError {
    #[error(
        "the XDP hook of {iface} is already held by {occupant}; refusing to replace it. \
         An interface takes one XDP program, so replacing it would silently stop \
         whatever it was doing. Detach it with `ip link set dev {iface} xdp off`, or run \
         Lorica on another interface."
    )]
    Occupied { iface: String, occupant: String },

    #[error(
        "{iface} has no native XDP support, and Lorica does not fall back to generic \
         mode: generic XDP runs after the network stack has built an skb, which is most \
         of the cost a drop exists to avoid. Use an interface whose driver supports XDP."
    )]
    NotNative { iface: String },

    #[error(
        "attached to {iface}, but the kernel reports {mode} instead of native mode. \
         Refusing an attach that is not what it was asked to be."
    )]
    NotNativeAfterAll { iface: String, mode: String },

    #[error("attaching to {iface} failed: {source}")]
    Failed {
        iface: String,
        #[source]
        source: ProgramError,
    },

    #[error(
        "detached from {iface}, but the kernel still reports a program on the hook after \
         {waited_ms} ms. Tearing a bpf_link down finishes on a workqueue, so a short wait \
         is normal and this is not one."
    )]
    StillAttached { iface: String, waited_ms: u128 },

    #[error("detaching from {iface} failed: {source}")]
    DetachFailed {
        iface: String,
        #[source]
        source: ProgramError,
    },
}

/// Attaches in native mode, and only in native mode.
///
/// The hook is not probed first. aya always sets `XDP_FLAGS_UPDATE_IF_NOEXIST`, so the
/// kernel refuses an occupied hook itself and there is no window between looking and
/// attaching; the probe happens afterwards, only to name the occupant of a hook that was
/// already busy.
pub fn attach_native(program: &mut Xdp, iface: &str) -> Result<XdpLinkId, AttachError> {
    let link = program
        .attach(iface, XdpMode::Driver)
        .map_err(|err| classify(err, iface))?;

    // The mode the kernel reports, not the mode that was requested. This is the check
    // that would catch a future aya or kernel quietly widening the flags, and it is
    // cheap: once per attach, never per packet.
    match hook_probe::probe(iface) {
        Ok(state) if state.mode == hook_probe::AttachMode::Native => Ok(link),
        Ok(state) => {
            let _ = program.detach(link);
            Err(AttachError::NotNativeAfterAll {
                iface: iface.to_owned(),
                mode: state.mode.to_string(),
            })
        }
        // The attach succeeded and the confirmation did not. Reporting a success here
        // would be reporting an unverified one, and this is the invariant the whole
        // measurement rests on, so it fails.
        Err(err) => {
            let _ = program.detach(link);
            Err(AttachError::NotNativeAfterAll {
                iface: iface.to_owned(),
                mode: format!("nothing it could read back: {err}"),
            })
        }
    }
}

/// How long to wait for the kernel to actually let go of the hook.
///
/// It was fifty milliseconds, on the argument that this was two orders of magnitude above
/// what had been observed, so anything slower was a fault and not a slow machine. **A shared
/// CI runner disproved that**: the second round of the detach-and-reattach cycle exceeded it,
/// with the hook still occupied. The observation was taken on a quiet four-vCPU lab VM, and
/// the workqueue that finishes the teardown competes with everything else on a contended
/// host.
///
/// So this is not a fault threshold and it should never have been described as one. It is how
/// long a caller is willing to block on a path that is **not** the packet path — detach runs
/// on a detection transition, not per packet. The failure it guards against is worse than the
/// wait: returning success while the hook is still busy hands the next attach an `EBUSY` from
/// the program that was just detached, intermittently and only under load.
const RELEASE_TIMEOUT: Duration = Duration::from_millis(500);

/// Detaches, and does not return until the hook is free.
///
/// Dropping a `bpf_link` closes a descriptor, and the kernel finishes the teardown on a
/// workqueue: the syscall returns before the program is off the interface. So an attach
/// issued straight after a detach can be refused with EBUSY by the program that was just
/// detached — intermittently, and only under load, which is the worst way for it to
/// happen. Since the design is detached by default and attached on detection, that
/// sequence is the production path and not a test convenience, so waiting belongs here
/// rather than in every caller.
pub fn detach(program: &mut Xdp, link: XdpLinkId, iface: &str) -> Result<(), AttachError> {
    program
        .detach(link)
        .map_err(|source| AttachError::DetachFailed {
            iface: iface.to_owned(),
            source,
        })?;

    let deadline = Instant::now() + RELEASE_TIMEOUT;
    loop {
        match hook_probe::probe(iface) {
            Ok(state) if state.prog_id.is_none() => return Ok(()),
            // An interface that has gone away is a hook nobody holds. This is the common
            // case for a test fixture torn down in whatever order Drop chose.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            _ if Instant::now() >= deadline => {
                return Err(AttachError::StillAttached {
                    iface: iface.to_owned(),
                    waited_ms: RELEASE_TIMEOUT.as_millis(),
                });
            }
            _ => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn classify(err: ProgramError, iface: &str) -> AttachError {
    match errno_of(&err) {
        // EBUSY is the hook already taken in native mode; EEXIST is it taken in
        // another mode, which the kernel words as "Native and generic XDP can't be
        // active at the same time". Both are one program in the way and the same
        // instruction to the operator, and the occupant carries its own mode in the
        // diagnostic. The second one is the common case in the field: an overlay agent
        // sitting on a generic hook is not visible to anyone looking for a native one.
        Some(libc::EBUSY) | Some(libc::EEXIST) => AttachError::Occupied {
            iface: iface.to_owned(),
            occupant: describe_occupant(iface),
        },
        Some(libc::EOPNOTSUPP) => AttachError::NotNative {
            iface: iface.to_owned(),
        },
        _ => AttachError::Failed {
            iface: iface.to_owned(),
            source: err,
        },
    }
}

/// Walks the source chain for an OS error code rather than matching on aya's error
/// variants: the errno is the stable part of this, and the shape of the enum around it
/// has changed between minor releases of a 0.x.
fn errno_of(err: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut current = Some(err);
    while let Some(err) = current {
        if let Some(code) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
        {
            return Some(code);
        }
        current = err.source();
    }
    None
}

fn describe_occupant(iface: &str) -> String {
    match hook_probe::occupant(iface) {
        Ok(Some(occupant)) => occupant.to_string(),
        // Both of these are worth distinguishing from a named program: the first says
        // the hook was taken and freed between two syscalls, the second says the
        // refusal is real but the diagnostic is incomplete, and an operator reading a
        // support ticket needs to know which.
        Ok(None) => "a program that was gone by the time the hook was queried".to_owned(),
        Err(err) => format!("a program the kernel would not name ({err})"),
    }
}
