//! Putting the program in the packet path, and what that costs from the moment it happens.
//!
//! **The tax is paid 100 % of the time, attack or not, and the number is 58.** Measured on
//! virtio in the lab: an attached program takes 58 % off the receive throughput and adds 57 %
//! to the application's p99, on traffic that triggers nothing. The mechanism is not a
//! disabled offload — that hypothesis was tested on kernel 6.8 and refuted, an attach turns
//! off not one virtio offload — it is that XDP runs **before** GRO, so the coalescing that
//! used to hand the stack one large segment per burst has nothing left to coalesce and the
//! stack pays per packet instead of per burst. No flag removes this; it is what the hook is.
//! Anyone who passes `--iface` is buying exactly that, and the flag exists so that they buy
//! it deliberately.
//!
//! **Why the operator decides and not the agent.** The design this replaces was detached by
//! default and attached on detection, which cannot work: detection reads the counters of the
//! program, and the counters only move while the program is attached. A signal that requires
//! being attached cannot be what decides to attach, so the decision is not the agent's to
//! make and it is a flag. The alternative that would work — a second, permanently attached
//! program cheap enough to leave on — is a different program and a different measurement.
//!
//! **Attaching is not arming.** `observe` stays the default mode and an attached agent in
//! observe mode writes nothing into the unified list: the counters move, the list does not.
//! That separation is what makes an attached default acceptable to open publicly, and
//! `tests/attach_iface.rs` asserts it rather than asserting the two flags are independent in
//! the source.

use aya::{
    Ebpf,
    programs::{Xdp, xdp::XdpLinkId},
};
use lorica_dataplane::loader;

/// The XDP program, by the name `lorica-ebpf` declares it under.
pub const PROGRAM: &str = "lorica_xdp";

/// An interface the program is on, and the link that holds it there.
///
/// One at a time, and not because a set would be hard: the XDP hook takes one program per
/// interface and this agent holds one program, so a second interface is a second agent. The
/// name is kept alongside the link because every message an operator reads about a detach
/// has to name what was detached, including the ones written after the link is gone.
pub struct Attachment {
    iface: String,
    link: XdpLinkId,
}

impl Attachment {
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

/// Attaches, in native mode or not at all.
///
/// The refusals are [`loader::attach_native`]'s and they are rendered here rather than
/// classified: an occupied hook names the program in the way, a driver without native
/// support says so, and neither falls back. Both messages are what an operator reads at the
/// moment the agent refuses to start, so they are passed through whole.
pub fn attach(ebpf: &mut Ebpf, iface: &str) -> Result<Attachment, String> {
    let link = loader::attach_native(program(ebpf)?, iface).map_err(|err| err.to_string())?;
    Ok(Attachment {
        iface: iface.to_owned(),
        link,
    })
}

/// Detaches, and does not return until the kernel has let go of the hook.
///
/// The [`Attachment`] is consumed on failure as well as on success, and that is deliberate:
/// aya removes the link from the program before anything here can fail, so a failure leaves
/// a value that no longer refers to a link the kernel would accept. Handing it back would be
/// offering the caller a second attempt that cannot work.
pub fn detach(ebpf: &mut Ebpf, attached: Attachment) -> Result<(), String> {
    let Attachment { iface, link } = attached;
    loader::detach(program(ebpf)?, link, &iface).map_err(|err| err.to_string())
}

fn program(ebpf: &mut Ebpf) -> Result<&mut Xdp, String> {
    ebpf.program_mut(PROGRAM)
        .ok_or_else(|| format!("no program named {PROGRAM} in the loaded object"))?
        .try_into()
        .map_err(|err| format!("{PROGRAM} is not an XDP program: {err}"))
}
