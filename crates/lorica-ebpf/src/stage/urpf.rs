//! Stage 5, conditional on the role. Strict reverse-path filtering: the source of the
//! packet is looked up as a destination and the answer has to come back out of the
//! interface the packet arrived on.
//!
//! Armed by the loader and never by the operator, for the reason `setting::URPF_ENFORCE`
//! carries: the criterion is a property of the routing table of the ingress interface, and
//! on a host with a default route the strict check discriminates nothing. The gate matters
//! in nanoseconds and not only in correctness, and by a much wider margin than the plan
//! expected: measured on the real pipeline, arming this stage takes the legitimate path
//! from **86 ns to 226 ns** above the `XDP_PASS` floor. That is **+163 %**, not the 59 %
//! an earlier C fixture predicted from a 48 ns helper — the fixture was wrong by about a
//! factor of three. Arming it where it discriminates nothing would more than double the
//! cost of every legitimate packet, which is what the criterion exists to avoid.
//!
//! The other half of the stage is that `bpf_fib_lookup` has nine return codes and only one
//! of them is a statement about the packet. `FWD_DISABLED` is what a host that does not
//! forward answers for every frame, before the table is consulted at all, so a stage that
//! read it as "no route back" would drop all traffic on the ordinary target of this tier.
//! The three counters below are that distinction made visible.

use aya_ebpf::{
    bindings::{
        BPF_FIB_LKUP_RET_BLACKHOLE, BPF_FIB_LKUP_RET_NOT_FWDED, BPF_FIB_LKUP_RET_PROHIBIT,
        BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LKUP_RET_UNREACHABLE,
    },
    programs::XdpContext,
};
use lorica_common::{CounterId, PacketView};

use crate::{helpers, settings, stage::Outcome};

/// Takes the context and not only the view, because the ingress interface is the one field
/// of `xdp_md` no parse produces: it comes from the receive queue the frame arrived on.
#[inline(never)]
pub fn run(ctx: &XdpContext, view: &PacketView) -> Outcome {
    if !settings::urpf_enforce() {
        return Outcome::Continue;
    }

    let ingress = ctx.ingress_ifindex() as u32;
    let answer = helpers::fib_reverse_path(ctx, view, ingress);

    match answer.code {
        // A route back that leaves by the interface the packet came in on. The ordinary
        // case, and the only one with no counter: an operator learns nothing from a number
        // that counts every legitimate packet.
        BPF_FIB_LKUP_RET_SUCCESS if answer.ifindex == ingress => Outcome::Continue,
        // Reachable, but not this way round. This counter is the only one here that names
        // an attacker, and it is the whole reason the stage exists.
        BPF_FIB_LKUP_RET_SUCCESS => {
            helpers::bump(CounterId::UrpfWrongInterface);
            Outcome::Drop
        }
        // No path back at all, whether the table says so by omission — `NOT_FWDED`, which
        // is also the answer for a route that is not unicast — or in as many words. The
        // verdict is a drop, and it is only defensible because of the criterion: the stage
        // is armed only where the loader found no default route on the ingress interface,
        // so a source the table cannot reach is one this host has no business believing in.
        // A count that climbs during a convergence window is a route that has not come
        // back yet and not an attack, which is what the 30 s hysteresis of the watcher is
        // there to keep rare.
        BPF_FIB_LKUP_RET_BLACKHOLE
        | BPF_FIB_LKUP_RET_UNREACHABLE
        | BPF_FIB_LKUP_RET_PROHIBIT
        | BPF_FIB_LKUP_RET_NOT_FWDED => {
            helpers::bump(CounterId::UrpfNoRoute);
            Outcome::Drop
        }
        // Everything left is about the host and not about the packet, so the packet goes
        // on: `FWD_DISABLED` (5) is every frame on a host that does not forward and is the
        // code the lab actually produces, `UNSUPP_LWT` (6) is a tunnel encapsulation this
        // program does not follow, `NO_NEIGH` (7) cannot arrive with `SKIP_NEIGH` set,
        // `FRAG_NEEDED` (8) needs a `tot_len` the wrapper does not send, `NO_SRC_ADDR` (9)
        // needs a flag it does not send either, and a value outside the enumeration is a
        // negative errno — the helper refusing the call. A counter climbing by one per
        // packet is the stage saying it cannot answer, which is a loader question.
        _ => {
            helpers::bump(CounterId::UrpfLookupUnsupported);
            Outcome::Continue
        }
    }
}
