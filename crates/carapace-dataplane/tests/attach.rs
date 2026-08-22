//! Native attach, and the refusal that has to name who is in the way.
//!
//! The XDP hook takes one program per interface. TCX brought ordered multi-program
//! attach, but for TC and not for XDP, and the libxdp dispatcher convention is a
//! cooperation protocol aya does not speak. So a collision with Cilium in
//! kube-proxy-replacement mode, or with a hosting provider XDP protection, is decided by
//! whoever attached last, and the loser stops filtering without saying so. Refusing is
//! the only honest behaviour, and a refusal that does not name the occupant is a support
//! ticket.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{path::PathBuf, process::Command};

use aya::{
    EbpfLoader,
    programs::{XdpMode, xdp::XdpLinkId},
};
use carapace_common::DEFAULT_SETTINGS;
use carapace_dataplane::loader::{
    AttachError, attach_native, detach,
    hook_probe::{self, AttachMode},
};
use support::{
    net::{Link, ip_link_mode},
    run::{load_raw, object_path, xdp_program},
};

/// The occupant of these tests: a program that does nothing, so whatever the attach does
/// next is about the hook and not about the program.
///
/// `bench/progs/*.o` is gitignored, so it is built rather than assumed present. When the
/// test runs on the measurement VM the object travels with the binary instead, because
/// that machine has no compiler, hence the environment variable.
fn xdp_pass_object() -> PathBuf {
    if let Ok(dir) = std::env::var("CARAPACE_BENCH_PROGS") {
        return PathBuf::from(dir).join("xdp_pass.o");
    }
    let progs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/progs");
    let object = progs.join("xdp_pass.o");
    if !object.is_file() {
        let out = Command::new("make")
            .arg("-C")
            .arg(&progs)
            .arg("xdp_pass.o")
            .output()
            .expect("cannot run make");
        assert!(
            object.is_file(),
            "make -C {} xdp_pass.o did not produce the target: {}",
            progs.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    object
}

fn occupy(iface: &str, mode: XdpMode) -> (aya::Ebpf, XdpLinkId) {
    let path = xdp_pass_object();
    let object =
        std::fs::read(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    let mut ebpf = EbpfLoader::new()
        .load(&object)
        .expect("loading xdp_pass.o failed");
    let program = xdp_program(&mut ebpf, "xdp_pass");
    let link = program
        .attach(iface, mode)
        .expect("xdp_pass could not take the hook, so the test cannot state its case");
    (ebpf, link)
}

#[test]
fn attaching_to_a_free_hook_lands_in_native_mode() {
    let veth = Link::veth("cara-free");
    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);

    let link = attach_native(program, &veth.name).expect("the hook was free");

    let state = hook_probe::probe(&veth.name).expect("probing the hook failed");
    assert_eq!(
        state.mode,
        AttachMode::Native,
        "the program is attached in {}, and generic mode makes every later number \
         meaningless",
        state.mode
    );
    assert_eq!(
        ip_link_mode(&veth.name),
        "xdp",
        "ip -d link has to render xdp and never xdpgeneric"
    );
    assert!(state.prog_id.is_some(), "the kernel named no program");

    detach(program, link, &veth.name).expect("detaching failed");
    assert_eq!(
        hook_probe::probe(&veth.name).unwrap().mode,
        AttachMode::None,
        "the hook is still held after a detach"
    );
    assert_eq!(ip_link_mode(&veth.name), "none");
}

/// The case the task exists for. A refusal that does not name the occupant leaves the
/// operator with nothing to act on, so the id, the name and the tag are all asserted.
#[test]
fn attaching_over_an_occupied_hook_is_refused_and_names_the_occupant() {
    let veth = Link::veth("cara-busy");
    let (occupant_ebpf, _link) = occupy(&veth.name, XdpMode::Driver);

    let held = hook_probe::occupant(&veth.name)
        .expect("probing the hook failed")
        .expect("the occupant took the hook but the kernel names nobody");

    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let err = attach_native(program, &veth.name)
        .expect_err("carapace replaced a program that was already there");

    assert!(
        matches!(err, AttachError::Occupied { .. }),
        "the hook was busy and the error says something else: {err}"
    );
    let message = err.to_string();
    // Printed, not just asserted on. This is the text an operator reads at the moment
    // Carapace refuses to start, and a diagnostic nobody has ever read is a diagnostic
    // nobody has judged. `--nocapture` shows it.
    println!("refusal as the operator sees it:\n{message}");
    for expected in [
        held.prog_id.to_string(),
        held.name.clone(),
        format!("{:016x}", held.tag),
        veth.name.clone(),
    ] {
        assert!(
            message.contains(&expected),
            "the diagnostic does not name {expected:?}; it says: {message}"
        );
    }

    // The occupant is still there: refusing means refusing, not replacing and reporting.
    assert_eq!(
        hook_probe::probe(&veth.name).unwrap().prog_id,
        Some(held.prog_id),
        "the refused attach replaced the occupant anyway"
    );
    drop(occupant_ebpf);
}

/// No silent fallback to generic. Generic XDP runs after the stack has already built an
/// skb, which is most of the cost the drop was meant to avoid, and the 2 to 8 Mpps it
/// yields varies enough that a measurement taken in that mode means nothing.
#[test]
fn a_driver_without_native_support_is_refused_rather_than_downgraded() {
    let dummy = Link::dummy("cara-dumb");
    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);

    let err = attach_native(program, &dummy.name).expect_err("a dummy has no ndo_bpf");
    assert!(
        matches!(err, AttachError::NotNative { .. }),
        "expected a refusal naming native mode, got: {err}"
    );
    assert_eq!(
        hook_probe::probe(&dummy.name).unwrap().mode,
        AttachMode::None,
        "something attached to a driver that cannot support it"
    );
}

/// The collision that actually happens in the field, and the one an earlier version of
/// this file tripped over on the lab machine: an overlay agent holds the *generic* hook,
/// so a native attach fails with a different errno and a message about the two modes not
/// coexisting. It is still one program in the way, and the refusal has to name it rather
/// than report a syscall.
#[test]
fn a_hook_held_in_another_mode_is_refused_and_names_the_occupant() {
    let veth = Link::veth("cara-mixed");
    let (occupant_ebpf, _link) = occupy(&veth.name, XdpMode::Skb);
    assert_eq!(
        hook_probe::probe(&veth.name).unwrap().mode,
        AttachMode::Generic,
        "the fixture did not take the generic hook"
    );

    let held = hook_probe::occupant(&veth.name).unwrap().unwrap();
    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);
    let err = attach_native(program, &veth.name).expect_err("the generic hook is taken");

    assert!(
        matches!(err, AttachError::Occupied { .. }),
        "a hook held in generic mode has to read as occupied and not as a failed \
         syscall: {err}"
    );
    let message = err.to_string();
    assert!(
        message.contains(&held.prog_id.to_string()) && message.contains("generic"),
        "the diagnostic names neither the occupant nor its mode: {message}"
    );
    drop(occupant_ebpf);
}

/// Detach is a production path and not a test convenience: the design that came out of
/// the attach-tax measurement is detached by default and attached on detection, so the
/// program is expected to come and go many times on a running node.
#[test]
fn a_detached_hook_can_be_taken_again() {
    let veth = Link::veth("cara-cycle");
    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);

    let mut ids = Vec::new();
    for round in 0..3 {
        let link = attach_native(program, &veth.name)
            .unwrap_or_else(|err| panic!("round {round} could not attach: {err}"));
        let state = hook_probe::probe(&veth.name).unwrap();
        assert_eq!(state.mode, AttachMode::Native, "round {round}");
        ids.push(state.prog_id);
        detach(program, link, &veth.name).unwrap_or_else(|err| panic!("round {round}: {err}"));
    }

    assert!(
        ids.windows(2).all(|pair| pair[0] == pair[1]),
        "the program id changed between attaches, so the program was reloaded rather \
         than reattached: {ids:?}"
    );
}

#[test]
fn an_unknown_interface_is_named_in_the_error() {
    let mut ebpf = load_raw(&object_path(), DEFAULT_SETTINGS);
    let program = xdp_program(&mut ebpf, support::PROGRAM);

    let err = attach_native(program, "cara-nosuch").expect_err("the interface does not exist");
    assert!(
        err.to_string().contains("cara-nosuch"),
        "the error does not name the interface: {err}"
    );
}
