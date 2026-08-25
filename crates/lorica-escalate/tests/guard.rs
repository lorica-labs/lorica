//! One test per refusal, because a guard tested in aggregate is a guard where one check
//! can rot while the suite stays green.

use lorica_escalate::guard::Guard;
use lorica_escalate::{Announce, EscalateError, LpmKey, Scope};

const UDP: u8 = 17;
const DECLARED: LpmKey = LpmKey::v4([203, 0, 113, 0], 24);
const ADMINISTRATION: LpmKey = LpmKey::v4([203, 0, 113, 240], 28);

fn guard(dry_run: bool) -> Guard {
    Guard {
        declared: vec![DECLARED],
        administration: vec![ADMINISTRATION],
        ports: 30000..=30200,
        rule_bound: 2,
        dry_run,
    }
}

fn toward(addr: [u8; 4], port: u16) -> Announce {
    Announce {
        dest: LpmKey::host_v4(addr),
        scope: Scope::new(UDP, port, port),
    }
}

#[test]
fn admits_a_declared_destination_in_range() {
    let req = toward([203, 0, 113, 9], 30120);
    let admitted = guard(false).admit(&req, 0).unwrap();
    assert_eq!(admitted.request().dest, req.dest);
}

#[test]
fn refuses_a_destination_outside_the_declared_prefixes() {
    let req = toward([198, 51, 100, 9], 30120);
    let err = guard(false).admit(&req, 0).unwrap_err();
    assert!(
        matches!(err, EscalateError::Undeclared(k) if k == req.dest),
        "{err:?}"
    );
}

#[test]
fn refuses_a_port_outside_the_permitted_range() {
    let req = toward([203, 0, 113, 9], 22);
    let err = guard(false).admit(&req, 0).unwrap_err();
    assert!(
        matches!(err, EscalateError::PortRange { lo: 22, hi: 22 }),
        "{err:?}"
    );
}

#[test]
fn refuses_an_announcement_past_the_rule_bound() {
    let req = toward([203, 0, 113, 9], 30120);
    let err = guard(false).admit(&req, 2).unwrap_err();
    assert!(
        matches!(err, EscalateError::RuleBound { live: 2, bound: 2 }),
        "{err:?}"
    );
}

/// The one that matters. The address is inside the declared prefix, so no other check can
/// catch it, and what it would buy an attacker who found a way to aim the detector at it
/// is the operator's own access to the machine, cut by the upstream, for as long as the
/// rule lives. The second half of the test is there so the first half cannot pass for the
/// wrong reason: with the administration list empty, the very same request is admitted.
#[test]
fn refuses_our_own_administration_prefix() {
    let req = toward([203, 0, 113, 241], 30120);
    let err = guard(false).admit(&req, 0).unwrap_err();
    assert!(
        matches!(err, EscalateError::Administration(k) if k == req.dest),
        "{err:?}"
    );

    let unguarded = Guard {
        administration: vec![],
        ..guard(false)
    };
    assert!(unguarded.admit(&req, 0).is_ok());
}

#[test]
fn dry_run_refuses_with_its_own_error() {
    let req = toward([203, 0, 113, 9], 30120);
    let err = guard(true).admit(&req, 0).unwrap_err();
    assert!(matches!(err, EscalateError::DryRun), "{err:?}");
}

/// A dry run reports the defect it found rather than the fact that it was a dry run: an
/// operator rehearsing a mitigation has to learn about the wrong port range now.
#[test]
fn dry_run_still_reports_a_real_violation() {
    let req = toward([203, 0, 113, 9], 22);
    let err = guard(true).admit(&req, 0).unwrap_err();
    assert!(
        matches!(err, EscalateError::PortRange { lo: 22, hi: 22 }),
        "{err:?}"
    );
}
