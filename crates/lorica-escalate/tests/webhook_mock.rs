//! The connector against a canned upstream, no network beyond loopback.
//!
//! The listener binds `127.0.0.1:0` and the test reads the port back. A hard-coded port is
//! how this repository already earned one intermittent failure: two test binaries of the
//! same crate run in parallel by default, and the second one to bind loses.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use lorica_escalate::guard::Guard;
use lorica_escalate::webhook::{MAX_ATTEMPTS, Webhook};
use lorica_escalate::{Announce, EscalateError, Escalator, LpmKey, Scope, Ticket};

/// Long enough that a request in flight arrives, short enough to keep the suite quick.
const SETTLE: Duration = Duration::from_millis(500);

const CREATED: &str = concat!(
    "HTTP/1.1 201 Created\r\n",
    "Content-Type: application/json\r\n",
    "Connection: close\r\n",
    "\r\n",
    "{\"id\":\"tkt-7f3\",\"state\":\"active\"}"
);
const NO_CONTENT: &str = concat!(
    "HTTP/1.1 204 No Content\r\n",
    "Connection: close\r\n",
    "\r\n"
);
const FORBIDDEN: &str = concat!(
    "HTTP/1.1 403 Forbidden\r\n",
    "Connection: close\r\n",
    "\r\n"
);
const UNAVAILABLE: &str = concat!(
    "HTTP/1.1 503 Service Unavailable\r\n",
    "Connection: close\r\n",
    "\r\n"
);

/// Answers one canned response per element and reports every request head it read.
fn mock(responses: &'static [&'static str]) -> (String, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for response in responses {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            // The client half-closes once its request is out, so end of stream delimits it
            // and no length parsing is needed here.
            let mut request = Vec::new();
            let _ = sock.read_to_end(&mut request);
            let _ = sock.write_all(response.as_bytes());
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        }
    });
    (authority, rx)
}

fn connector(authority: String) -> Webhook {
    Webhook::new(
        authority,
        "/v1/mitigation".to_owned(),
        Some("s3cret".to_owned()),
        Guard {
            declared: vec![LpmKey::v4([203, 0, 113, 0], 24)],
            administration: vec![LpmKey::v4([203, 0, 113, 240], 28)],
            ports: 30000..=30200,
            rule_bound: 4,
            dry_run: false,
        },
    )
}

fn request() -> Announce {
    Announce {
        dest: LpmKey::host_v4([203, 0, 113, 9]),
        scope: Scope::new(17, 30120, 30120),
    }
}

#[test]
fn announce_posts_the_prefix_and_returns_the_ticket() {
    let (authority, rx) = mock(&[CREATED]);
    let ticket = connector(authority).announce(&request()).unwrap();
    assert_eq!(ticket.id, "tkt-7f3");

    let head = rx.recv_timeout(SETTLE).unwrap();
    assert!(
        head.starts_with("POST /v1/mitigation HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("Authorization: Bearer s3cret"), "{head}");
    assert!(head.contains("Content-Length: "), "{head}");
}

#[test]
fn a_client_error_is_reported_and_not_retried() {
    let (authority, rx) = mock(&[FORBIDDEN, FORBIDDEN]);
    let err = connector(authority).announce(&request()).unwrap_err();
    assert!(matches!(err, EscalateError::Status(403)), "{err:?}");

    assert!(rx.recv_timeout(SETTLE).is_ok());
    assert!(
        rx.recv_timeout(SETTLE).is_err(),
        "a 403 is the upstream refusing us, and repeating it changes nothing"
    );
}

/// An unbounded retry loop under attack is one more amplifier, aimed at the API the
/// mitigation depends on. The mock offers more responses than the bound allows so that a
/// missing bound would show up as extra requests rather than as a hang.
#[test]
fn server_errors_are_retried_up_to_the_bound() {
    let (authority, rx) = mock(&[UNAVAILABLE; 8]);
    let err = connector(authority).announce(&request()).unwrap_err();
    assert!(matches!(err, EscalateError::Status(503)), "{err:?}");

    for _ in 0..MAX_ATTEMPTS {
        assert!(rx.recv_timeout(SETTLE).is_ok());
    }
    assert!(rx.recv_timeout(SETTLE).is_err(), "retried past the bound");
}

#[test]
fn withdraw_deletes_the_ticket_it_was_given() {
    let (authority, rx) = mock(&[CREATED, NO_CONTENT]);
    let connector = connector(authority);
    let ticket = connector.announce(&request()).unwrap();
    connector.withdraw(&ticket).unwrap();

    let _ = rx.recv_timeout(SETTLE).unwrap();
    let head = rx.recv_timeout(SETTLE).unwrap();
    assert!(
        head.starts_with("DELETE /v1/mitigation/tkt-7f3 HTTP/1.1\r\n"),
        "{head}"
    );
}

/// The ticket is a string chosen by the upstream and it lands in a request line. A reply
/// that smuggles a terminator in it appends a second request of the upstream's choosing,
/// under our credentials.
#[test]
fn a_ticket_id_that_could_forge_a_request_is_refused() {
    let (authority, rx) = mock(&[NO_CONTENT]);
    let forged = Ticket {
        id: "tkt-7f3 HTTP/1.1\r\nX-Injected: 1".to_owned(),
    };
    let err = connector(authority).withdraw(&forged).unwrap_err();
    assert!(matches!(err, EscalateError::NoTicket), "{err:?}");
    assert!(
        rx.recv_timeout(SETTLE).is_err(),
        "the forged id was emitted"
    );
}

#[test]
fn dry_run_emits_nothing() {
    let (authority, rx) = mock(&[CREATED]);
    let connector = Webhook::new(
        authority,
        "/v1/mitigation".to_owned(),
        None,
        Guard {
            declared: vec![LpmKey::v4([203, 0, 113, 0], 24)],
            administration: vec![],
            ports: 30000..=30200,
            rule_bound: 4,
            dry_run: true,
        },
    );
    let err = connector.announce(&request()).unwrap_err();
    assert!(matches!(err, EscalateError::DryRun), "{err:?}");
    assert!(
        rx.recv_timeout(SETTLE).is_err(),
        "a dry run reached the wire"
    );
}
