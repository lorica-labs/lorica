//! One HTTP POST to the anti-DDoS API of the host, and one DELETE to take it back.
//!
//! **The client, decided by measurement rather than by taste.** Two binaries were built
//! under the release profile of this workspace, each doing the same POST. With
//! `std::net::TcpStream` and nothing else: 130 048 bytes, and `cargo tree --edges normal`
//! lists the crate itself and no dependency. With `reqwest` 0.12 (`blocking`, `json`),
//! which brings hyper, tokio, http, and a TLS stack: 1 475 072 bytes and 96 distinct
//! crates over 231 tree entries. Eleven times the binary and ninety-six crates of supply
//! chain, for one request every few minutes, on a code path whose whole job is to be
//! trustworthy when everything else is on fire. Hence the hand-written request below.
//!
//! **What that costs, said plainly.** This speaks cleartext HTTP/1.1 only. A real provider
//! endpoint is HTTPS, so this connector is complete against a local relay or an endpoint on
//! a trusted link, and reaching `api.provider.com` directly needs a TLS crate added to
//! these measurements before it is honest to claim otherwise. The alternative is priced
//! above; that price does not change once a decision on TLS is made.
//!
//! **Why blocking, when the agent is async.** The call blocks, and it belongs on the one
//! blocking thread the agent already reserves (`max_blocking_threads(1)`). Nothing here
//! names a runtime, spawns a task, or asks for more than one thread, so `loricad` keeps
//! its `current_thread` scheduler: an escalation every few minutes is not a reason to make
//! the whole agent multi-threaded.

use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lorica_common::V4_MAPPED_PREFIX_BITS;

use crate::guard::{Admitted, Guard};
use crate::{Announce, EscalateError, Escalator, LpmKey, Ticket};

/// Attempts per call, retries included.
///
/// Public because the bound is a property callers and tests are entitled to assert, not an
/// implementation detail: an unbounded retry loop pointed at a provider API during an
/// attack is another amplifier, and the account it gets rate-limited is ours.
pub const MAX_ATTEMPTS: u32 = 3;

/// Fixed, not exponential. Three attempts cannot back off far enough for the difference to
/// matter, and a mitigation that has already spent this long is better reported as failed
/// than retried into the operator's timeout.
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// A stalled upstream must not stall the caller. This is the deadline for connect, write
/// and read alike.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Webhook {
    /// `host:port`, as it goes into the `Host` header and into name resolution.
    authority: String,
    path: String,
    token: Option<String>,
    guard: Guard,
    live: AtomicUsize,
}

impl Webhook {
    pub fn new(authority: String, path: String, token: Option<String>, guard: Guard) -> Self {
        Self {
            authority,
            path,
            token,
            guard,
            live: AtomicUsize::new(0),
        }
    }

    fn send(
        &self,
        method: &str,
        target: &str,
        body: Option<&str>,
    ) -> Result<String, EscalateError> {
        let mut attempt = 1;
        loop {
            match self.attempt(method, target, body) {
                Ok(reply) => return Ok(reply),
                Err(err) if attempt < MAX_ATTEMPTS && retryable(&err) => {
                    attempt += 1;
                    std::thread::sleep(RETRY_DELAY);
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn attempt(
        &self,
        method: &str,
        target: &str,
        body: Option<&str>,
    ) -> Result<String, EscalateError> {
        let addr = self
            .authority
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| malformed("the endpoint resolved to no address"))?;
        let mut sock = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
        sock.set_read_timeout(Some(IO_TIMEOUT))?;
        sock.set_write_timeout(Some(IO_TIMEOUT))?;

        let auth = match &self.token {
            Some(token) => format!("Authorization: Bearer {token}\r\n"),
            None => String::new(),
        };
        let framing = match body {
            Some(body) => format!(
                concat!(
                    "Content-Type: application/json\r\n",
                    "Content-Length: {}\r\n"
                ),
                body.len()
            ),
            None => String::new(),
        };
        sock.write_all(
            format!(
                concat!(
                    "{} {} HTTP/1.1\r\n",
                    "Host: {}\r\n",
                    "Connection: close\r\n",
                    "{}{}",
                    "\r\n",
                    "{}"
                ),
                method,
                target,
                self.authority,
                auth,
                framing,
                body.unwrap_or_default()
            )
            .as_bytes(),
        )?;

        // Half-close: the request is complete, and saying so is what lets the peer read to
        // end of stream and answer without a length-delimited parser on its side. It also
        // keeps Windows from resetting the connection over data left unread in a buffer,
        // which discards the reply along with it.
        sock.shutdown(std::net::Shutdown::Write)?;

        // `Connection: close` is what delimits the reply, so end of stream is the end of
        // the body and no chunked decoder is needed.
        let mut raw = String::new();
        sock.read_to_string(&mut raw)?;
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .ok_or_else(|| malformed("the reply had no header terminator"))?;
        let code: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| malformed("the reply had no status code"))?;
        if code >= 400 {
            return Err(EscalateError::Status(code));
        }
        // A 3xx is not followed. A mitigation endpoint that redirects is misconfigured, and
        // chasing the hop would send our credentials somewhere the operator did not name.
        Ok(body.to_owned())
    }
}

impl Escalator for Webhook {
    fn announce(&self, req: &Announce) -> Result<Ticket, EscalateError> {
        let admitted = self.guard.admit(req, self.live.load(Ordering::Relaxed))?;
        let reply = self.send("POST", &self.path, Some(&mitigation_json(&admitted)))?;
        let id = ticket_id(&reply).ok_or(EscalateError::NoTicket)?;
        self.live.fetch_add(1, Ordering::Relaxed);
        Ok(Ticket { id })
    }

    fn withdraw(&self, ticket: &Ticket) -> Result<(), EscalateError> {
        if self.guard.dry_run {
            return Err(EscalateError::DryRun);
        }
        if !usable_id(&ticket.id) {
            return Err(EscalateError::NoTicket);
        }
        self.send("DELETE", &format!("{}/{}", self.path, ticket.id), None)?;
        // Saturating, because withdrawing a ticket this process never announced must not
        // wrap the count into a rule bound that can never be satisfied again.
        let _ = self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                Some(live.saturating_sub(1))
            });
        Ok(())
    }
}

/// Takes an [`Admitted`] and not an [`Announce`]: this is the only function that turns a
/// request into bytes for the upstream, and the type it demands can only come from the
/// guard.
fn mitigation_json(admitted: &Admitted) -> String {
    let req = admitted.request();
    format!(
        r#"{{"prefix":"{}","protocol":{},"port_lo":{},"port_hi":{}}}"#,
        cidr(&req.dest),
        req.scope.proto,
        req.scope.port_lo,
        req.scope.port_hi
    )
}

/// The unified key printed the way an operator wrote it, IPv4 back out of the mapped range.
fn cidr(key: &LpmKey) -> String {
    let addr = Ipv6Addr::from(key.addr);
    match addr.to_ipv4_mapped() {
        Some(v4) if key.prefix_len >= V4_MAPPED_PREFIX_BITS => {
            format!("{v4}/{}", key.prefix_len - V4_MAPPED_PREFIX_BITS)
        }
        _ => format!("{addr}/{}", key.prefix_len),
    }
}

/// The one field of the reply that is needed, without a JSON parser.
///
/// A parser is not worth a dependency for a single string, and it would not remove the
/// check that follows: whatever the shape of the reply, the value is a stranger's text that
/// ends up in a request line, so it is admitted only if it is safe there. That check is
/// what makes the naive scan below safe rather than merely short.
fn ticket_id(reply: &str) -> Option<String> {
    let value = reply
        .split_once("\"id\"")?
        .1
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?
        .split_once('"')?
        .0;
    usable_id(value).then(|| value.to_owned())
}

/// Whether an identifier can be pasted into a request target without changing its meaning.
fn usable_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// A 429 and a 5xx are the upstream saying "not now"; everything else it says it means.
fn retryable(err: &EscalateError) -> bool {
    matches!(
        err,
        EscalateError::Transport(_) | EscalateError::Status(429)
    ) || matches!(err, EscalateError::Status(code) if *code >= 500)
}

fn malformed(what: &'static str) -> EscalateError {
    EscalateError::Transport(std::io::Error::new(std::io::ErrorKind::InvalidData, what))
}
