//! One GET, answered by hand, on loopback.
//!
//! **Why loopback is the default.** This endpoint serialises the whole registry on every
//! call, which makes it an amplifier: a few kilobytes of requests turn into a few
//! megabytes of responses and a matching amount of CPU, in the process whose entire purpose
//! is to survive floods. Bound to `127.0.0.1` it can only be reached by something already
//! on the host. Reaching it from off-host is an address the operator has to type.
//!
//! **Why the request is read once and truncated.** A scraper's request line arrives in the
//! first segment, and everything after the path is irrelevant to a GET that takes no
//! parameters. So one bounded read, one prefix comparison, and no parser: a request larger
//! than the buffer is answered from what did arrive, and a request that does not start with
//! `GET /metrics` gets a 404 and a closed socket. That is a smaller attack surface than a
//! header parser, not just less code.

use std::{future::pending, io};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{Exporter, Source};

/// Loopback, and the port Prometheus itself uses, because an operator who has to look it up
/// will guess this one.
pub const DEFAULT_ADDR: &str = "127.0.0.1:9090";

/// Enough for the request line and the first headers of any scraper. A request that does
/// not identify itself in 512 bytes is not one this endpoint wants to help.
const REQUEST: usize = 512;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\nConnection: close\r\n\r\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const FAILED: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";

/// Binds synchronously, so a bad address fails at startup rather than at the first scrape.
pub fn bind(addr: &str) -> io::Result<TcpListener> {
    TcpListener::from_std(std::net::TcpListener::bind(addr).and_then(|listener| {
        listener.set_nonblocking(true)?;
        Ok(listener)
    })?)
}

/// Accepts a scrape, or never resolves when the endpoint is off.
///
/// `select!` needs a future in every arm and `--metrics off` has no listener, so the absence
/// is a future that does not complete rather than a branch in the agent's loop.
pub async fn accept(listener: Option<&TcpListener>) -> io::Result<TcpStream> {
    match listener {
        Some(listener) => listener.accept().await.map(|(stream, _)| stream),
        None => pending().await,
    }
}

/// Answers one connection and closes it.
///
/// Awaited by the caller rather than spawned, for the reason the control socket is: on a
/// current-thread runtime a task per connection lets a slow reader sit in front of the tick.
pub async fn respond(
    mut stream: TcpStream,
    exporter: &mut Exporter,
    source: &Source<'_>,
) -> io::Result<()> {
    let mut request = [0u8; REQUEST];
    let read = stream.read(&mut request).await?;

    if !request[..read].starts_with(b"GET /metrics") {
        return stream.write_all(NOT_FOUND).await;
    }

    match exporter.render(source) {
        Ok(body) => {
            stream.write_all(OK).await?;
            stream.write_all(body.as_bytes()).await
        }
        // Only reachable if the encoder itself refuses the registry, which is a build-time
        // mistake and not a runtime condition. Reported rather than panicked: the agent
        // losing its metrics is not a reason for the agent to stop filtering packets.
        Err(_) => stream.write_all(FAILED).await,
    }
}
