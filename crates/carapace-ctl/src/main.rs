//! Thin client on the control socket: one text command out, the answer printed.
//!
//! It holds no type in common with the daemon on purpose. The capability table in that
//! answer is the daemon's own, so it describes the kernel the dataplane is loaded against
//! and not whichever machine happens to run this client.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

const CONTROL_SOCKET: &str = "/run/carapace/control.sock";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("status") => send("status"),
        _ => {
            eprintln!("usage: carapace-ctl status");
            ExitCode::FAILURE
        }
    }
}

fn send(command: &str) -> ExitCode {
    let mut answer = String::new();
    let exchange = UnixStream::connect(CONTROL_SOCKET).and_then(|mut socket| {
        writeln!(socket, "{command}")?;
        // Half-close: the daemon sees the end of the command without either side having to
        // agree on a delimiter before the protocol is written.
        socket.shutdown(Shutdown::Write)?;
        socket.read_to_string(&mut answer)
    });
    match exchange {
        Ok(_) => {
            println!("{}", answer.trim_end());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("no answer from {CONTROL_SOCKET}: {error}");
            ExitCode::FAILURE
        }
    }
}
