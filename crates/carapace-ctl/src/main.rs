//! Thin client. `status` announces the colour of this kernel, then asks the daemon what it
//! is doing with it.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use carapace_dataplane::capability::probe;

/// The daemon owns this socket. Until it exists, `status` still has the capability table to
/// print, because that one is read from the running kernel and needs nobody.
const CONTROL_SOCKET: &str = "/run/carapace/control.sock";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("status") => status(),
        _ => {
            eprintln!("usage: carapace-ctl status");
            ExitCode::FAILURE
        }
    }
}

fn status() -> ExitCode {
    match probe::running_release() {
        Some((major, minor)) => println!("kernel: {major}.{minor}"),
        None => println!("kernel: unknown, capabilities without a symbol probe read absent"),
    }
    println!("capabilities:");
    for found in probe::detect_all() {
        let row = found.cap.row();
        let state = if found.available { "yes" } else { "no " };
        let (major, minor) = row.since;
        println!("  {:<18} {state}  since {major}.{minor}", row.name);
        println!("    reference path: {}", row.fallback);
    }

    // The runtime half of `status` belongs to the daemon, which is not written yet. Say so
    // and fail: an empty success would read as "nothing to report".
    let reason = match UnixStream::connect(CONTROL_SOCKET) {
        Ok(_) => "no client for its protocol in this build".to_string(),
        Err(error) => error.to_string(),
    };
    eprintln!("no runtime status from {CONTROL_SOCKET}: {reason}");
    ExitCode::FAILURE
}
