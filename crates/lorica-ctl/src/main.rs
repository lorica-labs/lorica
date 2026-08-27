//! Thin client on the control socket: one text command out, the answer printed.
//!
//! **It holds no type in common with the daemon, and the number is 0 dependencies.** The
//! commands below are words, not a protocol: this writes one and prints what comes back
//! without looking at it, so there is nothing for a shared type to describe. The
//! alternative — a typed request and reply — cannot live in `loricad`, which pulls tokio,
//! aya and redb, so it would cost an 8th crate in a workspace of 7 and turn `cargo tree -p
//! lorica-ctl --edges normal` from 1 line into a tree. The day a command has to *decide*
//! from an answer, that crate is worth it; none of these does.
//!
//! **Which is why the exit code is about the exchange and not about the answer.** A refused
//! `arm` prints `{"error": ...}` and exits 0, because reading that field is deciding from
//! the answer. `jq -e` is the shell's way to do it in the meantime, and the day that is not
//! good enough is the day the typed protocol above gets written.
//!
//! The capability table in a `status` answer is the daemon's own, so it describes the kernel
//! the dataplane is loaded against and not whichever machine happens to run this client.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

const DEFAULT_SOCKET: &str = "/run/lorica/control.sock";

/// The daemon takes `--socket`, so this has to be movable too, and an environment variable
/// is the form that costs no argument parser. Two agents on one host — a lab machine with
/// several under test — otherwise fight over one path.
const SOCKET_VAR: &str = "LORICA_CONTROL_SOCKET";

/// Every word the daemon answers. Kept as one list because it is both the dispatch and the
/// usage line, and a usage string maintained apart from the dispatch is how a command comes
/// to exist without being documented.
const COMMANDS: [&str; 8] = [
    "status", "tiers", "rules", "arm", "disarm", "reload", "attach", "detach",
];

/// The one command with an operand, and the reason there is no argument parser here: a word
/// and an interface name are two `args()` and a `format!`, and anything that generalised
/// that would be the typed protocol this crate exists without.
const WITH_OPERAND: &str = "attach";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(word) if word == WITH_OPERAND => match args.next() {
            Some(iface) => send(&format!("{word} {iface}")),
            // Refused here rather than sent, so the message names the operand instead of the
            // daemon answering about a command it received without one.
            None => usage(&format!("{WITH_OPERAND} needs an interface name")),
        },
        Some(word) if COMMANDS.contains(&word.as_str()) => send(&word),
        _ => usage(""),
    }
}

fn usage(why: &str) -> ExitCode {
    if !why.is_empty() {
        eprintln!("lorica-ctl: {why}");
    }
    eprintln!("usage: lorica-ctl {}", COMMANDS.join("|"));
    eprintln!("       lorica-ctl {WITH_OPERAND} <iface>");
    eprintln!("socket: {} (override with {SOCKET_VAR})", socket());
    ExitCode::FAILURE
}

fn socket() -> String {
    std::env::var(SOCKET_VAR).unwrap_or_else(|_| DEFAULT_SOCKET.to_owned())
}

fn send(command: &str) -> ExitCode {
    let path = socket();
    let mut answer = String::new();
    let exchange = UnixStream::connect(&path).and_then(|mut socket| {
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
            eprintln!("no answer from {path}: {error}");
            // The agent needs CAP_BPF, so it runs as root, and it closes both the socket and
            // the directory to that user alone — anything looser would mean `arm` is
            // reachable by whoever is logged in. That is the right default and the wrong
            // thing to leave a reader guessing about, because the message alone reads like a
            // bug.
            if error.kind() == io::ErrorKind::PermissionDenied {
                eprintln!(
                    "the agent runs privileged, so the socket is 0600 and owned by the user \
                     it runs as; try again as that user"
                );
            }
            ExitCode::FAILURE
        }
    }
}
