//! The control socket: one line of text in, one JSON document out.
//!
//! **The client shares no type with the agent, and the number that keeps it that way is
//! 1.** `lorica-ctl` writes a command word and prints the answer; it decides nothing from
//! what comes back, so it needs none of the agent's types and `cargo tree -p lorica-ctl
//! --edges normal` prints 1 line — the crate itself. The alternative is a typed protocol,
//! and it can live in neither crate: `loricad` pulls tokio, aya and redb, so the protocol
//! would cost an 8th crate in a workspace of 7 and turn that 1 line into a tree. It is
//! worth that the day the CLI has to branch on an answer. Today it prints.
//!
//! **Who can reach it.** `arm` changes what the data path does to traffic, so the
//! permissions of this socket are the whole access control of the mitigation. They are not
//! left to the umask — see [`listen`].
//!
//! **What bounds an exchange.** `main` awaits the handler on the thread the tick runs on
//! rather than spawning it, which is the right choice — a task per connection would let a
//! slow reader sit in front of the tick — and it is only safe with the two bounds below:
//! [`MAX_COMMAND`] on what a client may say and [`EXCHANGE`] on how long it may take. A
//! client that connects and says nothing is otherwise not a slow client but a stopped
//! agent.

mod handler;

// `tests/series_cap.rs` includes this module for `Snapshot` alone, so from there one of
// these three is genuinely unused. That is what the allow covers and it covers nothing else.
#[allow(unused_imports)]
pub use handler::{Control, Tiers, arming_allowed};

use std::{
    fmt::Write as _,
    fs::{self, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use lorica_common::{Clock, CounterId};
use lorica_dataplane::capability::probe;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    time::timeout,
};

/// The directory, closed before the socket exists in it.
const DIR_MODE: u32 = 0o700;
/// The socket itself, closed again after the bind. Both, because either alone leaves a
/// window: see [`listen`].
const SOCKET_MODE: u32 = 0o600;

/// Bytes a client may send before the read stops looking for a newline.
///
/// The longest command is `disarm`, 6 bytes, and 32 leaves room for a CRLF and for a word
/// nobody has written yet. The bound is not tidiness: `read_line` grows its buffer until it
/// finds a newline, so an unbounded read is a client deciding how much the agent allocates.
/// A line cut here does not match any command and is refused like any other unknown word.
const MAX_COMMAND: u64 = 32;

/// How long one exchange may take, end to end.
///
/// Public because `tests/control.rs` asserts against it: what this bounds is the tick, not
/// the client, so the number has to be readable by the case that checks it.
pub const EXCHANGE: Duration = Duration::from_secs(2);

/// Binds the socket, and closes it to everyone but the user the agent runs as.
///
/// **The permissions were the umask's, and that is a defect and not a default.** `bind`
/// creates a socket with `0777 & !umask`. Under the usual `0022` that is `0755`, which
/// happens to be owner-only — connecting to a Unix socket needs *write* permission — so the
/// old code was correct by luck. Under a unit file carrying `UMask=0000` it is `0777`, and
/// then any local account can arm and disarm the mitigation of a machine it does not
/// administer. Luck is not an access control decision, so the mode is set here.
///
/// **The directory is tightened before the bind, and that ordering is the point.** Between
/// `bind` and any `chmod` of the socket there is an instant in which the socket exists at
/// whatever the umask said; a directory that cannot be traversed closes that instant,
/// because a path nobody can walk into is a socket nobody can connect to. The `chmod` of the
/// socket is the second layer, for the case where the directory already existed and belonged
/// to somebody else — which is why a failure to tighten it is returned rather than ignored.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, Permissions::from_mode(DIR_MODE))?;
    }
    // A socket left behind by a killed agent makes bind fail with EADDRINUSE, which reads
    // as "another agent is running" when there is none. Removing it is the only way to
    // start after a crash, and a stale socket accepts nothing anyway.
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))?;
    Ok(listener)
}

/// Reads one command and answers it.
///
/// Errors are the client going away or taking longer than [`EXCHANGE`], neither of which is
/// the agent's problem, so they are returned and dropped by the caller.
pub async fn serve(
    stream: UnixStream,
    snapshot: Snapshot,
    control: &mut Control<'_>,
) -> io::Result<()> {
    timeout(EXCHANGE, exchange(stream, snapshot, control))
        .await
        .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
}

async fn exchange(
    mut stream: UnixStream,
    snapshot: Snapshot,
    control: &mut Control<'_>,
) -> io::Result<()> {
    let mut command = String::new();
    let (read, mut write) = stream.split();
    BufReader::new(read.take(MAX_COMMAND))
        .read_line(&mut command)
        .await?;

    let answer = match command.trim() {
        "status" => status_json(&snapshot, control),
        "tiers" => handler::tiers_json(control),
        "rules" => handler::rules_json(&snapshot, control),
        "arm" => handler::arm(&snapshot, control),
        "disarm" => handler::disarm(control),
        "reload" => handler::reload(),
        // Escaped as one string and not interpolated into a hand-written one. The word is a
        // third party's bytes and the answer is read by `jq`: the shorter form put the
        // client's own quotes straight into the message, which produced
        // `{"error":"unknown command "x""}` — not JSON, for every unknown word ever sent.
        other => handler::error(&format!("unknown command {other}")),
    };
    write.write_all(answer.as_bytes()).await
}

/// What the agent knows about itself at the moment a query arrives.
#[derive(Clone, Copy)]
pub struct Snapshot {
    pub counter_slots: usize,
    pub ticks: u64,
    pub full_sweeps: u64,
    pub sweep_every: u64,
    /// The number the cost of the read is linear in, so the one an operator should look
    /// at when the agent is costing more than expected.
    pub slot_reads_per_second: u64,
    pub counted: u64,
    pub named_counted: u64,
    pub period_ms: u64,
    pub attached: bool,
    /// The clock every deadline in the maps is expressed on. Published because a TTL
    /// nobody can convert back into seconds is a decision nobody can check: the rate is
    /// measured at startup and has no other interface, and the jiffy is what the data
    /// path compares against right now.
    pub clock: Clock,
}

fn status_json(snapshot: &Snapshot, control: &Control<'_>) -> String {
    let release = probe::running_release();
    let detected = probe::detect_all();

    let mut out = String::with_capacity(4096);
    out.push_str("{\n");
    let _ = writeln!(
        out,
        "  \"kernel\": {},",
        quote(&match release {
            Some((major, minor)) => format!("{major}.{minor}"),
            None => "unknown".to_owned(),
        })
    );
    let _ = writeln!(out, "  \"attached\": {},", snapshot.attached);
    let _ = writeln!(out, "  \"tick_period_ms\": {},", snapshot.period_ms);
    let _ = writeln!(out, "  \"kernel_hz\": {},", snapshot.clock.hz);
    let _ = writeln!(out, "  \"jiffies\": {},", snapshot.clock.jiffies);
    let _ = writeln!(out, "  \"counter_slots\": {},", snapshot.counter_slots);
    let _ = writeln!(out, "  \"ticks\": {},", snapshot.ticks);
    let _ = writeln!(out, "  \"full_sweeps\": {},", snapshot.full_sweeps);
    let _ = writeln!(out, "  \"sweep_every_ticks\": {},", snapshot.sweep_every);
    let _ = writeln!(
        out,
        "  \"slot_reads_per_second\": {},",
        snapshot.slot_reads_per_second
    );
    let _ = writeln!(out, "  \"counted\": {},", snapshot.counted);
    let _ = writeln!(out, "  \"named_counted\": {},", snapshot.named_counted);
    let _ = writeln!(out, "  \"rss_kib\": {},", rss_kib());
    let _ = writeln!(out, "  \"mode\": {},", quote(handler::word(*control.mode)));
    // Reported next to the mode, because "observe" answers what the agent is doing and this
    // answers whether `arm` would be accepted at all. An operator who has to try the command
    // to find out has armed a security system to read a diagnostic.
    let _ = writeln!(
        out,
        "  \"armable\": {},",
        arming_allowed(u32::try_from(snapshot.counter_slots).unwrap_or(u32::MAX)).is_ok()
    );
    let _ = writeln!(out, "  \"rung\": {},", control.tiers.rung());
    let _ = writeln!(out, "  \"written\": {},", control.written);
    let _ = writeln!(out, "  \"withheld\": {},", control.withheld);
    let _ = writeln!(out, "  \"withdrawn\": {},", control.pulled);
    let _ = writeln!(
        out,
        "  \"standing\": {},",
        match control.standing.as_ref() {
            Some(key) => quote(&handler::prefix(key.addr, key.prefix_len)),
            None => "null".to_owned(),
        }
    );
    // Rendered from the catalogue itself and not from a list written here. This repository
    // has already carried 18 names for 34 counters, and a status page is exactly where that
    // goes unnoticed.
    out.push_str("  \"stages\": {\n");
    for (index, id) in CounterId::ALL.iter().enumerate() {
        let comma = if index + 1 == CounterId::ALL.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(
            out,
            "    {}: {}{comma}",
            quote(id.name()),
            control.stages[index]
        );
    }
    out.push_str("  },\n");
    out.push_str("  \"capabilities\": [\n");
    for (index, found) in detected.iter().enumerate() {
        let row = found.cap.row();
        let comma = if index + 1 == detected.len() { "" } else { "," };
        let _ = writeln!(
            out,
            "    {{\"name\": {}, \"available\": {}, \"since\": \"{}.{}\", \
             \"decided_by\": {}, \"fallback\": {}}}{comma}",
            quote(row.name),
            found.available,
            row.since.0,
            row.since.1,
            // Which evidence answered matters more than the answer: a row decided by the
            // release number alone announces a capability nobody observed, and misses a
            // distribution backport in the other direction.
            quote(if row.symbol.is_some() {
                "kernel symbol"
            } else {
                "release number"
            }),
            quote(row.fallback)
        );
    }
    out.push_str("  ]\n}\n");
    out
}

/// Resident set size, straight from the kernel.
///
/// Read here rather than remembered, because the number that matters is the one at the
/// moment somebody asks. Note that a reading taken seconds after a large allocation
/// measures the allocator holding pages, not the agent needing them: jemalloc gives back
/// 90 % of a peak after about nine seconds on this hardware, measured.
fn rss_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .and_then(|value| value.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

/// Escapes a string into a JSON scalar. Small on purpose: the only strings here are a
/// kernel release, a capability name, a prefix, a mode and one message, and pulling a
/// serialiser in for that would be more dependency than protocol.
///
/// **Control characters are dropped rather than encoded, and one of them is why this is not
/// only a matter of taste.** A carriage return in a string a client sent has already, in
/// this project, turned one received identifier into two requests. Nothing here is parsed
/// back, so encoding would be enough, but dropping is what makes the answer byte for byte
/// free of the two characters a framing bug needs.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
