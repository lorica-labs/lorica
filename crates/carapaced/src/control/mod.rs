//! The control socket. One command, `status`, and the answer is JSON.
//!
//! The client shares no type with the agent: it sends a line and prints what comes back.
//! A typed protocol would need a crate of its own to keep tokio and redb out of the CLI,
//! and there is nothing yet for the CLI to decide from the answer.

use std::{fmt::Write as _, fs, io, path::Path};

use carapace_dataplane::capability::probe;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub fn listen(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // A socket left behind by a killed agent makes bind fail with EADDRINUSE, which reads
    // as "another agent is running" when there is none. Removing it is the only way to
    // start after a crash, and a stale socket accepts nothing anyway.
    let _ = fs::remove_file(path);
    UnixListener::bind(path)
}

/// Reads one command and answers it. Errors are the client going away, which is not the
/// agent's problem, so they are returned and dropped by the caller.
pub async fn serve(mut stream: UnixStream, snapshot: Snapshot) -> io::Result<()> {
    let mut command = String::new();
    let (read, mut write) = stream.split();
    BufReader::new(read).read_line(&mut command).await?;

    let answer = match command.trim() {
        "status" => status_json(&snapshot),
        other => format!("{{\"error\":\"unknown command {}\"}}\n", quote(other)),
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
}

fn status_json(snapshot: &Snapshot) -> String {
    let release = probe::running_release();
    let detected = probe::detect_all();

    let mut out = String::with_capacity(2048);
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
/// kernel release, a capability name and a reference path, and pulling a serialiser in
/// for three shapes would be more dependency than protocol. Control characters are
/// dropped rather than encoded, since none can legitimately appear.
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
