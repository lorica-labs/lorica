//! The cardinality guard, counted rather than asserted.
//!
//! The agent side of `/metrics` is free and the server side is not: at 200 series a scrape
//! costs 30 µs, and at 100 000 series a PromQL query over four days does not come back
//! inside the 60 s timeout. So the number worth defending is the count of series this
//! endpoint can ever emit, and the only defence that survives maintenance is one that
//! recomputes it.
//!
//! **Why the count is encoded and not added up here.** A list of metric names written in a
//! test goes stale silently — it has happened twice in this tree, once with eighteen
//! counters named against thirty-four real ones. So both tests below render the registry
//! for real and read the answer out of the exposition text: the first counts sample lines
//! against a hard cap, the second extracts every label *name* that actually appears and
//! refuses the attacker-facing ones. Neither knows what the metrics are called.
//!
//! The modules under test are pulled in by path because `loricad` is a binary and an
//! integration test cannot reach into a binary. Including the source rather than copying it
//! is the whole point: what is counted is the registry the agent serves.

#[path = "../src/control/mod.rs"]
#[allow(dead_code)]
mod control;

// Included because `control` reaches for it — `disarm` withdraws what arming wrote — and a
// module pulled in by path brings its own edges with it, the way `tick_budget.rs` has to
// include both the state and the tick. Nothing here is counted; only `control::Snapshot` is.
#[path = "../src/enforce/mod.rs"]
#[allow(dead_code, unused_imports)]
mod enforce;

#[path = "../src/metrics/mod.rs"]
#[allow(dead_code)]
mod metrics;

use lorica_common::Clock;

use metrics::{Exporter, Source};

/// The ceiling, in series, and it is a number rather than a formula on purpose: a formula
/// would move with whatever the code does and stop being a decision.
///
/// Fifty-eight series are rendered today, thirty-four of them the named counters of
/// `CounterId`. The margin above is room for that list to reach forty and nothing else —
/// any label added to any metric here lands past it.
///
/// **It was 72 against 66 until the top-talker ranks were deleted.** Keeping 72 against 58
/// would have turned six slots of headroom into fourteen, which is enough for a whole label
/// family to arrive unnoticed: a ceiling left above the truth hides exactly what it was
/// written to catch. Six is the number that was argued, so six is what it keeps.
const SERIES_CAP: usize = 64;

/// Label names an attacker picks the value of. Each one is a documented cardinality
/// explosion: the defender's TSDB grows as fast as the attacker rotates sources.
const FORBIDDEN: [&str; 4] = ["src_ip", "sport", "flow_id", "asn"];

/// A snapshot with nothing zero in it, so a series that is only present when its value is
/// non-zero still shows up in the count.
fn snapshot() -> control::Snapshot {
    control::Snapshot {
        counter_slots: 50_000,
        ticks: 1_200,
        full_sweeps: 12,
        sweep_every: 100,
        slot_reads_per_second: 5_340,
        counted: 987_654_321,
        named_counted: 4_321,
        period_ms: 100,
        attached: true,
        clock: Clock {
            hz: 250,
            jiffies: 9_876_543,
        },
    }
}

fn stages() -> Vec<u64> {
    (0..lorica_common::CounterId::ALL.len() as u64)
        .map(|i| 7 + i * 13)
        .collect()
}

fn render() -> String {
    let snapshot = snapshot();
    let stages = stages();
    let mut exporter = Exporter::new();
    let source = Source {
        snapshot: &snapshot,
        stages: &stages,
    };
    // Rendered twice: the quantile gauges are fed from the sketch of the scrapes before
    // this one, so a single render would leave them at zero and hide three series.
    exporter.render(&source).expect("first render");
    exporter.render(&source).expect("second render").to_owned()
}

/// A sample line is any line the exposition does not begin with `#`, and the blank line
/// does not exist in this format.
fn sample_lines(exposition: &str) -> Vec<&str> {
    exposition
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect()
}

/// Every label name that appears anywhere in the exposition, read out of the text.
///
/// Both places count: the braces of a sample line, and the `# {…}` of an exemplar, which is
/// the one an address is allowed to reach. Values are skipped by their quotes, so a value
/// containing `=` or `,` cannot be mistaken for a name.
fn label_names(exposition: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in exposition.lines() {
        let bytes = line.as_bytes();
        let mut i = 0;
        let mut inside = false;
        let mut name = String::new();
        while i < bytes.len() {
            match bytes[i] {
                b'{' => {
                    inside = true;
                    name.clear();
                }
                b'}' if inside => inside = false,
                b'=' if inside => {
                    if !name.is_empty() && !names.contains(&name) {
                        names.push(name.clone());
                    }
                    name.clear();
                    // Skip the quoted value whole, escapes included.
                    if bytes.get(i + 1) == Some(&b'"') {
                        i += 2;
                        while i < bytes.len() && bytes[i] != b'"' {
                            i += if bytes[i] == b'\\' { 2 } else { 1 };
                        }
                    }
                }
                b',' if inside => name.clear(),
                c if inside && (c.is_ascii_alphanumeric() || c == b'_') => name.push(c as char),
                _ => {}
            }
            i += 1;
        }
    }
    names.sort();
    names
}

#[test]
fn series_stay_under_the_cap() {
    let exposition = render();
    let series = sample_lines(&exposition).len();
    println!("rendered series: {series} (cap {SERIES_CAP})");
    println!("exposition bytes: {}", exposition.len());
    assert!(
        series <= SERIES_CAP,
        "{series} series rendered, cap is {SERIES_CAP}. A label was added to a metric, or a \
         label took a value nobody counted at compile time. The names rendered are:\n{}",
        sample_lines(&exposition).join("\n")
    );
}

#[test]
fn no_label_is_named_after_something_an_attacker_picks() {
    let exposition = render();
    let names = label_names(&exposition);
    println!("label names rendered: {names:?}");
    for forbidden in FORBIDDEN {
        assert!(
            !names.iter().any(|name| name == forbidden),
            "label {forbidden:?} is exposed. Its value is chosen by whoever sends the \
             packet, so the series count of this endpoint becomes the attacker's to set. \
             Labels rendered: {names:?}"
        );
    }
}

/// The endpoint over a real socket, because the count that matters is the one a scraper
/// sees. The agent itself cannot be started here: it needs an eBPF object and CAP_BPF, so
/// what is bound is the same `serve` the agent binds.
#[test]
fn http_scrape_counts_the_same_series() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let body = runtime.block_on(async {
        let listener = metrics::serve::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");

        let served = tokio::spawn(async move {
            let snapshot = snapshot();
            let stages = stages();
            let mut exporter = Exporter::new();
            let source = Source {
                snapshot: &snapshot,
                stages: &stages,
            };
            for _ in 0..2 {
                let stream = metrics::serve::accept(Some(&listener))
                    .await
                    .expect("accept");
                metrics::serve::respond(stream, &mut exporter, &source)
                    .await
                    .expect("respond");
            }
        });

        let mut body = String::new();
        for _ in 0..2 {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("request");
            body.clear();
            stream.read_to_string(&mut body).await.expect("response");
        }
        served.await.expect("server task");
        body
    });

    let (head, payload) = body.split_once("\r\n\r\n").expect("headers end");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "response head: {head}");

    let exposed = payload
        .lines()
        .filter(|line| line.starts_with("lorica_"))
        .count();
    println!("HTTP GET /metrics -> lines matching ^lorica_ : {exposed}");
    assert_eq!(
        exposed,
        sample_lines(payload).len(),
        "every sample line must carry the prefix, otherwise the count above is not the \
         series count"
    );
    assert!(exposed <= SERIES_CAP, "{exposed} series over HTTP");
}
