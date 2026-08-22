//! The report is the only thing a measurement leaves behind, so its arithmetic is
//! checked against a distribution whose percentiles are known by construction.

use latency_probe::gap::GapRecord;
use latency_probe::profile::Profile;
use latency_probe::report::Report;

/// 1000 samples, value i+1 microseconds for i in 0..1000. The p-th percentile of
/// that ramp is p*10 microseconds, which makes every expectation below a fact
/// about the data rather than a value copied from a previous run.
fn ramp() -> Report {
    let mut report = Report::new(Profile::TcpReqResp, 20, 50);
    for i in 1..=1000u64 {
        report.record_rtt(i * 1_000);
    }
    report
}

/// Path::ends_with matches whole components, so a suffix has to be compared on
/// the file name itself.
fn named(path: &std::path::Path, suffix: &str) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(suffix))
}

fn near(got: u64, want: u64, tolerance_pct: f64) -> bool {
    let slack = (want as f64 * tolerance_pct / 100.0).max(1.0);
    (got as f64 - want as f64).abs() <= slack
}

#[test]
fn percentiles_match_a_known_ramp() {
    let p = ramp().percentiles();

    assert_eq!(p.samples, 1000);
    // HdrHistogram is bucketed: three significant figures allow 0.1% of error.
    assert!(near(p.p50_ns, 500_000, 0.2), "p50 {}", p.p50_ns);
    assert!(near(p.p90_ns, 900_000, 0.2), "p90 {}", p.p90_ns);
    assert!(near(p.p99_ns, 990_000, 0.2), "p99 {}", p.p99_ns);
    assert!(near(p.p999_ns, 999_000, 0.2), "p999 {}", p.p999_ns);
    assert!(near(p.max_ns, 1_000_000, 0.2), "max {}", p.max_ns);
}

#[test]
fn jitter_is_the_distance_between_p99_and_p50() {
    let p = ramp().percentiles();
    assert_eq!(p.jitter_ns, p.p99_ns - p.p50_ns);
}

#[test]
fn standard_deviation_matches_a_uniform_ramp() {
    // A uniform distribution over [1, n] microseconds has standard deviation
    // sqrt((n^2 - 1) / 12) microseconds, which is 288.7 us for n = 1000.
    let p = ramp().percentiles();
    assert!(near(p.stddev_ns, 288_675, 1.0), "stddev {}", p.stddev_ns);
}

#[test]
fn an_empty_report_yields_zeroes_rather_than_a_panic() {
    let p = Report::new(Profile::UdpEcho, 45, 10).percentiles();
    assert_eq!(p.samples, 0);
    assert_eq!(p.p99_ns, 0);
    assert_eq!(p.max_ns, 0);
}

#[test]
fn summary_csv_reads_back_with_the_values_it_was_written_from() {
    let dir = tempdir("summary");
    let mut report = ramp();
    report.set_sent(1010);
    report.set_env_file("env-20260101T000000Z.txt");
    report.add_caveat("no hardware timestamping on virtio");
    let expected = report.percentiles();

    let written = report.write_csv(&dir).expect("write_csv");
    let summary = written
        .iter()
        .find(|p| named(p, "tcp-reqresp-summary.csv"))
        .expect("summary file among the written files");

    let text = std::fs::read_to_string(summary).expect("read summary");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().expect("header").split(',').collect();
    let row: Vec<&str> = lines.next().expect("row").split(',').collect();
    assert_eq!(header.len(), row.len(), "header and row must have equal width");
    assert!(lines.next().is_none(), "the summary holds exactly one row");

    let field = |name: &str| -> &str {
        let i = header.iter().position(|h| *h == name).unwrap_or_else(|| panic!("no column {name}"));
        row[i]
    };

    assert_eq!(field("profile"), "tcp-reqresp");
    assert_eq!(field("samples"), "1000");
    assert_eq!(field("sent"), "1010");
    assert_eq!(field("lost"), "10");
    assert_eq!(field("p99_ns"), expected.p99_ns.to_string());
    assert_eq!(field("jitter_ns"), expected.jitter_ns.to_string());
    assert_eq!(field("env_file"), "env-20260101T000000Z.txt");
    assert!(field("caveats").contains("no hardware timestamping"));

    // A mean would be read as the headline number and hide exactly the tail this
    // whole probe exists to measure. publication.md classes it as a defect.
    assert!(!header.contains(&"mean_ns"), "the report must never carry a mean");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn gaps_are_written_to_their_own_file_only_when_there_are_gaps() {
    let dir = tempdir("gaps");

    let quiet = ramp().write_csv(&dir).expect("write_csv");
    assert!(!quiet.iter().any(|p| named(p, "-gaps.csv")));

    let mut report = ramp();
    report.set_gaps(vec![
        GapRecord { seq: 41, gap_ns: 250_000_000, closed: true },
        GapRecord { seq: 87, gap_ns: 12_000_000, closed: false },
    ]);
    let written = report.write_csv(&dir).expect("write_csv");
    let gaps = written
        .iter()
        .find(|p| named(p, "tcp-reqresp-gaps.csv"))
        .expect("gaps file");

    let text = std::fs::read_to_string(gaps).expect("read gaps");
    assert_eq!(text.lines().next(), Some("seq,gap_ns,closed"));
    assert_eq!(text.lines().count(), 3);
    assert!(text.contains("41,250000000,true"));
    assert!(text.contains("87,12000000,false"), "an unclosed gap keeps its flag");

    // The count belongs in the summary too, otherwise a reader has to open two
    // files to learn whether the run was interrupted.
    let summary = written.iter().find(|p| named(p, "-summary.csv")).expect("summary");
    let text = std::fs::read_to_string(summary).expect("read summary");
    let header: Vec<&str> = text.lines().next().unwrap().split(',').collect();
    let row: Vec<&str> = text.lines().nth(1).unwrap().split(',').collect();
    assert_eq!(row[header.iter().position(|h| *h == "gaps").unwrap()], "2");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_degraded_run_says_so_in_the_row() {
    let dir = tempdir("degraded");
    let mut report = ramp();
    report.set_degraded("clocksource is kvm-clock, not tsc");
    let written = report.write_csv(&dir).expect("write_csv");

    let summary = written.iter().find(|p| named(p, "-summary.csv")).expect("summary");
    let text = std::fs::read_to_string(summary).expect("read summary");
    let header: Vec<&str> = text.lines().next().unwrap().split(',').collect();
    let row: Vec<&str> = text.lines().nth(1).unwrap().split(',').collect();
    let degraded = row[header.iter().position(|h| *h == "degraded").unwrap()];
    assert!(degraded.contains("kvm-clock"), "degraded field was {degraded:?}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn commas_in_free_text_cannot_split_a_column() {
    let dir = tempdir("commas");
    let mut report = ramp();
    report.set_degraded("tsc unreliable, quanta fell back");
    report.add_caveat("first, second");
    let written = report.write_csv(&dir).expect("write_csv");

    let summary = written.iter().find(|p| named(p, "-summary.csv")).expect("summary");
    let text = std::fs::read_to_string(summary).expect("read summary");
    let header_width = text.lines().next().unwrap().split(',').count();
    let row_width = text.lines().nth(1).unwrap().split(',').count();
    assert_eq!(header_width, row_width, "free text must not introduce columns");

    std::fs::remove_dir_all(&dir).ok();
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("latency-probe-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}
