//! What a run leaves behind. Percentiles, jitter, losses, gaps — and never a mean:
//! an average latency hides the tail this probe exists to measure.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use hdrhistogram::Histogram;

use crate::gap::GapRecord;
use crate::profile::Profile;

/// One nanosecond to one hour, three significant figures.
const LOWEST_NS: u64 = 1;
const HIGHEST_NS: u64 = 3_600_000_000_000;
const SIGFIG: u8 = 3;

pub struct Percentiles {
    pub samples: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub stddev_ns: u64,
    /// p99 − p50. The number a player feels, as opposed to the one a graph shows.
    pub jitter_ns: u64,
}

pub struct Report {
    profile: Profile,
    rate_pps: u32,
    duration_s: u64,
    sent: u64,
    rtt: Histogram<u64>,
    /// Kernel receive timestamp to userspace return, on the load host. It answers
    /// "was the generator starved?" — without it, a p99 rise on the target cannot
    /// be told apart from one caused by the machine measuring it.
    kernel_delay: Histogram<u64>,
    gaps: Vec<GapRecord>,
    degraded: Option<String>,
    caveats: Vec<String>,
    env_file: Option<String>,
}

impl Report {
    pub fn new(profile: Profile, rate_pps: u32, duration_s: u64) -> Self {
        let hist = || Histogram::new_with_bounds(LOWEST_NS, HIGHEST_NS, SIGFIG).expect("valid bounds");
        Self {
            profile,
            rate_pps,
            duration_s,
            sent: 0,
            rtt: hist(),
            kernel_delay: hist(),
            gaps: Vec::new(),
            degraded: None,
            caveats: Vec::new(),
            env_file: None,
        }
    }

    pub fn record_rtt(&mut self, ns: u64) {
        self.rtt.saturating_record(ns.max(LOWEST_NS));
    }

    pub fn record_kernel_delay(&mut self, ns: u64) {
        self.kernel_delay.saturating_record(ns.max(LOWEST_NS));
    }

    pub fn set_sent(&mut self, sent: u64) {
        self.sent = sent;
    }

    pub fn set_gaps(&mut self, gaps: Vec<GapRecord>) {
        self.gaps = gaps;
    }

    /// A degraded run still writes its numbers, marked. Discarding them silently
    /// would leave no trace that the measurement was attempted at all.
    pub fn set_degraded(&mut self, reason: impl Into<String>) {
        self.degraded = Some(reason.into());
    }

    pub fn add_caveat(&mut self, caveat: impl Into<String>) {
        self.caveats.push(caveat.into());
    }

    pub fn set_env_file(&mut self, path: impl Into<String>) {
        self.env_file = Some(path.into());
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.is_some()
    }

    pub fn gaps(&self) -> &[GapRecord] {
        &self.gaps
    }

    pub fn percentiles(&self) -> Percentiles {
        percentiles_of(&self.rtt)
    }

    pub fn kernel_delay_percentiles(&self) -> Option<Percentiles> {
        (!self.kernel_delay.is_empty()).then(|| percentiles_of(&self.kernel_delay))
    }

    /// Writes the summary, and the gap list when the run recorded any. Returns
    /// every path written so a caller can name them in an index.
    pub fn write_csv(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        fs::create_dir_all(dir)?;
        let mut written = Vec::new();

        let p = self.percentiles();
        let k = self.kernel_delay_percentiles();
        let summary = dir.join(format!("{}-summary.csv", self.profile.as_str()));
        let header = "profile,rate_pps,duration_s,samples,sent,lost,gaps,\
                      p50_ns,p90_ns,p99_ns,p999_ns,max_ns,stddev_ns,jitter_ns,\
                      kernel_p50_ns,kernel_p99_ns,degraded,caveats,env_file";
        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.profile.as_str(),
            self.rate_pps,
            self.duration_s,
            p.samples,
            self.sent,
            self.sent.saturating_sub(p.samples),
            self.gaps.len(),
            p.p50_ns,
            p.p90_ns,
            p.p99_ns,
            p.p999_ns,
            p.max_ns,
            p.stddev_ns,
            p.jitter_ns,
            k.as_ref().map_or(0, |k| k.p50_ns),
            k.as_ref().map_or(0, |k| k.p99_ns),
            csv_text(self.degraded.as_deref().unwrap_or("")),
            csv_text(&self.caveats.join("; ")),
            csv_text(self.env_file.as_deref().unwrap_or("")),
        );
        fs::write(&summary, format!("{header}\n{row}\n"))?;
        written.push(summary);

        if !self.gaps.is_empty() {
            let path = dir.join(format!("{}-gaps.csv", self.profile.as_str()));
            let mut text = String::from("seq,gap_ns,closed\n");
            for g in &self.gaps {
                text.push_str(&format!("{},{},{}\n", g.seq, g.gap_ns, g.closed));
            }
            fs::write(&path, text)?;
            written.push(path);
        }

        Ok(written)
    }
}

fn percentiles_of(hist: &Histogram<u64>) -> Percentiles {
    let p50 = hist.value_at_quantile(0.50);
    let p99 = hist.value_at_quantile(0.99);
    Percentiles {
        samples: hist.len(),
        p50_ns: p50,
        p90_ns: hist.value_at_quantile(0.90),
        p99_ns: p99,
        p999_ns: hist.value_at_quantile(0.999),
        max_ns: if hist.is_empty() { 0 } else { hist.max() },
        stddev_ns: hist.stdev().round() as u64,
        jitter_ns: p99.saturating_sub(p50),
    }
}

/// Free text shares a line with numeric columns. Rather than quote it and force
/// every reader to implement CSV properly, the separators are removed: these
/// fields are read by humans, the columns beside them are read by scripts.
fn csv_text(s: &str) -> String {
    s.replace([',', '\n', '\r', '"'], ";")
}
