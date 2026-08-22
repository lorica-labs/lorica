//! Detecting the hole a hot XDP attach opens in a live flow.
//!
//! A gap is measured between two consecutive *arrivals*, not between a send and
//! its reply: when the receive path stops, nothing comes back at all, and the
//! only observable is silence longer than the sending cadence explains.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapRecord {
    /// When `closed`, the sequence number that ended the silence — the packets
    /// sent during the hole may never arrive, so they cannot name it. When not
    /// `closed`, the last sequence number seen before the silence began.
    pub seq: u64,
    pub gap_ns: u64,
    /// False when the run ended while the flow was still down. `gap_ns` is then a
    /// lower bound, and the outage outlasted the measurement — a materially
    /// different outcome from one that recovered, and the one that would be lost
    /// entirely if a gap were only recorded on the arrival that ends it.
    pub closed: bool,
}

pub struct GapDetector {
    threshold_ns: u64,
    last_arrival_ns: Option<u64>,
    last_seq: u64,
    gaps: Vec<GapRecord>,
}

impl GapDetector {
    pub fn new(threshold_ns: u64) -> Self {
        Self { threshold_ns, last_arrival_ns: None, last_seq: 0, gaps: Vec::new() }
    }

    /// A sensible threshold is a small multiple of the send interval: below that,
    /// ordinary scheduling noise would be reported as an outage.
    pub fn for_rate(rate_pps: u32, multiple: u32) -> Self {
        let interval_ns = 1_000_000_000u64 / rate_pps.max(1) as u64;
        Self::new(interval_ns * multiple.max(1) as u64)
    }

    pub fn observe(&mut self, seq: u64, arrival_ns: u64) {
        if let Some(previous) = self.last_arrival_ns {
            let elapsed = arrival_ns.saturating_sub(previous);
            if elapsed > self.threshold_ns {
                self.gaps.push(GapRecord { seq, gap_ns: elapsed, closed: true });
            }
        }
        self.last_arrival_ns = Some(arrival_ns);
        self.last_seq = seq;
    }

    pub fn threshold_ns(&self) -> u64 {
        self.threshold_ns
    }

    /// `end_ns` is the moment the last frame went out, not the end of the drain
    /// window: the silence that follows the final send is expected, and counting
    /// it would put a gap on every clean run.
    pub fn finish(mut self, end_ns: u64) -> Vec<GapRecord> {
        if let Some(previous) = self.last_arrival_ns {
            let elapsed = end_ns.saturating_sub(previous);
            if elapsed > self.threshold_ns {
                self.gaps.push(GapRecord { seq: self.last_seq, gap_ns: elapsed, closed: false });
            }
        }
        self.gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_steady_stream_has_no_gaps() {
        let mut d = GapDetector::new(100);
        for i in 0..10 {
            d.observe(i, i * 50);
        }
        assert!(d.finish(450).is_empty());
    }

    #[test]
    fn the_first_arrival_cannot_open_a_gap() {
        let mut d = GapDetector::new(100);
        d.observe(0, 1_000_000);
        assert!(d.finish(1_000_050).is_empty());
    }

    #[test]
    fn silence_beyond_the_threshold_is_recorded_against_the_arrival_that_ended_it() {
        let mut d = GapDetector::new(100);
        d.observe(1, 0);
        d.observe(2, 50);
        d.observe(7, 900);
        d.observe(8, 950);
        assert_eq!(d.finish(1_000), vec![GapRecord { seq: 7, gap_ns: 850, closed: true }]);
    }

    #[test]
    fn a_gap_exactly_at_the_threshold_is_not_a_gap() {
        let mut d = GapDetector::new(100);
        d.observe(1, 0);
        d.observe(2, 100);
        assert!(d.finish(150).is_empty());
    }

    #[test]
    fn an_outage_that_outlasts_the_run_is_still_reported() {
        let mut d = GapDetector::new(100);
        d.observe(1, 0);
        d.observe(2, 50);
        // Nothing else ever comes back, and the run stops at 900.
        assert_eq!(d.finish(900), vec![GapRecord { seq: 2, gap_ns: 850, closed: false }]);
    }

    #[test]
    fn a_run_that_never_received_anything_reports_no_gap() {
        // Zero samples is already visible as sent versus samples in the summary;
        // inventing a gap here would give it a duration nothing measured.
        assert!(GapDetector::new(100).finish(10_000).is_empty());
    }

    #[test]
    fn the_rate_constructor_scales_the_threshold_to_the_cadence() {
        let d = GapDetector::for_rate(20, 3);
        assert_eq!(d.threshold_ns(), 150_000_000);
    }

    #[test]
    fn a_zero_rate_does_not_divide_by_zero() {
        assert_eq!(GapDetector::for_rate(0, 3).threshold_ns(), 3_000_000_000);
    }
}
