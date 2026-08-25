//! A bounded ring of recent top talkers, and the reason it is a ring.
//!
//! **The rank is the label, the address is an exemplar.** An address in a label *value*
//! mints a new series every time the top-N rotates, and under attack the top-N rotates
//! constantly — that churn is the first documented cause of cardinality explosions, and it
//! is worse than a large static label set because the old series stay in the index. A rank
//! is `0..CAPACITY`, known while this file is being written, so the series count does not
//! move. The address rides along as an exemplar on the rank's counter, which the scraper
//! stores next to the sample instead of in the index: an exemplar cannot create a series.
//!
//! **Why a ring rather than a sorted top-N.** The bound has to be structural. A `Vec` with
//! a `truncate` somewhere is a bound that a later commit can forget; an array of
//! `CAPACITY` slots cannot hold more than `CAPACITY` addresses however wrong the caller
//! is, which is the property the exposition needs. What is lost is the ordering — the ring
//! holds the last `CAPACITY` pushed, not the largest — and that is deliberate: ranking
//! belongs to whoever measures the traffic, and doing it here would mean this module owned
//! a comparison it cannot justify.

use std::{fmt, net::IpAddr};

use prometheus_client::encoding::{EncodeLabelSet, LabelSetEncoder};

/// How many ranks the exposition carries, and therefore how many addresses can be in
/// flight. Eight because the exemplar is a forensic hint, not a data set: an operator who
/// needs the ninth talker is asking a question the flow log answers and a metric cannot.
pub const CAPACITY: usize = 8;

/// One observed source and what it sent.
#[derive(Clone, Copy, Debug)]
pub struct Talker {
    pub source: IpAddr,
    pub packets: u64,
}

/// Written by hand rather than derived, so the address never needs a `String`.
///
/// The derive wants a field whose type implements `EncodeLabelValue`, and `IpAddr` does
/// not; formatting into a `String` first would allocate once per rank per scrape for a
/// value the encoder is about to copy anyway. Writing straight into the encoder keeps
/// [`Talker`] `Copy` and the scrape allocation-free.
impl EncodeLabelSet for Talker {
    fn encode(&self, encoder: &mut LabelSetEncoder) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        let mut label = encoder.encode_label();
        let mut key = label.encode_label_key()?;
        key.write_str("source")?;
        let mut value = key.encode_label_value()?;
        write!(value, "{}", self.source)?;
        value.finish()
    }
}

/// The last [`CAPACITY`] talkers pushed, oldest overwritten.
#[derive(Clone, Copy, Debug, Default)]
pub struct Talkers {
    slots: [Option<Talker>; CAPACITY],
    next: usize,
}

impl Talkers {
    /// Unused by the agent: what would fill this ring is whatever measures per-source
    /// traffic, and that does not exist yet. Kept because the bound it enforces is what
    /// `tests/series_cap.rs` proves, and the test is the only caller.
    #[allow(dead_code, reason = "no producer of top talkers in the agent yet")]
    pub fn push(&mut self, talker: Talker) {
        self.slots[self.next] = Some(talker);
        self.next = (self.next + 1) % CAPACITY;
    }

    /// The talker at a rank, or nothing when fewer than [`CAPACITY`] have been seen. A
    /// missing talker still renders its rank, at zero: a rank that vanished from the
    /// exposition would be a series appearing and disappearing with the traffic, which is
    /// the churn this whole file exists to avoid.
    pub fn get(&self, rank: usize) -> Option<Talker> {
        self.slots.get(rank).copied().flatten()
    }
}
