//! Every series this agent can emit, resolved once at startup.
//!
//! **Why the handles are resolved here and not at the scrape.**
//! `Family::get_or_create()` costs 40 ns, because it hashes the label set and takes a
//! lock; a counter already resolved costs 1.5 ns. The expensive part was never the
//! increment, it was finding out which series the increment belongs to. Since the label
//! sets are all known while this file is being written — that is the whole cardinality
//! rule — the lookup can be done once and the answer kept. Which is also why this module
//! is the list of everything the endpoint can ever render: a series absent from
//! [`Handles::install`] has no handle and cannot appear.
//!
//! **Classic histogram buckets, eight of them, by default.** Native histograms cut the
//! cardinality of a latency distribution by roughly twenty, and the Prometheus text format
//! has no field for them and never will — `prometheus-client`'s text encoder falls back to
//! the classic buckets and rejects a native-only histogram outright with a `fmt::Error`.
//! For a project whose argument is "it runs on your VPS", the text endpoint is the product,
//! so native histograms are behind the `native-histograms` Cargo feature and never the
//! default. With the feature on, the histogram carries both representations: the text
//! endpoint keeps working and a protobuf scraper gets the native buckets.
//!
//! **Three gauges instead of a summary.** The quantiles come from a DDSketch — 9.5 ns per
//! insertion, and mergeable, which a `t-digest` of the same accuracy is not — and only
//! q50, q90 and q99 are exposed. Not as a `summary`: quantiles are not aggregatable, so a
//! `summary` invites an operator to average q99 across three agents and get a number that
//! means nothing. Three named gauges say what they are and nothing more.

use std::sync::atomic::{AtomicU64, Ordering};

use lorica_common::CounterId;
use prometheus_client::{
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

use super::Source;

/// One label, one value, and the value is a compile-time constant in every family below.
type Label<V> = [(&'static str, V); 1];

/// How many named counters the exposition carries. Read from `lorica-common`, never
/// written down here: a copy of this number is a copy that goes stale the next time a
/// stage is added.
const STAGES: usize = CounterId::ALL.len();

/// Exposed quantiles, paired with the label value that names them so the two cannot drift.
const QUANTILES: [(&str, f64); 3] = [("0.5", 0.5), ("0.9", 0.9), ("0.99", 0.99)];

/// Upper bounds of the scrape-latency histogram, in seconds. Seven, because
/// `Histogram::new` appends `+Inf` and eight rendered buckets is the budget. Centred on the
/// 30 µs a 200-series scrape was measured at, and stretched to 100 ms because the failure
/// this histogram exists to show is a registry that grew, which moves the scrape by orders
/// of magnitude and not by percent.
const SCRAPE_BUCKETS: [f64; 7] = [25e-6, 50e-6, 100e-6, 250e-6, 1e-3, 10e-3, 100e-3];

/// A gauge whose value is not a whole number.
type Real = Gauge<f64, AtomicU64>;

/// Every handle, resolved. Nothing here is looked up by name after startup.
pub struct Handles {
    /// Indexed by `CounterId::index()`.
    stages: [Counter; STAGES],
    ticks: Counter,
    full_sweeps: Counter,
    counted: Counter,
    named_counted: Counter,
    counter_slots: Gauge,
    sweep_every: Gauge,
    slot_reads_per_second: Gauge,
    tick_period_seconds: Real,
    attached: Gauge,
    kernel_hz: Gauge,
    kernel_jiffies: Gauge,
    pub scrape: Histogram,
    /// In the order of [`QUANTILES`].
    pub quantiles: [Real; 3],
}

impl Handles {
    /// Creates every series and hands back the registry they live in.
    ///
    /// The two are returned together because they are only correct together: a handle that
    /// was not registered writes into nothing, and a registration whose handle was dropped
    /// renders a series frozen at zero.
    pub fn install() -> (Registry, Self) {
        let mut registry = Registry::with_prefix("lorica");

        let stage_family = Family::<Label<&'static str>, Counter>::default();
        registry.register(
            "stage_events",
            "Packets accounted to each pipeline stage, by named counter",
            stage_family.clone(),
        );
        let stages = std::array::from_fn(|index| {
            stage_family.get_or_create_owned(&[("counter", CounterId::ALL[index].name())])
        });

        let quantile_family = Family::<Label<&'static str>, Real>::default();
        registry.register(
            "metrics_scrape_duration_quantile_seconds",
            "Scrape latency quantiles, from a DDSketch of every scrape before this one",
            quantile_family.clone(),
        );
        let quantiles = std::array::from_fn(|i| {
            quantile_family.get_or_create_owned(&[("quantile", QUANTILES[i].0)])
        });

        let handles = Self {
            stages,
            ticks: counter(&mut registry, "agent_ticks", "Sweep ticks since start"),
            full_sweeps: counter(
                &mut registry,
                "agent_full_sweeps",
                "Sweeps that read every slot of the counter map",
            ),
            counted: counter(
                &mut registry,
                "agent_counted",
                "Sum over every slot of the counter map at the last full sweep",
            ),
            named_counted: counter(
                &mut registry,
                "agent_named_counted",
                "Sum over the named counters at the last tick",
            ),
            counter_slots: gauge(
                &mut registry,
                "agent_counter_slots",
                "Slots the counter map is sized for",
            ),
            sweep_every: gauge(
                &mut registry,
                "agent_sweep_every_ticks",
                "Ticks between two full sweeps",
            ),
            slot_reads_per_second: gauge(
                &mut registry,
                "agent_slot_reads_per_second",
                "Slot reads per second, the number the read cost is linear in",
            ),
            tick_period_seconds: real(
                &mut registry,
                "agent_tick_period_seconds",
                "Period of the one timer the agent runs",
            ),
            attached: gauge(
                &mut registry,
                "agent_attached",
                "1 when the XDP program is attached to an interface",
            ),
            kernel_hz: gauge(
                &mut registry,
                "agent_kernel_hz",
                "Measured rate of the kernel clock every map deadline is expressed on",
            ),
            kernel_jiffies: gauge(
                &mut registry,
                "agent_kernel_jiffies",
                "The jiffy the data path is comparing deadlines against right now",
            ),
            scrape: scrape_histogram(),
            quantiles,
        };
        registry.register(
            "metrics_scrape_duration_seconds",
            "Time spent serialising this registry, excluding the scrape being served",
            handles.scrape.clone(),
        );

        (registry, handles)
    }

    /// Writes every handle from the snapshot. Called once per scrape and nowhere else.
    pub fn write(&self, source: &Source<'_>) {
        let snapshot = source.snapshot;

        for (index, stage) in self.stages.iter().enumerate() {
            store(stage, source.stages.get(index).copied().unwrap_or(0));
        }
        store(&self.ticks, snapshot.ticks);
        store(&self.full_sweeps, snapshot.full_sweeps);
        store(&self.counted, snapshot.counted);
        store(&self.named_counted, snapshot.named_counted);

        self.counter_slots.set(snapshot.counter_slots as i64);
        self.sweep_every.set(snapshot.sweep_every as i64);
        self.slot_reads_per_second
            .set(snapshot.slot_reads_per_second as i64);
        self.tick_period_seconds
            .set(snapshot.period_ms as f64 / 1_000.0);
        self.attached.set(i64::from(snapshot.attached));
        self.kernel_hz.set(i64::from(snapshot.clock.hz));
        self.kernel_jiffies.set(snapshot.clock.jiffies as i64);
    }
}

/// A counter written from a snapshot rather than incremented.
///
/// `Counter` has no `set`, on the grounds that a counter should be incremented where the
/// event happens. These totals are the kernel's, read out of a per-CPU map, so the only
/// correct write is the whole value — and monotonicity, the property `set` would otherwise
/// endanger, is guaranteed by the map rather than by this call.
fn store(counter: &Counter, value: u64) {
    counter.inner().store(value, Ordering::Relaxed);
}

fn counter(registry: &mut Registry, name: &str, help: &str) -> Counter {
    let metric = Counter::default();
    registry.register(name, help, metric.clone());
    metric
}

fn gauge(registry: &mut Registry, name: &str, help: &str) -> Gauge {
    let metric = Gauge::default();
    registry.register(name, help, metric.clone());
    metric
}

fn real(registry: &mut Registry, name: &str, help: &str) -> Real {
    let metric = Real::default();
    registry.register(name, help, metric.clone());
    metric
}

#[cfg(not(feature = "native-histograms"))]
fn scrape_histogram() -> Histogram {
    Histogram::new(SCRAPE_BUCKETS)
}

/// Classic *and* native, never native alone: the text encoder rejects a histogram with no
/// classic buckets, and the text endpoint is what this project ships.
#[cfg(feature = "native-histograms")]
fn scrape_histogram() -> Histogram {
    use prometheus_client::metrics::histogram::{
        DEFAULT_NATIVE_HISTOGRAM_BUCKET_FACTOR, NativeHistogramConfig,
    };

    Histogram::new_classic_and_native(
        SCRAPE_BUCKETS,
        NativeHistogramConfig::new(DEFAULT_NATIVE_HISTOGRAM_BUCKET_FACTOR),
    )
}

/// The quantiles to read out of the sketch, in the order of [`Handles::quantiles`].
pub const fn quantiles() -> [f64; 3] {
    [QUANTILES[0].1, QUANTILES[1].1, QUANTILES[2].1]
}
