//! The scrape: write every handle from the snapshot, then serialise.
//!
//! **Why the output buffer is kept.** `prometheus-client` allocates nothing per series, so
//! the only allocation left in a scrape is the buffer growing into its payload — measured
//! at 188 kB of allocations to produce 71 kB of text, because a `String` that doubles
//! copies everything it has each time. A buffer allocated once and `clear()`ed between
//! scrapes removes all of it, and `clear()` keeps the capacity where `String::new()` would
//! not.
//!
//! **Why this is not a `Collector`.** `prometheus-client`'s [`Collector`] trait builds
//! `ConstCounter` and `ConstGauge` values inside `encode`, one per series per scrape, which
//! is the exact opposite of a handle resolved at startup: it would throw away the 1.5 ns
//! lookup this design is built on and register a second source of truth for the series
//! list. Registering the pre-resolved handles and writing them here buys the same property
//! the `Collector` was wanted for — nothing is instrumented in the tick, every value is
//! read from the snapshot at the moment somebody asks — with one place that knows what
//! exists.
//!
//! [`Collector`]: prometheus_client::collector::Collector

use std::{fmt, time::Instant};

use prometheus_client::{encoding::text::encode, registry::Registry};
use sketches_ddsketch::{Config, DDSketch};

use super::{Source, registry::Handles};

/// 32 kB, which holds the 66 series this registry renders with room to spare, so the first
/// scrape does not pay for the growth the module comment is about. It is a starting point
/// and not a limit: the buffer grows once if the exposition ever outgrows it, and then
/// stops.
const BUFFER: usize = 32 * 1024;

pub struct Exporter {
    registry: Registry,
    handles: Handles,
    /// Every scrape latency since start, at 9.5 ns per insertion. Read into three gauges
    /// and never exposed as a distribution: see `registry`.
    sketch: DDSketch,
    out: String,
}

impl Default for Exporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter {
    pub fn new() -> Self {
        let (registry, handles) = Handles::install();
        Self {
            registry,
            handles,
            sketch: DDSketch::new(Config::defaults()),
            out: String::with_capacity(BUFFER),
        }
    }

    /// Renders the whole exposition.
    ///
    /// The latency of *this* scrape lands in the histogram and the sketch after the text is
    /// written, so it is carried by the next scrape: a metric cannot contain the time it
    /// took to serialise itself. The quantile gauges therefore describe every scrape before
    /// this one, which is what the help text says.
    pub fn render(&mut self, source: &Source<'_>) -> Result<&str, fmt::Error> {
        let started = Instant::now();

        self.handles.write(source);
        for (gauge, quantile) in self
            .handles
            .quantiles
            .iter()
            .zip(super::registry::quantiles())
        {
            gauge.set(self.sketch.quantile(quantile).ok().flatten().unwrap_or(0.0));
        }

        self.out.clear();
        encode(&mut self.out, &self.registry)?;

        let elapsed = started.elapsed().as_secs_f64();
        self.handles.scrape.observe(elapsed);
        self.sketch.add(elapsed);

        Ok(&self.out)
    }
}
