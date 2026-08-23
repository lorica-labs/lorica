//! The agent, reduced to what makes the counter read measurable: one timer, one sweep,
//! one control socket.
//!
//! No policy is loaded, nothing is attached, and no metric is exported. The design that
//! came out of the attach-tax measurement is detached by default and attached on
//! detection, so an agent that attached at startup would be the wrong default as well as
//! outside this phase.

mod alloc;
mod control;
mod tick;

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, EbpfLoader};
use lorica_common::{
    BUCKET_KEY_SYMBOLS, Clock, CounterId, DEFAULT_SETTINGS, SETTINGS_SYMBOL, key_words,
};
use lorica_dataplane::{clock, loader, maps};
use tokio::{runtime::Builder, time::MissedTickBehavior};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

const DEFAULT_SOCKET: &str = "/run/lorica/control.sock";
const PROGRAM: &str = "lorica_xdp";

const USAGE: &str = "usage: loricad --object PATH [--socket PATH] [--counters N] \
                     [--hz N] [--batch N] [--seconds N]";

struct Options {
    object: PathBuf,
    socket: PathBuf,
    /// Counter slots to size the map for. The named counters come first and the rest
    /// belong one to an entry of the unified list, so this is the number the agent reads
    /// every tick and the number the exit criterion is stated about.
    counter_slots: u32,
    hz: u32,
    /// Elements per `BPF_MAP_LOOKUP_BATCH` call. Exposed because it is the one knob of
    /// the read whose best value is a measurement and not a derivation.
    batch: u32,
    /// Ticks between two full sweeps of the counter map. One means every tick, which is
    /// the cadence the exit criterion is literally written about; anything above it trades
    /// freshness of the per-entry counters for CPU, and the trade is exactly linear.
    sweep_every: u64,
    /// Seconds to run before exiting. Zero runs until signalled, which is what a real
    /// agent does; a measurement wants a bound.
    seconds: u64,
}

fn main() -> ExitCode {
    match parse_options().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("loricad: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn parse_options() -> Result<Options> {
    let mut options = Options {
        object: PathBuf::new(),
        socket: PathBuf::from(DEFAULT_SOCKET),
        counter_slots: CounterId::COUNT,
        hz: 10,
        batch: 1_000,
        sweep_every: 1,
        seconds: 0,
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--object" => options.object = PathBuf::from(value()?),
            "--socket" => options.socket = PathBuf::from(value()?),
            "--counters" => options.counter_slots = value()?.parse()?,
            "--hz" => options.hz = value()?.parse()?,
            "--batch" => options.batch = value()?.parse()?,
            "--sweep-every" => options.sweep_every = value()?.parse()?,
            "--seconds" => options.seconds = value()?.parse()?,
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }
    if options.object.as_os_str().is_empty() {
        bail!("--object is required: the eBPF object is built by another toolchain\n{USAGE}");
    }
    if options.hz == 0 || options.batch == 0 || options.sweep_every == 0 {
        bail!("--hz 0 never ticks, --batch 0 reads nothing, --sweep-every 0 never sweeps");
    }
    if options.counter_slots < CounterId::COUNT {
        bail!(
            "--counters {} is below the {} named counters",
            options.counter_slots,
            CounterId::COUNT
        );
    }
    Ok(options)
}

fn run(options: Options) -> Result<()> {
    // Built by hand rather than through the attribute macro. `#[tokio::main]` spawns one
    // worker per logical CPU, which is 56 threads on a dual Xeon, and their work-stealing
    // takes cache lines from the application this agent exists to protect.
    let runtime = Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .enable_io()
        .build()
        .context("building the runtime failed")?;
    runtime.block_on(serve(options))
}

async fn serve(options: Options) -> Result<()> {
    let (ebpf, clock) = load(&options.object, options.counter_slots)?;
    // Two readers over the same map: one stops at the named counters, one covers every
    // slot. Each owns its buffers, sized once, so neither allocates again.
    let named = maps::counters(ebpf, CounterId::COUNT, options.batch.min(CounterId::COUNT))
        .context("building the named-counter reader failed")?;
    let full = maps::counters(ebpf, options.counter_slots, options.batch)
        .context("building the full-sweep reader failed")?;
    let mut sweep = tick::Sweep::new(
        named,
        full,
        CounterId::COUNT as usize,
        options.counter_slots as usize,
        options.sweep_every,
    );

    let listener = control::listen(&options.socket)
        .with_context(|| format!("cannot listen on {}", options.socket.display()))?;

    let period = Duration::from_micros(1_000_000 / u64::from(options.hz));
    let mut timer = tokio::time::interval(period);
    // Delay, never Burst. A late tick under attack must not be followed by a burst of
    // catch-up sweeps, which is exactly when the machine has least to spare.
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let deadline = (options.seconds > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(options.seconds));

    // Every allocation of the startup is behind us at this point, so what the tick does
    // afterwards is measurable by difference.
    let settled = alloc::allocations();
    eprintln!(
        "loricad: {} counter slots, batch {}, {} Hz, full sweep every {} ticks,          {} slot reads per second, socket {}, kernel clock {} Hz at jiffy {}",
        options.counter_slots,
        options.batch,
        options.hz,
        sweep.every(),
        sweep.slot_reads_per_second(options.hz),
        options.socket.display(),
        clock.hz,
        clock.jiffies,
    );

    loop {
        tokio::select! {
            _ = timer.tick() => {
                sweep.run();
                if deadline.is_some_and(|at| tokio::time::Instant::now() >= at) {
                    eprintln!(
                        "loricad: {} ticks, {} full sweeps of {} slots, {} failed, \
                         {} allocations after the first sweep",
                        sweep.ticks(),
                        sweep.full_sweeps(),
                        sweep.slots(),
                        sweep.failures(),
                        alloc::allocations().saturating_sub(settled),
                    );
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting on the control socket failed")?;
                let snapshot = control::Snapshot {
                    counter_slots: sweep.slots(),
                    ticks: sweep.ticks(),
                    full_sweeps: sweep.full_sweeps(),
                    sweep_every: sweep.every(),
                    slot_reads_per_second: sweep.slot_reads_per_second(options.hz),
                    counted: sweep.counted(),
                    named_counted: sweep.named_counted(),
                    period_ms: period.as_millis() as u64,
                    attached: false,
                    // The rate was measured once at startup; the jiffy is read here,
                    // because the number worth publishing is the one the deadlines are
                    // being compared against at the moment somebody asks. A zero is a
                    // probe that stopped answering, which no running counter can be.
                    clock: Clock {
                        jiffies: clock::read(ebpf).unwrap_or(0),
                        ..clock
                    },
                };
                // Awaited rather than spawned. One client at a time is the whole protocol,
                // and a task per connection would let a slow reader hold the tick behind
                // it on a single-threaded runtime without anybody noticing.
                let _ = control::serve(stream, snapshot).await;
            }
        }
    }
}

/// Loads and verifies the program, calibrates the clock its deadlines are written in, and
/// leaks it.
///
/// Deliberately leaked: the maps have to outlive every reader of them, and the program is
/// meant to live as long as the process. Threading a lifetime through the runtime to say
/// so would buy nothing, and dropping it early would close the map descriptors under the
/// sweep.
///
/// The calibration happens here because it needs the program mutable, which it only is
/// before the leak, and because it sleeps: a few hundred milliseconds at startup, once,
/// where no tick is waiting on it.
fn load(object: &Path, slots: u32) -> Result<(&'static Ebpf, Clock)> {
    let bytes = std::fs::read(object)
        .with_context(|| format!("cannot read the eBPF object at {}", object.display()))?;
    // Drawn here and never written down. The bucket index is chosen by whoever sends the
    // packet, so an unkeyed one would have the same collisions on every host and at every
    // boot. The two budgets keep the unconfigured initialisers of the program: reading them
    // from a configuration file is not this phase.
    let key =
        key_words(loader::draw_index_key().context("cannot draw the key of the bucket index")?);
    let mut ebpf = EbpfLoader::new()
        .override_global(SETTINGS_SYMBOL, &DEFAULT_SETTINGS, true)
        .override_global(BUCKET_KEY_SYMBOLS[0], &key[0], true)
        .override_global(BUCKET_KEY_SYMBOLS[1], &key[1], true)
        .map_max_entries("COUNTERS", slots)
        .load(&bytes)
        .with_context(|| format!("loading {} failed", object.display()))?;

    // Verified but not attached. The maps exist, which is all the counter read needs, and
    // attaching is a decision this phase does not make.
    let program: &mut aya::programs::Xdp = ebpf
        .program_mut(PROGRAM)
        .with_context(|| format!("no program named {PROGRAM}"))?
        .try_into()
        .context("the program is not an XDP program")?;
    program
        .load()
        .context("the verifier rejected the program")?;

    let clock = clock::calibrate(&mut ebpf)
        .context("cannot measure the rate of the kernel clock the deadlines are compared to")?;

    Ok((Box::leak(Box::new(ebpf)), clock))
}
