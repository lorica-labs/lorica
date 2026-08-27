//! The agent, reduced to what makes the counter read measurable: one timer, one sweep,
//! one control socket.
//!
//! No policy is loaded and nothing is attached unless `--iface` says so. Detached stays the
//! default because the attach tax is paid on every packet whether or not anything is
//! happening — see [`attach`] for the two numbers — and attached-on-detection, which was the
//! design that came out of that measurement, is not what replaced it: detection reads the
//! counters of the program and the counters only move while it is attached, so the signal
//! that was supposed to decide the attach requires the attach. The decision is the
//! operator's, it is one flag, and the agent stays attached for as long as it runs.

mod alloc;
mod attach;
mod control;
mod enforce;
mod journal;
mod log;
mod metrics;
mod state;
mod store;
mod tick;

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use aya::{Ebpf, EbpfLoader};
use lorica_common::{
    BUCKET_KEY_SYMBOLS, Clock, CounterId, DEFAULT_SETTINGS, SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL,
    SIGNATURE_VECTORS_SYMBOL, key_words,
};
use lorica_dataplane::{
    clock, loader,
    maps::{self, batch::PerCpuU64Reader},
};
use lorica_detect::{Config as Ladder, Engine};
use lorica_policy::Mode;
use tokio::{
    runtime::Builder,
    signal::unix::{SignalKind, signal},
    time::MissedTickBehavior,
};

use crate::{
    attach::Attachment,
    enforce::{Applied, apply, withdraw},
};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

const DEFAULT_SOCKET: &str = "/run/lorica/control.sock";

const USAGE: &str = "usage: loricad --object PATH [--socket PATH] [--counters N] [--hz N] \
                     [--batch N] [--sweep-every N] [--seconds N] [--metrics ADDR|off] \
                     [--mode observe|armed] [--iface NAME]";

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
    /// Whether a refused rung is written into the list or only reported. `observe` by
    /// default, and that default is what makes the repository publishable: a tool that
    /// watches and reports cannot create the destructive false positive.
    mode: Mode,
    /// Where `/metrics` listens, or `off`. Loopback by default: the endpoint serialises the
    /// whole registry per call, so exposing it off-host is an address somebody types.
    metrics: String,
    /// The interface to attach to at startup, and to stay attached to. Absent by default,
    /// because the attach tax in [`attach`] is paid on every packet whether or not anything
    /// is happening, and nothing here can decide for the operator that it is worth paying.
    iface: Option<String>,
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
        mode: Mode::default(),
        metrics: metrics::serve::DEFAULT_ADDR.to_owned(),
        iface: None,
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
            "--metrics" => options.metrics = value()?,
            "--mode" => options.mode = value()?.parse().map_err(anyhow::Error::msg)?,
            "--iface" => options.iface = Some(value()?),
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
    // The same predicate the control socket applies to `arm`, asked here of `--mode armed`.
    // It lives next to the socket because that is the caller nobody reads a usage string
    // before using; restating it would be how the guard comes to hold on one path only.
    if options.mode == Mode::Armed {
        control::arming_allowed(options.counter_slots).map_err(anyhow::Error::msg)?;
    }
    Ok(options)
}

fn run(options: Options) -> Result<()> {
    log::init()?;
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

async fn serve(mut options: Options) -> Result<()> {
    let (ebpf, clock) = load(&options.object, options.counter_slots)?;
    // The descriptors below are duplicates and not borrows of the loaded program, and that
    // is what makes attaching possible at all: attaching needs the program mutably, at any
    // moment for as long as the agent runs, and a borrow of its maps that lives that long
    // would freeze it. A `dup` costs one syscall at startup and names the same kernel object,
    // so nothing about what is read changes.
    let counters = duplicate(ebpf, "COUNTERS")?;
    let list = duplicate(ebpf, "UNIFIED_LIST")?;
    // Two readers over the same map: one stops at the named counters, one covers every
    // slot. Each owns its buffers, sized once, so neither allocates again.
    let named = reader(
        counters,
        CounterId::COUNT,
        options.batch.min(CounterId::COUNT),
    )
    .context("building the named-counter reader failed")?;
    let full = reader(counters, options.counter_slots, options.batch)
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

    let scrapes = (options.metrics != "off")
        .then(|| metrics::serve::bind(&options.metrics))
        .transpose()
        .with_context(|| format!("cannot listen on {}", options.metrics))?;
    // Built here so the registry's one allocation per series is behind the settled count
    // below. A scrape after that allocates nothing but the growth of its output buffer.
    let mut exporter = metrics::Exporter::new();

    // The ladder that decides what goes into the list resolved above, which was resolved at
    // startup so an agent whose object has no list fails there rather than on the first
    // refusal.
    let mut engine = Engine::new(Ladder::default());
    // One slot for everything the ladder writes, the first one above the named counters.
    // Not one per entry: a slot allocator is a thing to build when something reads the
    // per-entry counters back, and nothing does yet.
    let refusals = CounterId::COUNT;
    let mut written = 0u64;
    let mut withheld = 0u64;
    let mut pulled = 0u64;
    // The key the last applied rung wrote, so a descent can take it back out instead of
    // waiting for the deadline. The deadline is the net for an agent that died; while the
    // agent is alive, leaving a refusal standing for the ten minutes of its TTL after the
    // traffic that justified it stopped is the policy being made by a timeout.
    let mut standing: Option<lorica_common::LpmKey> = None;
    // The rungs the ladder has stood on. The engine counts its transitions and keeps none,
    // and `lorica-ctl tiers` answers with a list.
    let mut tiers = control::Tiers::default();

    let period = Duration::from_micros(1_000_000 / u64::from(options.hz));
    let mut timer = tokio::time::interval(period);
    // Delay, never Burst. A late tick under attack must not be followed by a burst of
    // catch-up sweeps, which is exactly when the machine has least to spare.
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let deadline = (options.seconds > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(options.seconds));

    // Two preallocated snapshot buffers, alternated. Built before `settled` below, so the
    // two allocations it makes are startup's and the tick's difference stays a difference.
    let mut published = state::Published::default();
    let mut journal = log::Journal::default();
    // The origin of `at_ns`. Monotone since here rather than since boot: what reads it are
    // deltas between two snapshots, and an offset cancels in a delta. Anything comparing a
    // snapshot against a kernel deadline needs the jiffy base instead, which is what
    // `clock::read` is for.
    let started = Instant::now();

    // Registered once, before the loop, rather than built inside the `select!`. A future
    // built per iteration registers its handler after the signal it was meant to catch may
    // already have been delivered, and the agent then keeps running with an interface it was
    // told to give back. Both signals, because `Ctrl-C` is SIGINT and a service manager
    // sends SIGTERM, and an agent that only handles one of them leaves a hook behind under
    // the other.
    let mut interrupted = signal(SignalKind::interrupt()).context("cannot listen for SIGINT")?;
    let mut terminated = signal(SignalKind::terminate()).context("cannot listen for SIGTERM")?;

    // The attach, last of the startup and after everything that can still fail cheaply. An
    // attach that succeeds and is then followed by a failed bind would leave a program on an
    // interface nobody is watching, which is the state this whole file exists to not be in.
    let mut attached: Option<Attachment> = None;
    if let Some(iface) = options.iface.clone() {
        // Refused, not degraded. An agent that starts believing it protects an interface and
        // does not is worse than an agent that did not start: the first is a monitored
        // service reporting healthy.
        let held = attach::attach(ebpf, &iface)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("cannot attach to {iface}"))?;
        eprintln!(
            "loricad: attached to {} in native mode; every received packet goes through the \
             program from now on, at 58 % off the receive throughput and 57 % onto the \
             application p99 measured on virtio, whether or not anything is attacking",
            held.iface()
        );
        attached = Some(held);
    }

    // Every allocation of the startup is behind us at this point, so what the tick does
    // afterwards is measurable by difference.
    let settled = alloc::allocations();
    eprintln!(
        "loricad: {} counter slots, batch {}, {} Hz, full sweep every {} ticks, {} slot reads per second, socket {}, kernel clock {} Hz at jiffy {}",
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
                published.publish(&sweep, started.elapsed().as_nanos() as u64);
                // Decide from the snapshot that was just published, not from the sweep: the
                // published one is what every reader sees, so a decision taken off anything
                // else could disagree with the metric an operator is looking at.
                let decision = engine.observe(&published.read());
                tiers.note(sweep.ticks(), engine.current().rung());
                match apply(list, options.mode, &decision, refusals)
                    .context("writing a refusal into the list failed")?
                {
                    Applied::Written(key) => {
                        // A rung that moves to a different key leaves the previous one
                        // behind, so it goes out before the new one goes in.
                        if let Some(previous) = standing.replace(key).filter(|k| *k != key) {
                            withdraw(list, previous)
                                .context("withdrawing a superseded refusal failed")?;
                            pulled += 1;
                        }
                        written += 1;
                    }
                    Applied::Withheld(_) => withheld += 1,
                    Applied::Nothing => {
                        // The descent. Nothing to refuse any more, so what was refused
                        // comes back out now rather than at its deadline.
                        if let Some(previous) = standing.take() {
                            withdraw(list, previous)
                                .context("withdrawing a refusal on the descent failed")?;
                            pulled += 1;
                        }
                    }
                }
                journal.tick(&published.read(), &decision, written + withheld);
                if deadline.is_some_and(|at| tokio::time::Instant::now() >= at) {
                    eprintln!(
                        "loricad: {} ticks, {} full sweeps of {} slots, {} failed, \
                         {} snapshot buffers reallocated, {} allocations after the first sweep, \
                         rung {} in {:?} mode, {} entries written, {} withheld, {} withdrawn",
                        sweep.ticks(),
                        sweep.full_sweeps(),
                        sweep.slots(),
                        sweep.failures(),
                        published.reallocations(),
                        alloc::allocations().saturating_sub(settled),
                        engine.current().rung(),
                        options.mode,
                        written,
                        withheld,
                        pulled,
                    );
                    break;
                }
            }
            // Both signals lead to the same exit, and the exit is below the loop rather than
            // in these arms: a detach written twice is a detach that gets fixed once.
            _ = interrupted.recv() => break,
            _ = terminated.recv() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting on the control socket failed")?;
                let snapshot = snapshot(&sweep, &options, period, clock, &attached, ebpf);
                let latest = published.read();
                // Borrows, not copies: `arm` and `disarm` change the mode the next tick
                // reads and withdraw the key the descent would otherwise have taken out, so
                // a control plane holding its own copies would be a second answer to
                // whether this agent is armed.
                let mut control = control::Control {
                    mode: &mut options.mode,
                    standing: &mut standing,
                    pulled: &mut pulled,
                    written,
                    withheld,
                    stages: latest.counters.named(),
                    tiers: &tiers,
                    attached: &mut attached,
                    // Reborrowed rather than moved: the loop runs again after this.
                    ebpf: &mut *ebpf,
                };
                // Awaited rather than spawned. One client at a time is the whole protocol,
                // and a task per connection would let a slow reader hold the tick behind
                // it on a single-threaded runtime without anybody noticing.
                let _ = control::serve(stream, snapshot, &mut control).await;
            }
            scraped = metrics::serve::accept(scrapes.as_ref()) => {
                let stream = scraped.context("accepting a scrape failed")?;
                let snapshot = snapshot(&sweep, &options, period, clock, &attached, ebpf);
                // The snapshot the last tick published, held for the length of the response
                // and no longer. `load_full`, so nothing of arc-swap's is held across the
                // await below.
                let latest = published.read();
                let source = metrics::Source {
                    snapshot: &snapshot,
                    stages: latest.counters.named(),
                    log_lost: log::lost(),
                    log_folded: log::folded(),
                };
                // Awaited for the reason above, and more sharply: a scrape serialises the
                // whole registry, so a scraper that stops reading must not be able to sit
                // in front of the tick.
                let _ = metrics::serve::respond(stream, &mut exporter, &source).await;
            }
        }
    }

    // Detached before the process goes away, and reported.
    //
    // **On a kernel that has `bpf_link`, closing the process would free the hook anyway, and
    // that is not the case this exists for.** aya falls back to a netlink attach when
    // `bpf_link_create` is refused, and a netlink attach is not owned by any descriptor: the
    // program stays on the interface after the agent is gone, filtering with a policy nobody
    // can change and nobody can read. The other half is this: an agent that lets the kernel
    // tidy up never learns whether the tidying worked, so a detach that fails is a line an
    // operator reads here instead of an interface somebody finds later.
    if let Some(held) = attached.take() {
        let iface = held.iface().to_owned();
        attach::detach(ebpf, held)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("cannot detach from {iface}"))?;
        eprintln!("loricad: detached from {iface}");
    }
    Ok(())
}

/// A descriptor of one of the program's maps that outlives any borrow of the program.
///
/// [`maps::fd`] hands out a borrow, and a borrow held for the life of the agent is what
/// would make the program permanently unattachable — see the call site. The duplicate refers
/// to the same kernel object, so the map is the same map and its lifetime in the kernel is
/// now the longer of the two descriptors.
fn duplicate(ebpf: &Ebpf, name: &str) -> Result<BorrowedFd<'static>> {
    let fd = maps::fd(ebpf, name).with_context(|| format!("no {name} map in the object"))?;
    let owned = fd
        .try_clone_to_owned()
        .with_context(|| format!("cannot duplicate the descriptor of {name}"))?;
    // Leaked for the reason `load` is: this is the agent's handle on the map for as long as
    // it runs, and closing it would take the map out from under the sweep.
    let kept: &'static OwnedFd = Box::leak(Box::new(owned));
    Ok(kept.as_fd())
}

/// The counter reader, over a descriptor rather than over the program.
///
/// [`maps::counters`] is this same call and takes the program, which is the one thing that
/// cannot be borrowed here for as long as the reader lives. So the invariant it exists to
/// state once is restated once more, here, and nowhere else in this crate.
fn reader(
    fd: BorrowedFd<'static>,
    entries: u32,
    batch: u32,
) -> io::Result<PerCpuU64Reader<'static>> {
    // SAFETY: `fd` is a duplicate of the descriptor of COUNTERS, declared
    // `PerCpuArray<u64>` in lorica-ebpf, which is the map type and the eight-byte value
    // width PerCpuU64Reader requires.
    unsafe { PerCpuU64Reader::new(fd, entries, batch) }
}

/// What the agent knows about itself, for whichever of the two listeners asked.
///
/// The clock rate was measured once at startup; the jiffy is read here, because the number
/// worth publishing is the one the deadlines are being compared against at the moment
/// somebody asks. A zero is a probe that stopped answering, which no running counter can
/// be.
fn snapshot(
    sweep: &tick::Sweep,
    options: &Options,
    period: Duration,
    clock: Clock,
    attached: &Option<Attachment>,
    ebpf: &Ebpf,
) -> control::Snapshot {
    control::Snapshot {
        counter_slots: sweep.slots(),
        ticks: sweep.ticks(),
        full_sweeps: sweep.full_sweeps(),
        sweep_every: sweep.every(),
        slot_reads_per_second: sweep.slot_reads_per_second(options.hz),
        counted: sweep.counted(),
        named_counted: sweep.named_counted(),
        period_ms: period.as_millis() as u64,
        // The live value and not a constant. It was `false` in the source, which was true of
        // the agent that never attached and would have gone on reading `false` the day it
        // did — a status field whose value is written in the code that renders it answers
        // about that code and not about the agent.
        attached: attached.is_some(),
        clock: Clock {
            jiffies: clock::read(ebpf).unwrap_or(0),
            ..clock
        },
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
/// **Leaked mutably, and that is the difference from what was here before.** Attaching takes
/// the program mutably, at any moment for as long as the agent runs, so a shared `&'static`
/// would make `--iface` and the `attach` command unwritable rather than merely awkward.
///
/// The calibration happens here because it needs the program mutable, which it only is
/// before the leak, and because it sleeps: a few hundred milliseconds at startup, once,
/// where no tick is waiting on it.
fn load(object: &Path, slots: u32) -> Result<(&'static mut Ebpf, Clock)> {
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
        // The whole catalogue, because no configuration is read here yet and the program's
        // own initialiser is none of it. `Compiled::signature_vectors` is what goes here
        // once the configuration reaches this path, and the vectors it leaves out are then
        // absent from the verified program rather than skipped by it.
        .override_global(SIGNATURE_VECTORS_SYMBOL, &SIGNATURE_VECTORS_ALL, true)
        .override_global(BUCKET_KEY_SYMBOLS[0], &key[0], true)
        .override_global(BUCKET_KEY_SYMBOLS[1], &key[1], true)
        .map_max_entries("COUNTERS", slots)
        .load(&bytes)
        .with_context(|| format!("loading {} failed", object.display()))?;

    // Verified here and attached later, or never. Loading is what creates the maps, which is
    // all the counter read needs; whether the program also sees packets is `--iface`.
    let program: &mut aya::programs::Xdp = ebpf
        .program_mut(attach::PROGRAM)
        .with_context(|| format!("no program named {}", attach::PROGRAM))?
        .try_into()
        .context("the program is not an XDP program")?;
    program
        .load()
        .context("the verifier rejected the program")?;

    let clock = clock::calibrate(&mut ebpf)
        .context("cannot measure the rate of the kernel clock the deadlines are compared to")?;

    Ok((Box::leak(Box::new(ebpf)), clock))
}
