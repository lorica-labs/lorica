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
mod roster;
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

use anyhow::{Context, Result, bail, ensure};
use aya::{Ebpf, EbpfLoader};
use lorica_common::{
    BUCKET_KEY_SYMBOLS, Clock, CounterId, CounterLayout, DEFAULT_BANK_BUCKETS, DEFAULT_SETTINGS,
    OPERATOR_SETTINGS, SETTINGS_SYMBOL, SIGNATURE_VECTORS_ALL, SIGNATURE_VECTORS_SYMBOL, key_words,
    settings_word,
};
use lorica_dataplane::{
    clock, loader,
    maps::{self, Counters, bank::BankReader},
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
    roster::Roster,
};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

const DEFAULT_SOCKET: &str = "/run/lorica/control.sock";

const USAGE: &str = "usage: loricad --object PATH [--socket PATH] [--counters N] [--hz N] \
                     [--batch N] [--sweep-every N] [--bank-every N] [--sweep-stride N] [--seconds N] \
                     [--metrics ADDR|off] [--mode observe|armed] [--iface NAME]                      [--policy NAME,...] [--config PATH]";

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
    /// Ticks between two passes over the bucket bank.
    ///
    /// Ten by default, so once a second at the default rate, against the counter sweep's every
    /// tick. The bank is the candidate side of the snapshot — a level names a number and never
    /// a source, because 1 024 buckets against any realistic source count means two sources
    /// share one — so nothing built on it can confirm a refusal, and freshness buys it nothing.
    /// It also costs a syscall and 64 KiB of copy where the counter sweep costs neither.
    bank_every: u64,
    /// Ticks between two full sweeps of the counter map. One means every tick, which is
    /// the cadence the exit criterion is literally written about; anything above it trades
    /// freshness of the per-entry counters for CPU, and the trade is exactly linear.
    sweep_every: u64,
    /// Reads one full sweep is spread over. One reads the whole map in a single read, which
    /// is what the agent did before this existed; above it, each read covers `1/N` of the
    /// map and resumes where the last one stopped.
    ///
    /// It divides the worst read of a sweep where `--sweep-every` only makes them rarer, and
    /// it is the knob for the tail: the read is preemptible between elements, so the cost of
    /// one read is what a scheduling tail is measured against.
    sweep_stride: u32,
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
    /// The configuration file, or nothing. Absent is the observation default with no
    /// operator rules — which is a useful agent, and the one the quick start runs.
    ///
    /// Present, it decides everything it carries and the flags that would restate it are
    /// refused rather than merged: an operator debugging why a rule does not fire should
    /// not have to discover that a command line quietly won.
    config: Option<PathBuf>,
    /// The policy word the program is loaded with: which stages enforce, and how the
    /// parser treats IP options, ICMP and later fragments. Zero by default, which is
    /// observation — see [`lorica_common::OPERATOR_SETTINGS`] for the names.
    ///
    /// Fixed at load time and not reloadable, because the program reads it as a `.bss`
    /// global rather than a map: a word that could change under an attached program would
    /// cost a helper call on every packet that reaches a stage with a knob. Changing it is
    /// a restart, which the detached-by-default design makes cheap.
    policy: u32,
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

/// The clock the pre-load pass compiles against.
///
/// **Why there is a pass with a fake clock at all.** The counter map's size comes out of the
/// configuration and has to be known before the program is loaded, because the load is what
/// creates the map; the deadlines in the same configuration are measured against a kernel
/// jiffy counter that only a loaded program can read. That is a cycle, not an oversight.
///
/// So the file is compiled twice. This pass decides the sizes and the two load-time words and
/// reports every error, which is the pass an operator's mistake comes back from — before
/// anything is loaded. The pass after the load differs only in the clock, and only its
/// entries are used. `publish` asserts the two agree on everything else rather than trusting
/// that they must.
const PROVISIONAL_CLOCK: Clock = Clock {
    hz: 250,
    jiffies: 0,
};

/// What the configuration decides that the load needs to know.
struct Plan {
    settings: u32,
    signature_vectors: u32,
    sizes: lorica_policy::MapSizes,
    mode: Mode,
    warnings: Vec<lorica_policy::Warning>,
}

fn read_config(path: &Path) -> Result<lorica_policy::Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the configuration at {}", path.display()))?;
    lorica_policy::Config::from_toml(&text)
        .with_context(|| format!("{} is not a valid configuration", path.display()))
}

/// The clock-free half of the compile, taken from a pass against [`PROVISIONAL_CLOCK`].
fn plan(config: &lorica_policy::Config) -> Result<Plan> {
    let compiled = lorica_policy::compile(config, PROVISIONAL_CLOCK, memlock_model())
        .context("the configuration did not compile")?;
    Ok(Plan {
        settings: compiled.settings,
        signature_vectors: compiled.signature_vectors,
        sizes: compiled.sizes,
        mode: config.mode,
        warnings: compiled.warnings,
    })
}

/// The memory model of this machine, and not of the one the profile was written against.
///
/// A per-CPU map costs eight bytes per possible processor, so the same configuration is a
/// different number of megabytes on a four-thread VPS and a fifty-six-thread host. Charging
/// the reference count here would let a profile pass its own audit and overrun its budget.
fn memlock_model() -> lorica_policy::MemlockModel {
    lorica_policy::MemlockModel::for_cpus(
        aya::util::nr_cpus().map_or(lorica_policy::REFERENCE_CPUS, |cpus| cpus as u64),
    )
}

/// The rules that go into the two flat tables, in one write of the `.bss` section.
///
/// Separate from [`publish`] because the two halves of stage 3 take different shapes and are
/// filled by different code: the trie takes keyed entries with deadlines and counter indices,
/// and these tables take a snapshot built whole. Nothing here depends on the clock, so it runs
/// before the trie pass and with the plan's own compile rather than a third one.
fn publish_flat(object: &Path, ebpf: &Ebpf, config: &lorica_policy::Config) -> Result<()> {
    let compiled = lorica_policy::compile(config, PROVISIONAL_CLOCK, memlock_model())
        .context("the configuration did not compile")?;
    if compiled.flat.is_empty() {
        // Nothing to publish, and the tables are already zero: `.bss` is zeroed by the kernel
        // when the map is created, and zero is `Class24::None` — no verdict — everywhere.
        return Ok(());
    }

    let snapshot = lorica_policy::build(&compiled.flat, EXPANSION_BUDGET)
        .context("the flat blocklist did not build")?;
    let bytes = std::fs::read(object)
        .with_context(|| format!("cannot read the eBPF object at {}", object.display()))?;
    let section = maps::blocklist::Section::of(&bytes)
        .context("cannot find the blocklist tables in the object")?;
    let image = section.image(&snapshot.class24, &snapshot.oa);
    let fd = maps::fd(ebpf, maps::blocklist::SECTION).with_context(|| {
        format!(
            "the loaded program has no {} map, so the flat tables cannot be published",
            maps::blocklist::SECTION
        )
    })?;
    // SAFETY: `image` is exactly `section.bytes` long, which is the size read off the same
    // object the map was created from.
    unsafe { maps::blocklist::publish(fd, &image) }.context("writing the flat blocklist failed")?;

    eprintln!(
        "loricad: {} prefixes in the flat tables ({} keys, {} expanded, worst probe {}), one write",
        compiled.flat.len(),
        snapshot.keys,
        snapshot.expanded,
        snapshot.worst_psl
    );
    Ok(())
}

/// Keys the tables may hold that no line of the configuration named.
///
/// A `/25` is 128 of them and a `/24` with one exception inside it costs a block of up to 255,
/// so a mistyped prefix length is the cheapest way to ask for a million. Half the table is the
/// load factor the probe sequence was dimensioned for, and the builder refuses past it rather
/// than degrading quietly.
const EXPANSION_BUDGET: usize = lorica_common::blocklist::OA_MAX_KEYS / 2;

/// The operator's rules, into the unified list, against the measured clock.
///
/// Everything the file decided that does not depend on the clock was decided by [`plan`] and
/// is already in the loaded program. This pass recomputes it anyway — the compiler has one
/// entry point — and asserts that it came out the same, because the alternative is trusting
/// that a function is insensitive to an argument it takes.
fn publish(
    list: BorrowedFd<'_>,
    config: &lorica_policy::Config,
    clock: Clock,
    planned: &Plan,
) -> Result<Roster> {
    let compiled = lorica_policy::compile(config, clock, memlock_model())
        .context("the configuration compiled before the load and not after it")?;
    ensure!(
        compiled.settings == planned.settings
            && compiled.signature_vectors == planned.signature_vectors
            && compiled.sizes.counter_entries == planned.sizes.counter_entries,
        "the configuration compiled to a different program before the load than after it, so          the loaded program was sized and armed for a policy that is not the one being written"
    );

    // Written as one call each rather than merged: the operator's entries own a counter slot
    // apiece and the bogons share one, so what the file asked for stays readable in the
    // counters without subtracting a generated table from it.
    let chunk = LIST_CHUNK;
    maps::lpm::load(list, &compiled.entries, chunk).context("writing the operator rules failed")?;
    maps::lpm::load(list, &compiled.bogons, chunk).context("writing the bogon table failed")?;
    eprintln!(
        "loricad: {} operator entries and {} bogon prefixes in the list, room for {}",
        compiled.entries.len(),
        compiled.bogons.len(),
        compiled.sizes.unified_list_entries
    );
    // Built from this compile and not from a second one: the pairing has to be the one the
    // trie was actually filled with.
    Ok(Roster::from_entries(&compiled.entries))
}

/// Entries per `BPF_MAP_UPDATE_BATCH`. One thousand is the batch the counter read settled on
/// for the same reason — the syscall is the cost and the chunk amortises it — and this write
/// happens once at startup, where the number is not worth its own flag.
const LIST_CHUNK: usize = 1_000;

/// [`settings_word`] with the list of what was expected attached to its refusal.
///
/// The parsing itself is in `lorica-common`, beside the table of names, because a binary
/// crate cannot be reached from an integration test and the two would drift unchecked.
fn parse_policy(list: &str) -> Result<u32> {
    settings_word(list).map_err(|unknown| {
        let known: Vec<&str> = OPERATOR_SETTINGS.iter().map(|(name, _)| *name).collect();
        anyhow::anyhow!(
            "unknown policy {unknown}, expected one of {}",
            known.join(", ")
        )
    })
}

fn parse_options() -> Result<Options> {
    let mut options = Options {
        object: PathBuf::new(),
        socket: PathBuf::from(DEFAULT_SOCKET),
        counter_slots: CounterId::COUNT,
        hz: 10,
        batch: 1_000,
        // Five and not ten: the detector's profile cadence is 500 ms, and a slow tick that
        // sees an unchanged bank computes its loaded share at the bank's resolution rather
        // than its own. The two have to move together — see `SLOW_PERIOD_NS`.
        bank_every: 5,
        sweep_every: 1,
        sweep_stride: 1,
        seconds: 0,
        mode: Mode::default(),
        metrics: metrics::serve::DEFAULT_ADDR.to_owned(),
        iface: None,
        policy: DEFAULT_SETTINGS,
        config: None,
    };
    let mut args = std::env::args().skip(1);
    // The flags actually typed, so that `--config` can refuse the ones it would override
    // instead of silently winning or silently losing against them.
    let mut given: Vec<String> = Vec::new();
    while let Some(flag) = args.next() {
        given.push(flag.clone());
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--object" => options.object = PathBuf::from(value()?),
            "--socket" => options.socket = PathBuf::from(value()?),
            "--counters" => options.counter_slots = value()?.parse()?,
            "--hz" => options.hz = value()?.parse()?,
            "--batch" => options.batch = value()?.parse()?,
            "--sweep-every" => options.sweep_every = value()?.parse()?,
            "--bank-every" => options.bank_every = value()?.parse()?,
            "--sweep-stride" => options.sweep_stride = value()?.parse()?,
            "--seconds" => options.seconds = value()?.parse()?,
            "--metrics" => options.metrics = value()?,
            "--mode" => options.mode = value()?.parse().map_err(anyhow::Error::msg)?,
            "--iface" => options.iface = Some(value()?),
            "--policy" => options.policy = parse_policy(&value()?)?,
            "--config" => options.config = Some(PathBuf::from(value()?)),
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }
    if options.object.as_os_str().is_empty() {
        bail!("--object is required: the eBPF object is built by another toolchain\n{USAGE}");
    }
    if options.hz == 0 || options.batch == 0 || options.sweep_every == 0 {
        bail!("--hz 0 never ticks, --batch 0 reads nothing, --sweep-every 0 never sweeps");
    }
    if options.sweep_stride == 0 {
        bail!("--sweep-stride 0 would cover zero slots per read, so no pass would ever finish");
    }
    if options.counter_slots < CounterId::COUNT {
        bail!(
            "--counters {} is below the {} named counters",
            options.counter_slots,
            CounterId::COUNT
        );
    }
    // A configuration file carries all three of these, so accepting both spellings would make
    // the answer to "why is this rule not firing" depend on which one the reader looked at.
    // Refused rather than merged, and named individually: an error saying only "conflicting
    // options" leaves the operator to find which.
    if options.config.is_some() {
        for flag in ["--policy", "--counters", "--mode"] {
            if given.iter().any(|typed| typed == flag) {
                bail!(
                    "{flag} and --config both set the same thing, and the file is the one that                      can be reviewed: remove {flag} and write it in the file"
                );
            }
        }
    }
    // The same predicate the control socket applies to `arm`, asked here of `--mode armed`.
    // It lives next to the socket because that is the caller nobody reads a usage string
    // before using; restating it would be how the guard comes to hold on one path only.
    if options.mode == Mode::Armed {
        control::arming_allowed(options.counter_slots).map_err(anyhow::Error::msg)?;
    }
    Ok(options)
}

/// The bank's map name, spelled here because the agent opens it by name and the program
/// declares it by name, and a typo is a map nobody finds.
const BANK_MAP: &str = "BUCKET_BANK";

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
    // Read and compiled before anything is loaded, so a file with a bad prefix in it is a
    // refusal an operator reads at a prompt rather than after twenty megabytes of maps exist.
    let config = match &options.config {
        Some(path) => Some(read_config(path)?),
        None => None,
    };
    let plan = config.as_ref().map(plan).transpose()?;
    if let Some(plan) = &plan {
        // Everything the file decides that the load needs. `--policy`, `--counters` and
        // `--mode` were refused above, so nothing here is overwriting a typed value.
        options.policy = plan.settings;
        options.counter_slots = plan.sizes.counter_entries;
        options.mode = plan.mode;
        for warning in &plan.warnings {
            eprintln!("loricad: warning: {warning}");
        }
    }
    let vectors = plan
        .as_ref()
        .map_or(SIGNATURE_VECTORS_ALL, |plan| plan.signature_vectors);

    // Computed before the load, because the load needs it: the counter map's entry count and
    // the stripe width the program indexes it with both come from here.
    let layout = maps::counter_layout(options.counter_slots).with_context(|| {
        format!(
            "no counter layout for {} slots on this machine",
            options.counter_slots
        )
    })?;
    let (ebpf, clock) = load(&options.object, &layout, options.policy, vectors)?;
    // Before anything is attached, and in one system call. The two flat tables live in the
    // `.bss` section aya materialises as a map of one entry, so publishing a blocklist of any
    // size is one `bpf_map_update_elem` against that entry rather than one call per prefix.
    if let Some(config) = &config {
        publish_flat(&options.object, ebpf, config)?;
    }
    // The descriptors below are duplicates and not borrows of the loaded program, and that
    // is what makes attaching possible at all: attaching needs the program mutably, at any
    // moment for as long as the agent runs, and a borrow of its maps that lives that long
    // would freeze it. A `dup` costs one syscall at startup and names the same kernel object,
    // so nothing about what is read changes.
    let counters = duplicate(ebpf, maps::COUNTERS)?;
    let list = duplicate(ebpf, "UNIFIED_LIST")?;
    // The second pass, and the one whose entries are real: the clock above was measured off
    // the program that is now loaded, so a `ttl_secs` in the file becomes a deadline the data
    // path can compare against.
    // **The roster is what makes a per-entry counter evidence rather than a number.** It is
    // built from the same compile that filled the list, so the key a slot is attributed to is
    // the key the compiler gave that slot -- see `roster`. An agent with no configuration has
    // an empty one and publishes no entries, which is correct: it has no entry to attribute.
    let roster = match (&config, &plan) {
        (Some(config), Some(planned)) => publish(list, config, clock, planned)?,
        _ => Roster::default(),
    };
    // Two readers over the same map: one stops at the named counters, one covers every
    // slot. Each owns its buffers, sized once, so neither allocates again.
    //
    // Both try the mapping first and fall back to the batch walk. The failure is reported once
    // and only for the full sweep: it is the same map and the same flag, so a second line
    // would say the same thing twice, and it is the full sweep whose cost the fallback changes.
    let named = reader(
        counters,
        CounterId::COUNT,
        options.batch.min(CounterId::COUNT),
    )
    .context("building the named-counter reader failed")?;
    let full = reader(counters, options.counter_slots, options.batch)
        .context("building the full-sweep reader failed")?;
    // Read before the reader is moved into the sweep, and kept as a string: the sweep answers
    // *which* path it got and this is *why*, which is only interesting once, at startup.
    let unmapped = full.unmapped().map(ToString::to_string);
    let full = full.with_stride(options.sweep_stride);
    // The bank, on a cadence of its own. Absent rather than fatal: an agent that cannot open
    // it loses its pressure signal and keeps everything a confirmed key rests on, which is the
    // half that can refuse traffic. See `tick::Sweep`'s field for why it is read slower.
    let bank = duplicate(ebpf, BANK_MAP)
        .ok()
        // SAFETY: `BANK_MAP` is declared in the loaded program as an `ARRAY` with a four-byte
        // key and a `BANK_SLOT_BYTES` value, and the descriptor is a `dup` of that map's.
        .map(|fd| unsafe { BankReader::new(fd, DEFAULT_BANK_BUCKETS, options.batch) });
    if bank.is_none() {
        eprintln!("loricad: no {BANK_MAP} map, so the bank pressure signal is absent for this run");
    }
    let mut sweep = tick::Sweep::new(
        named,
        full,
        CounterId::COUNT as usize,
        options.counter_slots as usize,
        options.sweep_every,
        bank,
        options.bank_every,
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
        "loricad: {} counter slots striped over {} processors ({} map entries), read by {}, batch {}, {} Hz, full sweep every {} ticks over {} reads, {} slot reads per second, {} entries attributable to a key, bank every {} ticks, socket {}, kernel clock {} Hz at jiffy {}",
        options.counter_slots,
        layout.cpus,
        layout.entries(),
        if sweep.is_mapped() {
            "mmap"
        } else {
            "BPF_MAP_LOOKUP_BATCH"
        },
        options.batch,
        options.hz,
        sweep.every(),
        sweep.stride(),
        sweep.slot_reads_per_second(options.hz),
        roster.len(),
        options.bank_every,
        options.socket.display(),
        clock.hz,
        clock.jiffies,
    );
    // The fallback, named with the reason the kernel gave. Measured on the target it is a
    // factor of 52 to 78 in the cost of a sweep — and worse than the per-CPU map this replaced,
    // because a slot is now four elements of the walk instead of one. An agent that quietly
    // took it would be an agent whose CPU figure nobody can explain.
    if let Some(err) = unmapped {
        eprintln!(
            "loricad: the counter array could not be mapped, so the sweep is reading it through              BPF_MAP_LOOKUP_BATCH at 666 ns a slot against 4.2 mapped: {err}"
        );
    }
    // Said once, at startup, and not counted as a metric: it is a property of how the guest
    // was booted, so it cannot change while the agent runs and nobody can act on it from a
    // dashboard.
    if let Some((possible, online)) = maps::batch::phantom_cpus() {
        eprintln!(
            "loricad: the kernel reports {possible} possible processors and {online} online,              so every per-CPU counter carries {} slots that can never be written and every              batch read copies them anyway. Booting the guest with maxcpus equal to its vCPU              count removes the copies.",
            possible - online,
        );
    }

    loop {
        tokio::select! {
            _ = timer.tick() => {
                // The tick timed from here to the journal call below, which is the whole of
                // the periodic work: the sweep, the publication, the decision and whatever
                // the decision wrote into the list. The tail this measures is what
                // `log::health` attributes to the scheduler, the hypervisor or a faulted
                // buffer, so it has to cover the syscalls and not only the sweep.
                let tick_started = Instant::now();
                // One reading of the clock for the whole tick: the sweep stamps the slices it
                // completed with it and the publication carries it, so a slice's stamp and the
                // snapshot's `at_ns` are the same number and a rate derived from the two is
                // divided by an interval that exists.
                let at_ns = started.elapsed().as_nanos() as u64;
                sweep.run(at_ns);
                published.publish(&sweep, at_ns, &roster);
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
                journal.tick(
                    &published.read(),
                    &decision,
                    written + withheld,
                    tick_started.elapsed(),
                );
                if deadline.is_some_and(|at| tokio::time::Instant::now() >= at) {
                    eprintln!(
                        "loricad: {} ticks, {} full sweeps of {} slots, {} bank passes, {} failed, \
                         {} snapshot buffers reallocated, {} allocations after the first sweep, \
                         rung {} in {:?} mode, {} entries written, {} withheld, {} withdrawn",
                        sweep.ticks(),
                        sweep.full_sweeps(),
                        sweep.slots(),
                        sweep.bank_sweeps(),
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
fn reader(fd: BorrowedFd<'static>, slots: u32, batch: u32) -> io::Result<Counters<'static>> {
    let layout = maps::counter_layout(slots)?;
    // SAFETY: `fd` is a duplicate of the descriptor of COUNTERS, declared `Array<u64>` with
    // BPF_F_MMAPABLE in lorica-ebpf and created by `load` above from a layout computed the
    // same way, which is the map type, the value width and the entry count both readers
    // require.
    Ok(unsafe { Counters::open(fd, layout, batch) })
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
fn load(
    object: &Path,
    layout: &CounterLayout,
    policy: u32,
    vectors: u32,
) -> Result<(&'static mut Ebpf, Clock)> {
    let bytes = std::fs::read(object)
        .with_context(|| format!("cannot read the eBPF object at {}", object.display()))?;
    // Drawn here and never written down. The bucket index is chosen by whoever sends the
    // packet, so an unkeyed one would have the same collisions on every host and at every
    // boot. The two budgets keep the unconfigured initialisers of the program: reading them
    // from a configuration file is not this phase.
    let key =
        key_words(loader::draw_index_key().context("cannot draw the key of the bucket index")?);
    // The counter map is one flat array striped by processor, so its entry count and the
    // stripe width the program indexes it with are one decision. `maps::size_counters` is what
    // applies both, and it is the only thing allowed to size that map.
    let mut loader = EbpfLoader::new();
    let mut ebpf = maps::size_counters(&mut loader, layout)
        .override_global(SETTINGS_SYMBOL, &policy, true)
        // `Compiled::signature_vectors` where a configuration named some, and the whole
        // catalogue where none did. The vectors it leaves out are absent from the verified
        // program rather than skipped by it, which is why this is a load-time word.
        .override_global(SIGNATURE_VECTORS_SYMBOL, &vectors, true)
        .override_global(BUCKET_KEY_SYMBOLS[0], &key[0], true)
        .override_global(BUCKET_KEY_SYMBOLS[1], &key[1], true)
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
