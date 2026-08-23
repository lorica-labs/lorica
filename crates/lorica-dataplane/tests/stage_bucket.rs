//! Stage 7. One leaky bucket per hashed source, in a shared lock-free bank.
//!
//! Every case that is about the verdict configures a rate of zero and a burst of *k*
//! frames. A rate of zero never drains, so exactly *k* packets fit and the *k+1*-th does
//! not, whatever the machine and whatever `CONFIG_HZ` — the clock is in jiffies and a
//! jiffy is 1 to 4 ms wide, so a burst measured against a rate would be a race between
//! the test and the tick. The one case that needs a real rate is the leak measurement, and
//! it says so.

#![cfg(feature = "kernel-tests")]

mod support;

use std::{
    collections::BTreeSet,
    env,
    sync::Mutex,
    time::{Duration, Instant},
};

use lorica_common::{DEFAULT_SETTINGS, Drain, Rate, UNITS_PER_BYTE, setting};
use support::{
    BucketGlobals, PktBuilder, TestProg, XdpAction, program, program_with_buckets,
    program_with_stalled_buckets,
};

/// 14 Ethernet, 20 IPv4, 8 UDP and this much payload.
const PAYLOAD: usize = 64;
const FRAME: u64 = 14 + 20 + 8 + PAYLOAD as u64;

/// Well above the reflection ports the signature stage knows, so a case about the buckets
/// is not quietly a case about stage 6.
const SPORT: u16 = 20_000;
const GAME_PORT: u16 = 30_120;

const ENFORCE: u32 = DEFAULT_SETTINGS | setting::ENFORCE_BUCKETS;

fn udp(src: [u8; 4], sport: u16) -> Vec<u8> {
    PktBuilder::eth()
        .ipv4()
        .src_v4(src)
        .udp(sport, GAME_PORT)
        .payload(PAYLOAD)
        .build()
}

/// A burst of exactly `frames` packets of this fixture, and nothing draining it.
fn burst_of(frames: u64) -> BucketGlobals {
    BucketGlobals::fixed(Rate {
        drain: Drain::NONE,
        burst: frames * FRAME,
    })
}

/// `10.a.b.c`, so a test can walk a source address space looking for one that lands in a
/// chosen bucket without ever leaving a documentation range.
fn v4(n: u32) -> [u8; 4] {
    [10, (n >> 16) as u8, (n >> 8) as u8, n as u8]
}

fn mapped(addr: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..].copy_from_slice(&addr);
    out
}

/// `count` source addresses that all land in the same bucket.
///
/// A loop, and the loop is the point: colliding the *index* is all a steering attack needs
/// and the bank has a four-figure number of buckets, so one candidate in a thousand lands
/// where the attacker wants it. Nobody has to find a collision of the 64-bit hash itself.
/// What keying buys is that the loop has to be run against the key of the running load and
/// its answer is worthless against the next one.
fn steered(globals: &BucketGlobals, buckets: u32, count: usize) -> Vec<[u8; 4]> {
    let target = globals.index_of(&mapped(v4(1)), buckets);
    (1u32..)
        .map(v4)
        .filter(|addr| globals.index_of(&mapped(*addr), buckets) == target)
        .take(count)
        .collect()
}

/// `count` source addresses in `count` distinct buckets.
fn spread(globals: &BucketGlobals, buckets: u32, count: usize) -> Vec<[u8; 4]> {
    let mut seen = BTreeSet::new();
    (1u32..)
        .map(v4)
        .filter(|addr| seen.insert(globals.index_of(&mapped(*addr), buckets)))
        .take(count)
        .collect()
}

fn verdicts(prog: &TestProg, packets: &[Vec<u8>]) -> Vec<XdpAction> {
    packets.iter().map(|pkt| prog.run(pkt)).collect()
}

fn dropped(verdicts: &[XdpAction]) -> usize {
    verdicts.iter().filter(|v| **v == XdpAction::Drop).count()
}

/// Under the burst, nothing is refused and nothing is counted as excess.
#[test]
fn a_source_under_its_burst_is_not_refused() {
    let prog = program_with_buckets(ENFORCE, burst_of(10));
    let packets: Vec<Vec<u8>> = (0..5).map(|_| udp([10, 90, 1, 2], SPORT)).collect();

    assert!(
        verdicts(&prog, &packets)
            .iter()
            .all(|v| *v == XdpAction::Pass)
    );
    assert_eq!(prog.counter("bucket_over_budget"), 0);
}

/// Over the burst, and only the excess.
#[test]
fn only_the_excess_over_the_burst_is_refused() {
    let prog = program_with_buckets(ENFORCE, burst_of(5));
    let packets: Vec<Vec<u8>> = (0..8).map(|_| udp([10, 90, 1, 2], SPORT)).collect();

    let seen = verdicts(&prog, &packets);
    assert_eq!(
        seen,
        vec![
            XdpAction::Pass,
            XdpAction::Pass,
            XdpAction::Pass,
            XdpAction::Pass,
            XdpAction::Pass,
            XdpAction::Drop,
            XdpAction::Drop,
            XdpAction::Drop,
        ],
        "a burst of five frames has to admit five and refuse the rest"
    );
    assert_eq!(prog.counter("bucket_over_budget"), 3);
}

/// The criterion this stage exists for. One source, twenty source ports, one bucket.
///
/// The index is a hash of the source address **alone**. Folding the source port into it
/// would give each of these twenty packets a bucket of its own and refuse none of them,
/// which is why that line in `stage/bucket.rs` says so.
#[test]
fn a_flood_spread_across_source_ports_from_one_source_is_refused() {
    let prog = program_with_buckets(ENFORCE, burst_of(5));
    let packets: Vec<Vec<u8>> = (0..20).map(|i| udp([10, 90, 1, 2], SPORT + i)).collect();

    let seen = verdicts(&prog, &packets);
    assert_eq!(
        dropped(&seen),
        15,
        "twenty packets against a burst of five, all from one source: fifteen have to go"
    );
    assert_eq!(prog.counter("bucket_over_budget"), 15);
}

/// An attacker who picks sources that share a bucket gains nothing by it.
///
/// The comparison is against the same traffic from sources that do *not* share a bucket,
/// which is the shape that gets the most through: every source brings its own burst.
/// Concentrating can only take that away, so the steered drop count has to be at least the
/// spread one — and here the spread traffic fits entirely, so the inequality is strict.
#[test]
fn steering_onto_one_bucket_does_not_lower_the_drop_rate() {
    const SOURCES: usize = 8;
    const EACH: usize = 4;

    let globals = burst_of(5);

    let steered_drops = {
        let prog = program_with_buckets(ENFORCE, globals);
        let packets: Vec<Vec<u8>> = steered(&globals, prog.bank_len(), SOURCES)
            .into_iter()
            .flat_map(|src| (0..EACH).map(move |_| udp(src, SPORT)))
            .collect();
        dropped(&verdicts(&prog, &packets))
    };
    let spread_drops = {
        let prog = program_with_buckets(ENFORCE, globals);
        let packets: Vec<Vec<u8>> = spread(&globals, prog.bank_len(), SOURCES)
            .into_iter()
            .flat_map(|src| (0..EACH).map(move |_| udp(src, SPORT)))
            .collect();
        dropped(&verdicts(&prog, &packets))
    };

    assert_eq!(
        spread_drops, 0,
        "four packets per source against a burst of five: spread traffic has to fit"
    );
    assert_eq!(
        steered_drops,
        SOURCES * EACH - 5,
        "thirty-two packets steered into one bucket with a burst of five leave five through"
    );
    assert!(steered_drops >= spread_drops);
}

/// The two response paths reach the same tier, and one counter says so.
///
/// `MARK_OVER_BUDGET` is set by the loader only where the metadata capability answers yes,
/// which the 6.8 floor of the project does not, so an operator's dashboard reads a
/// different kernel from one deployment to the next. What must not differ is what the
/// dashboard says about the same traffic: `bucket_over_budget` counts the excess either
/// way, and the excess is never served normally either way.
#[test]
fn the_same_excess_is_counted_the_same_whether_it_is_dropped_or_marked() {
    let globals = burst_of(1);
    let excess = udp([10, 90, 1, 2], SPORT);

    let dropping = program_with_buckets(ENFORCE, globals);
    assert_eq!(dropping.run(&excess), XdpAction::Pass);
    assert_eq!(dropping.run(&excess), XdpAction::Drop);

    let marking = program_with_buckets(ENFORCE | setting::MARK_OVER_BUDGET, globals);
    assert_eq!(marking.run(&excess), XdpAction::Pass);
    assert_eq!(
        marking.run(&excess),
        XdpAction::Pass,
        "with the bit set the excess reaches the stack instead of being dropped"
    );

    assert_eq!(
        dropping.counter("bucket_over_budget"),
        marking.counter("bucket_over_budget"),
        "the counter an operator reads has to say the same thing about the same traffic"
    );
    assert_eq!(dropping.counter("bucket_over_budget"), 1);
    assert_eq!(dropping.counter("bucket_marked"), 0);
    assert_eq!(marking.counter("bucket_marked"), 1);
}

/// With the bit clear the stage counts and passes, because the default mode of the product
/// is observation.
#[test]
fn the_excess_is_counted_and_passed_when_the_stage_is_not_armed() {
    let prog = program_with_buckets(DEFAULT_SETTINGS, burst_of(1));
    let excess = udp([10, 90, 1, 2], SPORT);

    assert_eq!(prog.run(&excess), XdpAction::Pass);
    assert_eq!(prog.run(&excess), XdpAction::Pass);
    assert_eq!(prog.counter("bucket_over_budget"), 1);
}

/// **The measurement.** How much the lock-free bank leaks at the operating point.
///
/// Four threads pinned one per CPU, all hammering the same bucket, against the same offered
/// total enforced by one thread. The comparison is a *rate* and not a count, because four
/// threads finish the same total in a quarter of the wall time and a leaky bucket drains
/// against wall time. The burst is four jiffies of the rate and not a handful of frames: a
/// jiffy is 1 to 4 ms wide, so a burst below one jiffy's release is what caps the
/// throughput instead of the rate, and the measurement would report the burst back to
/// itself.
///
/// **The number came out above the 2.62x the layout was retained against**, and the
/// assertion below is deliberately not armed on that figure. 2.62x was measured with four
/// cores doing nothing but the bucket update; this one runs the whole pipeline against a
/// budget two orders of magnitude below what the cores can offer, so the bucket stays
/// saturated for the whole run and every packet is a candidate for the race. The two
/// numbers do not share a denominator and one cannot gate the other.
///
/// What *does* bound this one is the thread count, and the mechanism says why. A bucket is
/// two words written separately: `last_tick` is moved to the current jiffy before `level` is
/// stored, so N CPUs that read the same `last_tick` each subtract the same tick's worth of
/// drain and only one of the stores survives — one tick can be spent up to N times. That is
/// the same N the per-CPU layout was rejected for diluting by, which makes it the honest
/// gate: the retained layout has to beat the layout it was retained over.
///
/// The printed figure is only the measurement when this case runs alone — libtest runs the
/// rest of this file on the other CPUs, which competes with the four pinned threads and
/// reads back as less contention than there is. Run it alone with
/// `--exact the_lock_free_bank_leaks_less_than_the_layout_it_was_retained_over`.
///
/// **And then do not read one run as the number.** Nine isolated runs per arm, interleaved
/// so drift could not pick a side, put this figure between **1.6 and 4.0 and bimodal** — a
/// cluster near 1.7 and another near 3.1 — on a four-vCPU guest. Single readings of 1.53,
/// 1.79, 2.98, 3.07 and 3.27 have all been taken from that same distribution and each one
/// looked like a result at the time. What reproduces is the gate, not the value: every
/// observation stays under the thread count.
///
/// One hypothesis died here and it is worth keeping. Removing the division from `charge` was
/// expected to shorten the read-modify-write window and so to *reduce* the leak — accuracy
/// and speed moving together. Measured, it went the other way: median 1.79x before the
/// change, 2.98x after. The mechanism runs backwards from the guess, because a shorter update
/// fits more updates per CPU inside one jiffy, so more CPUs land in the same window per tick
/// and one tick's drain is spent more times. **Speed buys contention here, not accuracy**,
/// and an optimisation that degrades enforcement precision is worth knowing about even when
/// the gate still holds. That mechanism is still a conjecture, and the case below is what
/// turns it into a measurement: the same leak swept over the window width it blames.
#[test]
fn the_lock_free_bank_leaks_less_than_the_layout_it_was_retained_over() {
    /// What four cores doing nothing but the update measured. Reported against, not
    /// asserted against — see above.
    const CEILING: f64 = 2.62;
    const REPEAT: u32 = 4_000_000;

    let cpus = online_cpus();
    assert!(
        cpus >= 2,
        "a contention measurement needs more than one CPU; this machine reports {cpus}"
    );
    let threads = cpus.min(4);
    let _alone = serialised();
    let (rate, _) = budget_rate();

    let one = observe(
        rate,
        Shape::Concentrated,
        1,
        0,
        REPEAT * u32::try_from(threads).unwrap(),
    );
    let many = observe(rate, Shape::Concentrated, threads, 0, REPEAT);

    let single = one.leak;
    let leak = many.leak;
    println!(
        "bucket bank on {threads} pinned CPU: one thread enforced {single:.4} of the \
         configured rate, {threads} threads enforced {leak:.4} — a leak factor of \
         {leak:.2}x against a ceiling of {CEILING:.2}x"
    );

    // Not a tolerance on the leak: a guard on the method. A single thread races nothing, so
    // anything but one here means the harness is measuring the burst, the wall clock or the
    // syscall rather than the bank.
    assert!(
        (0.5..1.5).contains(&single),
        "one thread enforced {single:.4} of the configured rate, so this measures something \
         other than the bank"
    );
    assert!(
        leak < threads as f64,
        "the bank leaked {leak:.2}x on {threads} CPU, which is the dilution the per-CPU \
         layout was rejected for: the retained layout no longer beats the one it was \
         retained over, and the layout question is open again"
    );
}

/// **The surface.** The same leak, measured as a function of the two variables it could
/// depend on: the number of contending cores `C` and the width `Δ` of the read-modify-write
/// window, in dead reads placed between the load and the store of the bucket.
///
/// This exists because a hypothesis died on a point reading and a point reading could not
/// say why. Removing the division from `charge` shortened the window and the leak went *up*,
/// median 1.79 to 2.98, which is backwards from the guess that a shorter window races less.
/// The mechanism proposed for it — a shorter update fits more updates per CPU inside one
/// jiffy, so more CPUs land in the same window per tick and one tick's drain is spent more
/// times — is a conjecture, and `Δ` is what turns it into a measurement. If the leak is a
/// function of window width, `leak(C, Δ)` is monotone in `Δ` and that pair of medians is two
/// points on a curve. If it is flat in `Δ`, the mechanism is something else, which is the
/// more interesting outcome.
///
/// **The arms.** `concentrated` puts every thread on one bucket: the attack shape the layout
/// exists to survive and the one the lock collapsed under. `uniform` gives each thread a
/// bucket of its own on a cache line of its own, which shares nothing and so says how much
/// of a concentrated figure is contention rather than harness. The denominator differs with
/// the arm and has to: every bucket the traffic touches brings a budget of its own, so the
/// leak of a uniform arm is against `C` budgets and the leak of a concentrated one against
/// one.
///
/// **Nothing here asserts a leak value**, for the reason the case above states at length: it
/// is a distribution between 1.6 and 4.0 and bimodal, and five point readings each looked
/// like a result. What is asserted is the gate — every observation under the thread count,
/// the dilution the per-CPU layout would have imposed — and the one-thread control, which is
/// what says the harness measures the bank rather than the burst or the syscall. At one
/// thread the gate degenerates (nothing races, and the control has read 0.994 to 0.996), so
/// there the control band is the assertion.
///
/// **Read the samples, not their median.** The default is three per arm and a campaign wants
/// more: the bimodality is the finding, and a median is exactly the operation that hid it.
///
/// **What the first serialised run said, on the dev guest and not on the campaign host**, so
/// this is the harness working and not the number: concentrated at four cores read 1.84 and
/// 1.39 at `Δ = 0`, 2.57 and 3.21 at 64, 3.83 and 3.84 at 1024, against a control of 0.994 to
/// 0.996 at every width and a uniform arm flat at 0.98. Monotone in `Δ`, which is the
/// direction the refuted hypothesis needs, and 64 dead reads already move the leak further
/// than the whole 1.79-to-2.98 pair it was blamed for. Two samples per point is not a
/// distribution and one guest is not a campaign; the spread inside `Δ = 0` alone, 1.39 to
/// 1.84, is why this prints samples instead of a median.
///
/// The window costs what it should and nothing when it is zero: the same object JITs to
/// 8 167 bytes at `Δ = 0` and 8 186 at any `Δ` above it — 19 bytes of loop the verifier
/// removes when the word is zero — and a packet cost 182 ns of `duration` at 0, 236 at 64 and
/// 713 at 1024, which is about one cycle per dead read.
///
/// Knobs, all optional, defaults in brackets: `LORICA_BANK_CORES` [the machine, capped at 4],
/// `LORICA_BANK_WINDOW` [0], `LORICA_BANK_SHAPES` [concentrated,uniform],
/// `LORICA_BANK_SAMPLES` [3], `LORICA_BANK_REPEAT` [1000000] packets per thread per sample.
/// Cores and windows take comma-separated lists.
///
/// Like the case above, this is only a measurement when it runs alone: libtest otherwise
/// runs the rest of the file on the CPUs the pinned threads were promised. Run it with
/// `--exact the_bank_leak_is_a_surface_over_cores_and_window`.
#[test]
fn the_bank_leak_is_a_surface_over_cores_and_window() {
    let cpus = online_cpus();
    assert!(
        cpus >= 2,
        "a contention measurement needs more than one CPU; this machine reports {cpus}"
    );
    let _alone = serialised();
    let (rate, hz) = budget_rate();

    let cores = list("LORICA_BANK_CORES", &[cpus.min(4)]);
    let windows: Vec<u32> = list("LORICA_BANK_WINDOW", &[0]);
    let samples = number("LORICA_BANK_SAMPLES", 3);
    let repeat = number("LORICA_BANK_REPEAT", 1_000_000);
    let widest = u32::try_from(*cores.iter().max().expect("no core count to sweep")).unwrap();

    for shape in shapes() {
        for &window in &windows {
            // The control first, and offered the same total as the widest arm so the burst
            // is the same fraction of the run: a short control reports the burst back as
            // enforcement. One thread races nothing, so anything but one here means the arm
            // measures the wall clock or the syscall rather than the bank.
            let control = observe(rate, shape, 1, window, repeat * widest);
            emit(shape, 1, window, 0, control.leak, hz, &control);
            assert!(
                (0.5..1.5).contains(&control.leak),
                "one thread enforced {:.4} of the configured rate at window {window}, so \
                 this arm measures something other than the bank",
                control.leak
            );

            for &threads in &cores {
                for sample in 1..=samples {
                    let seen = observe(rate, shape, threads, window, repeat);
                    emit(shape, threads, window, sample, control.leak, hz, &seen);
                    assert!(
                        threads < 2 || seen.leak < threads as f64,
                        "the bank leaked {:.2}x on {threads} CPU at window {window}, which \
                         is the dilution the per-CPU layout was rejected for: the retained \
                         layout no longer beats the one it was retained over, and the layout \
                         question is open again",
                        seen.leak
                    );
                }
            }
        }
    }
}

/// Held by each contention case for its whole run, so the two of them never overlap.
///
/// Not tidiness. libtest runs this file's cases on the very CPUs these threads are pinned
/// to, and the two measurements are seconds each: run at once, each is the other's noise.
/// Measured, and the direction is not obvious — the one-thread control read **0.1997** while
/// the other case had four threads pinned, against 0.994 alone, because a leaky bucket
/// credits a preempted offerer nothing beyond its burst, so a thread that is descheduled for
/// four fifths of the wall clock reports the bank as five times stricter than it is. The
/// seven verdict cases above are milliseconds and do not need the lock.
///
/// This is not the isolation a campaign needs. That still means one case at a time on an
/// idle machine, which is what `--exact` is for; the lock only keeps these two from ruining
/// each other in an ordinary suite run.
static CONTENTION: Mutex<()> = Mutex::new(());

/// The lock, ignoring poison: a failed measurement should report its own failure and not
/// turn the other case into a confusing panic about a mutex.
fn serialised() -> std::sync::MutexGuard<'static, ()> {
    CONTENTION.lock().unwrap_or_else(|held| held.into_inner())
}

/// 10 MB/s per bucket, far under what one core can offer through `BPF_PROG_TEST_RUN`, so the
/// enforcement binds and what gets through is what the bank let through.
const BYTES_PER_SEC: u64 = 10_000_000;

/// The `duration` field of `BPF_PROG_TEST_RUN` against the CPU time it accounts for: 128 ns
/// of `duration` for 262 ns of task-clock, measured on the campaign host, a stable factor of
/// 2.06. Ratios out of that field are sound; absolutes are about half the CPU time, so a
/// cost quoted in cycles goes through this first.
const TASK_CLOCK_PER_DURATION: f64 = 2.06;

/// Core clock of the campaign host, out of `cycles / task-clock`, no turbo. The measured
/// band is 1.875 to 1.953 GHz and this is its midpoint: the ±2 % it costs is an order below
/// the spread of the leak figures, and the line also prints `ns_per_pkt`, so a host that
/// clocks differently can redo the conversion from the same output.
const CAMPAIGN_GHZ: f64 = 1.914;

/// One source address for every concentrated thread: the same one, so the same bucket.
const HOT_SRC: [u8; 4] = [10, 90, 1, 2];

/// The rate every contention arm is measured against.
///
/// The one configuration in this file with a real drain, so the one that needs the jiffy
/// width. `Drain::per_jiffy` is the conversion the loader does, called here the same way,
/// which is the point of it living in the type: the number above stays in bytes per second
/// and nothing on the packet path multiplies. The burst is four jiffies of the rate and not
/// a handful of frames — a jiffy is 1 to 4 ms wide, so a burst below one jiffy's release
/// would cap the throughput instead of the rate and the measurement would report the burst
/// back to itself.
fn budget_rate() -> (Rate, u32) {
    let hz = program().clock().hz;
    (
        Rate {
            drain: Drain::per_jiffy(BYTES_PER_SEC, hz),
            burst: 4 * BYTES_PER_SEC / u64::from(hz),
        },
        hz,
    )
}

/// How the threads are spread over the bank.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Concentrated,
    Uniform,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Self::Concentrated => "concentrated",
            Self::Uniform => "uniform",
        }
    }

    /// Buckets the arm touches, which is the denominator of its leak: each one brings a
    /// budget of its own, so four threads on four buckets are allowed four times the bytes
    /// four threads on one are.
    fn buckets(self, threads: usize) -> usize {
        match self {
            Self::Concentrated => 1,
            Self::Uniform => threads,
        }
    }

    /// One source address per thread, chosen so the addresses land where the arm says.
    fn sources(self, globals: &BucketGlobals, bank: u32, threads: usize) -> Vec<[u8; 4]> {
        match self {
            Self::Concentrated => vec![HOT_SRC; threads],
            Self::Uniform => spread(globals, bank, threads),
        }
    }
}

/// The arms to sweep, from `LORICA_BANK_SHAPES`.
fn shapes() -> Vec<Shape> {
    let Ok(named) = env::var("LORICA_BANK_SHAPES") else {
        return vec![Shape::Concentrated, Shape::Uniform];
    };
    named
        .split(',')
        .filter(|field| !field.is_empty())
        .map(|field| match field.trim() {
            "concentrated" => Shape::Concentrated,
            "uniform" => Shape::Uniform,
            other => panic!("LORICA_BANK_SHAPES names {other}, which is no arm of this harness"),
        })
        .collect()
}

/// A comma-separated list of numbers out of the environment. A trailing comma is not an
/// error, because a campaign builds these strings in a shell loop.
fn list<T: Clone + std::str::FromStr>(var: &str, default: &[T]) -> Vec<T> {
    let Ok(value) = env::var(var) else {
        return default.to_vec();
    };
    value
        .split(',')
        .filter(|field| !field.is_empty())
        .map(|field| {
            field
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("{var} holds {value:?}, which is not a list of numbers"))
        })
        .collect()
}

fn number(var: &str, default: u32) -> u32 {
    let Ok(value) = env::var(var) else {
        return default;
    };
    value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{var} holds {value:?}, which is not a number"))
}

/// One observation of one arm.
struct Observed {
    /// Bytes the bank let through over the bytes the buckets it touched were configured for.
    /// One is enforced exactly; the thread count is the dilution per-CPU would have cost.
    leak: f64,
    /// The `duration` field of `BPF_PROG_TEST_RUN`, averaged over the threads. Not CPU time
    /// and not cycles: see [`TASK_CLOCK_PER_DURATION`].
    ns_per_pkt: f64,
    offered: u64,
    refused: u64,
    elapsed: Duration,
    /// Bytes of the program that produced this line, which is what says the widening loop
    /// is absent at `Δ = 0` rather than merely cheap.
    jited: u32,
}

/// What `threads` pinned threads got past the bank, and what the kernel charged them for it.
fn observe(rate: Rate, shape: Shape, threads: usize, window: u32, repeat: u32) -> Observed {
    let globals = BucketGlobals::fixed(rate);
    let prog = program_with_stalled_buckets(ENFORCE, globals, window);
    let packets: Vec<Vec<u8>> = shape
        .sources(&globals, prog.bank_len(), threads)
        .into_iter()
        .map(|src| udp(src, SPORT))
        .collect();

    // Warm every bucket the arm touches to its ceiling, so the burst is spent before the
    // clock starts and what is timed is the steady state.
    for pkt in &packets {
        for _ in 0..64 {
            prog.run(pkt);
        }
    }

    let before = prog.counter("bucket_over_budget");
    let start = Instant::now();
    // SAFETY-adjacent, not unsafe: `BPF_PROG_TEST_RUN` is a syscall on a shared program
    // descriptor and nothing on this side of it is mutated, which is what lets the same
    // program be hammered from several threads at once.
    let shared = Shared(&prog);
    let ns: u128 = std::thread::scope(|scope| {
        let running: Vec<_> = packets
            .iter()
            .enumerate()
            .map(|(cpu, pkt)| {
                let shared = &shared;
                let pkt = pkt.clone();
                scope.spawn(move || {
                    pin_to(cpu);
                    shared.0.ns_per_run(&pkt, repeat)
                })
            })
            .collect();
        running
            .into_iter()
            .map(|thread| thread.join().expect("a measuring thread panicked"))
            .sum()
    });
    let elapsed = start.elapsed();
    let refused = prog.counter("bucket_over_budget") - before;

    let offered = u64::from(repeat) * threads as u64;
    assert!(
        refused < offered,
        "everything offered was refused, so nothing was measured"
    );
    assert!(
        elapsed > Duration::from_millis(100),
        "the run lasted {elapsed:?}, which is too short against a jiffy"
    );

    let passed = (offered - refused) as f64 * FRAME as f64 / elapsed.as_secs_f64();
    let configured = (shape.buckets(threads) as u64 * BYTES_PER_SEC) as f64;
    Observed {
        leak: passed / configured,
        ns_per_pkt: ns as f64 / threads as f64,
        offered,
        refused,
        elapsed,
        jited: prog.jited_len(),
    }
}

/// The line a campaign parses: one per observation, space-separated `key=value`, fixed
/// field order. `cyc_per_pkt` is derived from `ns_per_pkt` through the two constants above
/// and is cycles of the campaign host; `ns_per_pkt` is the kernel's `duration` field and is
/// about half the CPU time.
fn emit(shape: Shape, cores: usize, window: u32, sample: u32, single: f64, hz: u32, o: &Observed) {
    println!(
        "bank shape={} cores={cores} window={window} sample={sample} buckets={} \
         leak={:.4} single={single:.4} ns_per_pkt={:.1} cyc_per_pkt={:.0} offered={} \
         refused={} elapsed_ms={} hz={hz} jited={}",
        shape.name(),
        shape.buckets(cores),
        o.leak,
        o.ns_per_pkt,
        o.ns_per_pkt * TASK_CLOCK_PER_DURATION * CAMPAIGN_GHZ,
        o.offered,
        o.refused,
        o.elapsed.as_millis(),
        o.jited,
    );
}

struct Shared<'a>(&'a TestProg);

// SAFETY: the only thing the threads touch is `ns_per_run`, which reads the program
// descriptor and issues a syscall. Nothing in `TestProg` is written during a run, and the
// kernel serialises nothing per descriptor that this side would have to.
unsafe impl Sync for Shared<'_> {}

fn online_cpus() -> usize {
    // SAFETY: sysconf takes an integer and returns one.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    usize::try_from(count).expect("the machine reports no online CPU")
}

/// Pins the calling thread, which is what makes four threads four CPUs rather than four
/// turns on one.
fn pin_to(cpu: usize) {
    // SAFETY: an all-zero `cpu_set_t` is a valid empty set, `CPU_SET` fills it, and a pid
    // of zero means the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set),
            0,
            "cannot pin a thread to CPU {cpu}"
        );
    }
}

/// What a packet costs its bucket: the frame length, in sub-byte units.
///
/// Every burst in this file is stated in frames, so a charge taken on the payload length
/// or on the IP total length would leave the arithmetic here self-consistent and wrong,
/// and would under-count the traffic an operator is paying for. It is also the only
/// assertion that reads the bank rather than a verdict.
#[test]
fn a_frame_costs_its_length_in_sub_byte_units() {
    let prog = program_with_buckets(DEFAULT_SETTINGS, burst_of(10));
    prog.run(&udp([10, 90, 1, 2], SPORT));

    let charged: u64 = prog.bank_levels().iter().sum();
    assert_eq!(charged, FRAME * UNITS_PER_BYTE);
}
