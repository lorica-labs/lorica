use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use latency_probe::clock::Clock;
use latency_probe::profile::{self, LoadArgs, Profile};

#[derive(Parser)]
#[command(about = "Application latency under load, with its own metrology written down")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Echo traffic back. Runs on the measurement target.
    Serve {
        #[arg(long, value_enum)]
        profile: Profile,
        #[arg(long)]
        bind: SocketAddr,
    },
    /// Generate legitimate traffic and record what came back.
    Load {
        #[arg(long, value_enum)]
        profile: Profile,
        #[arg(long)]
        target: SocketAddr,
        /// Defaults to the cadence of the profile.
        #[arg(long)]
        rate: Option<u32>,
        #[arg(long)]
        duration: u64,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        gap_detect: bool,
        /// Silence worth this many send intervals counts as a hole.
        #[arg(long, default_value_t = 3)]
        gap_multiple: u32,
        /// Path of the record written by scripts/lab/capture-env.sh, cited in the
        /// summary so a result can never be separated from its environment.
        #[arg(long)]
        env: Option<String>,
    },
    /// Prove the probe measures what it claims, on loopback, before it is trusted.
    SelfTest {
        #[arg(long, default_value_t = 1000)]
        max_p99_us: u64,
        #[arg(long, default_value_t = 5)]
        duration: u64,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Serve { profile, bind } => match profile::serve(profile, bind) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("serve: {e}")),
        },
        Command::Load { profile, target, rate, duration, out, gap_detect, gap_multiple, env } => {
            let clock = Clock::calibrated();
            report_clock(&clock);
            let args = LoadArgs {
                target,
                rate_pps: rate.unwrap_or_else(|| profile.default_rate_pps()),
                duration_s: duration,
                gap_detect,
                gap_multiple,
                env_file: env,
            };
            match profile::load(profile, &args, &clock) {
                Ok(report) => match report.write_csv(&out) {
                    Ok(paths) => {
                        let p = report.percentiles();
                        println!(
                            "samples {} gaps {} p50 {} us p99 {} us p99.9 {} us max {} us jitter {} us",
                            p.samples,
                            report.gaps().len(),
                            p.p50_ns / 1000,
                            p.p99_ns / 1000,
                            p.p999_ns / 1000,
                            p.max_ns / 1000,
                            p.jitter_ns / 1000,
                        );
                        for path in paths {
                            println!("{}", path.display());
                        }
                        // A degraded run is written, then reported as a failure, so
                        // a campaign script stops instead of collecting bad numbers.
                        if report.is_degraded() { ExitCode::FAILURE } else { ExitCode::SUCCESS }
                    }
                    Err(e) => fail(format!("write: {e}")),
                },
                Err(e) => fail(format!("load: {e}")),
            }
        }
        Command::SelfTest { max_p99_us, duration } => self_test(max_p99_us, duration),
    }
}

fn report_clock(clock: &Clock) {
    let f = &clock.facts;
    eprintln!(
        "clock: clocksource={} constant_tsc={} nonstop_tsc={} resolution={}ns calibration={}ppm",
        f.clocksource, f.constant_tsc, f.nonstop_tsc, f.resolution_ns, f.calibration_error_ppm
    );
    for caveat in &f.caveats {
        eprintln!("caveat: {caveat}");
    }
    if let Some(reason) = &f.degraded {
        eprintln!("DEGRADED: {reason}");
    }
}

fn self_test(max_p99_us: u64, duration: u64) -> ExitCode {
    let clock = Clock::calibrated();
    report_clock(&clock);
    if let Some(reason) = &clock.facts.degraded {
        return fail(format!("clock is degraded: {reason}"));
    }

    for profile in [Profile::TcpReqResp, Profile::UdpEcho] {
        let target = match spawn_echo(profile) {
            Ok(addr) => addr,
            Err(e) => return fail(format!("{}: {e}", profile.as_str())),
        };
        let args = LoadArgs {
            target,
            rate_pps: profile.default_rate_pps(),
            duration_s: duration,
            gap_detect: true,
            gap_multiple: 3,
            env_file: None,
        };
        let report = match profile::load(profile, &args, &clock) {
            Ok(r) => r,
            Err(e) => return fail(format!("{}: {e}", profile.as_str())),
        };
        let p = report.percentiles();
        println!(
            "{}: samples {} gaps {} p50 {} us p99 {} us max {} us",
            profile.as_str(),
            p.samples,
            report.gaps().len(),
            p.p50_ns / 1000,
            p.p99_ns / 1000,
            p.max_ns / 1000
        );

        if p.samples == 0 {
            return fail(format!("{}: nothing came back", profile.as_str()));
        }
        // Loopback loses nothing. A missing reply here is a bug in the probe, not
        // a property of the network.
        if p.samples != args.rate_pps as u64 * duration {
            return fail(format!(
                "{}: {} replies for {} sends",
                profile.as_str(),
                p.samples,
                args.rate_pps as u64 * duration
            ));
        }
        if !report.gaps().is_empty() {
            return fail(format!("{}: {} gaps on loopback", profile.as_str(), report.gaps().len()));
        }
        if p.p99_ns / 1000 > max_p99_us {
            return fail(format!("{}: p99 {} us exceeds {} us", profile.as_str(), p.p99_ns / 1000, max_p99_us));
        }
        if report.kernel_delay_percentiles().is_none() {
            return fail(format!("{}: no kernel receive timestamp arrived", profile.as_str()));
        }
    }

    println!("self-test passed");
    ExitCode::SUCCESS
}

/// Binds first, then hands the bound socket to a thread, so the caller learns the
/// ephemeral port without racing the server's startup.
fn spawn_echo(profile: Profile) -> std::io::Result<SocketAddr> {
    match profile {
        Profile::TcpReqResp => {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            std::thread::spawn(move || profile::tcp_reqresp::serve_listener(listener));
            Ok(addr)
        }
        Profile::UdpEcho => {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            let addr = socket.local_addr()?;
            std::thread::spawn(move || profile::udp_echo::serve_socket(socket));
            Ok(addr)
        }
    }
}

fn fail(message: String) -> ExitCode {
    eprintln!("{message}");
    ExitCode::FAILURE
}
