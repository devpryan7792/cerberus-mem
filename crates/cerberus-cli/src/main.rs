//! `cerberus-mem` command-line entry point.

use cerberus_cli::scan::{scan_targets, ScanConfig};
use cerberus_core::reader::FallbackReader;
use cerberus_report::jsonl::JsonlEmitter;
use cerberus_report::models::ForensicFinding;
use clap::Parser;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Upper bound on scanner threads used by daemon mode.
const DAEMON_MAX_THREADS: usize = 4;

#[derive(Debug, Parser)]
#[command(
    name = "cerberus-mem",
    version,
    about = "Linux in-memory forensics and EDR evasion detection engine"
)]
struct Cli {
    /// Scan a single process ID.
    #[arg(long, conflicts_with = "all")]
    pid: Option<i32>,

    /// Scan every visible process.
    #[arg(long)]
    all: bool,

    /// Write findings as JSON-Lines to this file (append mode).
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Continuously sweep at the configured interval.
    #[arg(long)]
    daemon: bool,

    /// Seconds between daemon sweeps.
    #[arg(long, default_value_t = 30)]
    interval: u64,

    /// Quarantine directory for extracted divergent bytes.
    #[arg(long)]
    quarantine_dir: Option<PathBuf>,

    /// Maximum scanner worker threads.
    ///
    /// Defaults to every available core. Daemon mode caps this at 4 unless the
    /// value is given explicitly, so continuous sweeps do not saturate a
    /// production host.
    #[arg(long, value_name = "N")]
    max_threads: Option<usize>,
}

fn main() {
    // Default to `warn` so operational diagnostics (such as YAMA restrictions)
    // are visible without requiring RUST_LOG, while still honoring an
    // explicit override from the environment.
    if std::env::var_os("RUST_LOG").is_none() {
        env_logger::Builder::from_env(env_logger::Env::default().filter_or("warn", "warn")).init();
    } else {
        env_logger::init();
    }
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("cerberus-mem: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.pid.is_none() && !cli.all && !cli.daemon {
        return Err("specify --pid <PID>, --all, or --daemon".into());
    }

    report_yama_scope();

    let reader = FallbackReader::new();
    let max_threads = resolve_max_threads(cli.max_threads, cli.daemon);
    let config = ScanConfig {
        pid: cli.pid,
        // Daemon mode without an explicit target sweeps the host, matching the
        // documented `--daemon --interval N --quarantine-dir DIR` invocation.
        all: cli.all || (cli.daemon && cli.pid.is_none()),
        quarantine_dir: cli.quarantine_dir,
        max_threads,
    };

    if cli.daemon {
        loop {
            let findings = scan_targets(&reader, &config);
            emit_findings(&findings, cli.jsonl.as_deref())?;
            eprintln!("cerberus-mem: {} finding(s)", findings.len());
            std::thread::sleep(Duration::from_secs(cli.interval.max(1)));
        }
    }

    let findings = scan_targets(&reader, &config);
    emit_findings(&findings, cli.jsonl.as_deref())?;
    eprintln!("cerberus-mem: {} finding(s)", findings.len());
    Ok(())
}

/// Resolve the worker-thread budget.
///
/// Daemon mode is capped so a continuous sweep leaves headroom for the host's
/// own work; an explicit `--max-threads` always wins.
fn resolve_max_threads(explicit: Option<usize>, daemon: bool) -> Option<usize> {
    if let Some(threads) = explicit {
        return Some(threads.max(1));
    }
    if !daemon {
        return None;
    }
    let available = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4);
    Some(available.min(DAEMON_MAX_THREADS))
}

/// Warn when YAMA prevents inspection of foreign processes.
fn report_yama_scope() {
    if let Some(diagnostic) = cerberus_procfs::yama::foreign_inspection_diagnostic() {
        log::warn!("{diagnostic}");
    }
}

fn emit_findings(
    findings: &[ForensicFinding],
    jsonl_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = jsonl_path {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let mut emitter = JsonlEmitter::new(file);
        emitter.emit_all(findings)?;
        emitter.flush()?;
    } else {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        for finding in findings {
            writeln!(
                output,
                "[{:?}] pid={} {:?}: {} (0x{:x}-0x{:x})",
                finding.severity,
                finding.target_pid,
                finding.anomaly_type,
                finding.description,
                finding.affected_address_range.0,
                finding.affected_address_range.1
            )?;
        }
    }

    Ok(())
}
