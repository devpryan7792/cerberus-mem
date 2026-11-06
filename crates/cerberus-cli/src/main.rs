//! `cerberus-mem` command-line entry point.

mod scan;

use cerberus_core::reader::DirectSyscallReader;
use cerberus_report::jsonl::JsonlEmitter;
use cerberus_report::models::ForensicFinding;
use clap::Parser;
use scan::{scan_targets, ScanConfig};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("cerberus-mem: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.pid.is_none() && !cli.all {
        return Err("specify either --pid <PID> or --all".into());
    }

    let reader = DirectSyscallReader::new();
    let config = ScanConfig {
        pid: cli.pid,
        all: cli.all,
        quarantine_dir: cli.quarantine_dir,
    };

    if cli.daemon {
        loop {
            let findings = scan_targets(&reader, &config);
            emit_findings(&findings, cli.jsonl.as_deref())?;
            std::thread::sleep(Duration::from_secs(cli.interval.max(1)));
        }
    }

    let findings = scan_targets(&reader, &config);
    emit_findings(&findings, cli.jsonl.as_deref())?;
    eprintln!("cerberus-mem: {} finding(s)", findings.len());
    Ok(())
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
