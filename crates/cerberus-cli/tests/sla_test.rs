//! Layer 5 SLA gate assertions.
//!
//! These are ignored by default because they only make sense against an
//! optimized build on an idle host. Run with:
//!
//! ```bash
//! cargo test -p cerberus-cli --release --test sla_test -- --ignored --nocapture
//! ```

use cerberus_cli::scan::{scan_process, scan_targets, ScanConfig};
use cerberus_core::reader::DirectSyscallReader;
use std::time::{Duration, Instant};

const SINGLE_PID_P99_LIMIT: Duration = Duration::from_micros(1500);
const SWEEP_LIMIT: Duration = Duration::from_millis(500);
const SINGLE_PID_SAMPLES: usize = 200;

fn config_for_pid(pid: i32) -> ScanConfig {
    ScanConfig {
        pid: Some(pid),
        all: false,
        quarantine_dir: None,
    }
}

fn sweep_config() -> ScanConfig {
    ScanConfig {
        pid: None,
        all: true,
        quarantine_dir: None,
    }
}

/// Short-lived target process for the single-PID gate.
///
/// Scanning the test harness itself would measure the harness's own code size
/// rather than a typical process, so the gate runs against a spawned `sleep`.
struct ScanTarget {
    child: std::process::Child,
    pid: i32,
}

impl ScanTarget {
    fn spawn() -> Self {
        let child = std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep target");
        let pid = child.id() as i32;
        // Let execve complete so the target's maps and exe are stable.
        std::thread::sleep(Duration::from_millis(100));
        Self { child, pid }
    }
}

impl Drop for ScanTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Serializes the performance gates: the sweep saturates the machine and would
/// otherwise pollute the concurrently sampled per-PID latency percentiles.
static SLA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialized() -> std::sync::MutexGuard<'static, ()> {
    SLA_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
#[ignore = "performance gate; run with --release --ignored"]
fn test_single_pid_p99_under_sla() {
    let _guard = serialized();
    let target = ScanTarget::spawn();
    let reader = DirectSyscallReader::new();
    let config = config_for_pid(target.pid);

    // Warm the ELF cache before sampling.
    let _ = scan_process(target.pid, &reader, &config);

    let mut samples = Vec::with_capacity(SINGLE_PID_SAMPLES);
    for _ in 0..SINGLE_PID_SAMPLES {
        let start = Instant::now();
        let _ = scan_process(target.pid, &reader, &config);
        samples.push(start.elapsed());
    }
    samples.sort_unstable();

    let index = (samples.len() * 99) / 100;
    let p99 = samples[index.min(samples.len() - 1)];
    eprintln!("single-PID scan p99 = {p99:?} (limit {SINGLE_PID_P99_LIMIT:?})");
    assert!(
        p99 < SINGLE_PID_P99_LIMIT,
        "single-PID p99 {p99:?} exceeds the 1.5 ms SLA"
    );
}

#[test]
#[ignore = "performance gate; run with --release --ignored"]
fn test_full_sweep_under_sla() {
    let _guard = serialized();
    let reader = DirectSyscallReader::new();
    let config = sweep_config();

    let _ = scan_targets(&reader, &config);

    let mut best = Duration::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        let _ = scan_targets(&reader, &config);
        best = best.min(start.elapsed());
    }

    eprintln!("full host sweep best = {best:?} (limit {SWEEP_LIMIT:?})");
    assert!(
        best < SWEEP_LIMIT,
        "full host sweep {best:?} exceeds the 500 ms SLA"
    );
}
