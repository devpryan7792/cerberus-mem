//! Layer 5 SLA benchmarks: per-PID latency and full host sweep throughput.
//!
//! Run with `cargo bench -p cerberus-cli`. The single-PID benchmark scans a
//! spawned `sleep` target, since benchmarking the harness itself would measure
//! Criterion's linked code size rather than a typical daemon. The sweep
//! benchmark walks `/proc` exactly as the CLI does.

use cerberus_cli::scan::{scan_process, scan_targets, ScanConfig};
use cerberus_core::reader::{DirectSyscallReader, FallbackReader};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::process::{Child, Command};
use std::time::Duration;

fn single_pid_config(pid: i32) -> ScanConfig {
    ScanConfig {
        pid: Some(pid),
        all: false,
        quarantine_dir: None,
        max_threads: None,
    }
}

fn full_sweep_config() -> ScanConfig {
    ScanConfig {
        pid: None,
        all: true,
        quarantine_dir: None,
        max_threads: None,
    }
}

/// Keeps a target process alive for the duration of the benchmark.
struct ScanTarget {
    child: Child,
    pid: i32,
}

impl ScanTarget {
    fn spawn() -> Self {
        let child = Command::new("sleep")
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

fn bench_single_pid(c: &mut Criterion) {
    let target = ScanTarget::spawn();
    let reader = DirectSyscallReader::new();
    let config = single_pid_config(target.pid);

    // Warm the ELF caches so the benchmark measures scan latency, not disk I/O.
    let _ = scan_process(target.pid, &reader, &config);

    c.bench_function("scan_single_pid", |bencher| {
        bencher.iter(|| black_box(scan_process(black_box(target.pid), &reader, &config)))
    });
}

fn bench_full_sweep(c: &mut Criterion) {
    let reader = FallbackReader::new();
    let config = full_sweep_config();
    let _ = scan_targets(&reader, &config);

    c.bench_function("sweep_host_all", |bencher| {
        bencher.iter(|| black_box(scan_targets(&reader, &config)))
    });
}

criterion_group!(benches, bench_single_pid, bench_full_sweep);
criterion_main!(benches);
