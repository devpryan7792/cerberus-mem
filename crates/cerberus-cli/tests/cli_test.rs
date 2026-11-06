//! CLI-level behaviour tests: thread budget, target selection, and output
//! modes that do not depend on adversarial payloads.

use cerberus_cli::scan::{scan_process, sweep_host, ScanConfig};
use cerberus_core::reader::DirectSyscallReader;
use std::process::{Child, Command, Stdio};

struct ChildGuard(Child);

impl ChildGuard {
    fn spawn_sleep() -> Self {
        let child = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn sleep target");
        Self(child)
    }

    fn pid(&self) -> i32 {
        self.0.id() as i32
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(pid: Option<i32>, all: bool, max_threads: Option<usize>) -> ScanConfig {
    ScanConfig {
        pid,
        all,
        quarantine_dir: None,
        max_threads,
    }
}

#[test]
fn test_scan_process_returns_findings_for_readable_child() {
    let target = ChildGuard::spawn_sleep();
    // Let execve finish so the maps and the live memory describe the same
    // address space.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let reader = DirectSyscallReader::new();

    let findings = scan_process(
        target.pid(),
        &reader,
        &config(Some(target.pid()), false, None),
    );

    // A clean `sleep` must not produce hollowing, GOT, inline-hook, or
    // fileless findings, but the scan itself must complete without panicking.
    assert!(
        !findings.iter().any(|finding| matches!(
            finding.anomaly_type,
            cerberus_report::models::AnomalyType::ProcessHollowing
                | cerberus_report::models::AnomalyType::GotPltHijack
                | cerberus_report::models::AnomalyType::InlineFunctionHook
                | cerberus_report::models::AnomalyType::FilelessMemfdExecution
        )),
        "clean target produced suspicious findings: {findings:?}"
    );
}

#[test]
fn test_sweep_honours_thread_budget() {
    let reader = DirectSyscallReader::new();

    let unlimited = sweep_host(&reader, &config(None, true, None));
    let limited = sweep_host(&reader, &config(None, true, Some(2)));

    assert!(
        !unlimited.is_empty() || !limited.is_empty(),
        "sweep produced no findings at all; the host should expose W^X or anon-exec mappings"
    );

    // Both sweeps must observe the same processes, so the finding sets match.
    let mut unlimited_keys: Vec<_> = unlimited
        .iter()
        .map(|finding| (finding.target_pid, finding.anomaly_type))
        .collect();
    let mut limited_keys: Vec<_> = limited
        .iter()
        .map(|finding| (finding.target_pid, finding.anomaly_type))
        .collect();
    unlimited_keys.sort();
    limited_keys.sort();

    assert_eq!(
        unlimited_keys, limited_keys,
        "thread budget changed which findings were produced"
    );
}

#[test]
fn test_cli_accepts_max_threads_flag() {
    let status = Command::new(env!("CARGO_BIN_EXE_cerberus-mem"))
        .args(["--all", "--max-threads", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run cerberus-mem");

    assert!(status.success(), "cerberus-mem --max-threads 1 failed");
}

#[test]
fn test_cli_rejects_pid_and_all_together() {
    let status = Command::new(env!("CARGO_BIN_EXE_cerberus-mem"))
        .args(["--pid", "1", "--all"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run cerberus-mem");

    assert!(
        !status.success(),
        "--pid and --all must be mutually exclusive"
    );
}

#[test]
fn test_cli_requires_a_target() {
    let status = Command::new(env!("CARGO_BIN_EXE_cerberus-mem"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run cerberus-mem");

    assert!(!status.success(), "a scan target is required");
}
