//! Fileless execution detection (memfd and deleted executables).

use cerberus_procfs::maps::VmaRecord;
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};

/// Inspect a process for memfd-backed and unlinked executable images.
pub fn check_fileless_execution(
    meta: &ProcessMetadata,
    _vmas: &[VmaRecord],
) -> Vec<ForensicFinding> {
    let mut findings = Vec::new();

    if let Some(exe_path) = &meta.exe_target {
        let exe_str = exe_path.to_string_lossy();
        if exe_str.starts_with("/memfd:") || exe_str.contains("memfd:") {
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity: Severity::Critical,
                anomaly_type: AnomalyType::FilelessMemfdExecution,
                description: format!(
                    "Process executable is backed by anonymous memory file descriptor: {exe_str}"
                ),
                affected_address_range: (0, 0),
                backing_detail: exe_str.to_string(),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        } else if meta.is_exe_deleted {
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity: Severity::High,
                anomaly_type: AnomalyType::DeletedBinaryExecution,
                description: format!("Process executable has been unlinked from disk: {exe_str}"),
                affected_address_range: (0, 0),
                backing_detail: exe_str.to_string(),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        }
    }

    findings
}
