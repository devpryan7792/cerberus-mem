//! W^X and anonymous executable mapping detection.

use cerberus_procfs::maps::VmaRecord;
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};

/// Large anonymous executable mappings are more suspicious than small JIT
/// stubs; runtime engines are exempted from the critical upgrade.
const LARGE_EXEC_MAPPING: u64 = 64 * 1024;

/// Well-known legitimate runtime engines that may create executable anon pages.
const JIT_COMMS: &[&str] = &[
    "node",
    "nodejs",
    "java",
    "javac",
    "chromium",
    "chrome",
    "firefox",
    "dotnet",
    "mono",
    "d8",
    "qemu-system-x86_64",
    "qemu-system-aarch64",
];

/// Scan every VMA for W^X violations and anonymous executable mappings.
pub fn scan_vma_anomalies(meta: &ProcessMetadata, vmas: &[VmaRecord]) -> Vec<ForensicFinding> {
    let mut findings = Vec::new();
    let jit_runtime = is_authorized_jit(&meta.comm);

    for vma in vmas {
        if vma.is_rwx() {
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity: Severity::High,
                anomaly_type: AnomalyType::WxorXViolation,
                description: format!(
                    "Mapping at 0x{:x}-0x{:x} is simultaneously writable and executable ({:?})",
                    vma.start, vma.end, vma.perms
                ),
                affected_address_range: (vma.start, vma.end),
                backing_detail: format!("{:?}", vma.backing),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        }

        if vma.is_anonymous_exec() {
            let large = vma.size() > LARGE_EXEC_MAPPING;
            let severity = if large && !jit_runtime {
                Severity::Critical
            } else {
                Severity::Medium
            };
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity,
                anomaly_type: AnomalyType::AnonymousExecutableMapping,
                description: format!(
                    "Executable {} mapping at 0x{:x}-0x{:x} ({} bytes){}",
                    if matches!(vma.backing, cerberus_procfs::maps::VmaBacking::Heap) {
                        "heap"
                    } else {
                        "anonymous"
                    },
                    vma.start,
                    vma.end,
                    vma.size(),
                    if large && !jit_runtime {
                        " exceeds the 64 KiB shellcode threshold"
                    } else {
                        ""
                    }
                ),
                affected_address_range: (vma.start, vma.end),
                backing_detail: format!("{:?}", vma.backing),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        }
    }

    findings
}

fn is_authorized_jit(comm: &str) -> bool {
    let lower = comm.to_ascii_lowercase();
    JIT_COMMS.iter().any(|candidate| lower.contains(candidate))
}
