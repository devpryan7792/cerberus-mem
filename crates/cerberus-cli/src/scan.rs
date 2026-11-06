//! Multi-process scan orchestration.

use cerberus_core::errors::MemoryReaderError;
use cerberus_core::reader::ProcessMemoryReader;
use cerberus_detect::fileless::check_fileless_execution;
use cerberus_detect::got_poison::inspect_process_got_with_context;
use cerberus_detect::hollowing::inspect_process_hollowing_with_context;
use cerberus_detect::inline_hook::inspect_inline_hooks_with_context;
use cerberus_detect::wxorx::scan_vma_anomalies;
use cerberus_procfs::maps::{read_process_maps, VmaProtection, VmaRecord};
use cerberus_procfs::process::enumerate_all_pids;
use cerberus_procfs::snapshot::address_space_replaced;
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::ForensicFinding;
use cerberus_report::quarantine::QuarantineDumper;
use rayon::prelude::*;
use std::path::PathBuf;

/// Attempts made to obtain a consistent snapshot of one process.
const SNAPSHOT_RETRIES: usize = 2;

/// Configuration for one scan invocation.
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Scan a single PID.
    pub pid: Option<i32>,
    /// Scan every visible process.
    pub all: bool,
    /// Optional quarantine directory for divergent byte ranges.
    pub quarantine_dir: Option<PathBuf>,
    /// Maximum number of scanner worker threads.
    ///
    /// `None` uses every available core. Daemon mode should prefer a lower
    /// value so continuous sweeps do not saturate a production host.
    pub max_threads: Option<usize>,
}

/// Scan one process with every detection engine.
///
/// A target that calls `execve(2)` while being inspected replaces its entire
/// address space, so the maps snapshot and the memory sample can describe
/// different layouts. Such a torn snapshot is retried against a fresh read
/// instead of being reported as a threat.
pub fn scan_process(
    pid: i32,
    reader: &dyn ProcessMemoryReader,
    config: &ScanConfig,
) -> Vec<ForensicFinding> {
    for attempt in 0..SNAPSHOT_RETRIES {
        let meta = match ProcessMetadata::extract(pid) {
            Ok(meta) => meta,
            Err(_) => return Vec::new(),
        };
        let vmas = match read_process_maps(pid) {
            Ok(vmas) => vmas,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        findings.extend(check_fileless_execution(&meta, &vmas));
        findings.extend(scan_vma_anomalies(&meta, &vmas));

        // Memory-backed engines need a readable target. Probe once so
        // unprivileged sweeps do not parse every on-disk executable before the
        // kernel refuses the first read.
        if !memory_access_denied(pid, &vmas, reader) {
            findings.extend(inspect_process_hollowing_with_context(
                pid, &meta, &vmas, reader,
            ));
            findings.extend(inspect_process_got_with_context(pid, &meta, &vmas, reader));
            findings.extend(inspect_inline_hooks_with_context(pid, &meta, &vmas, reader));
        }

        if attempt + 1 < SNAPSHOT_RETRIES && address_space_replaced(pid, &meta, &vmas) {
            continue;
        }

        quarantine_artifacts(config, &findings);
        return findings;
    }

    Vec::new()
}

/// Scan every host process in parallel.
pub fn sweep_host(reader: &dyn ProcessMemoryReader, config: &ScanConfig) -> Vec<ForensicFinding> {
    let pids = match enumerate_all_pids() {
        Ok(pids) => pids,
        Err(_) => return Vec::new(),
    };

    let findings: Vec<ForensicFinding> = match config.max_threads {
        Some(threads) => {
            let pool = match rayon::ThreadPoolBuilder::new()
                .num_threads(threads.max(1))
                .build()
            {
                Ok(pool) => pool,
                Err(_) => return Vec::new(),
            };
            pool.install(|| {
                pids.into_par_iter()
                    .flat_map(|pid| scan_process(pid, reader, config))
                    .collect()
            })
        }
        None => pids
            .into_par_iter()
            .flat_map(|pid| scan_process(pid, reader, config))
            .collect(),
    };

    let mut findings = findings;
    findings.sort_by(|left, right| {
        left.target_pid
            .cmp(&right.target_pid)
            .then_with(|| left.anomaly_type.cmp(&right.anomaly_type))
    });

    findings
}

/// Scan targets selected by `config`.
pub fn scan_targets(reader: &dyn ProcessMemoryReader, config: &ScanConfig) -> Vec<ForensicFinding> {
    cerberus_elf::disk::clear_cache();
    cerberus_elf::dynamic::clear_cache();

    if let Some(pid) = config.pid {
        scan_process(pid, reader, config)
    } else if config.all {
        sweep_host(reader, config)
    } else {
        Vec::new()
    }
}

/// Whether the kernel denies memory access to the target process.
///
/// Only an explicit access denial (`EPERM` / `EACCES`) or a vanished target
/// suppresses the memory-backed detectors. Transient faults such as `EFAULT`
/// are treated as "accessible" so a single unmapped probe address never hides
/// a real finding.
fn memory_access_denied(pid: i32, vmas: &[VmaRecord], reader: &dyn ProcessMemoryReader) -> bool {
    let Some(vma) = vmas
        .iter()
        .find(|vma| vma.perms.contains(VmaProtection::READ))
    else {
        return true;
    };
    let mut probe = [0u8; 1];
    match reader.read_memory(pid, vma.start, &mut probe) {
        Ok(_) => false,
        Err(MemoryReaderError::PermissionDenied { .. })
        | Err(MemoryReaderError::ProcessNotFound { .. }) => true,
        Err(_) => false,
    }
}

fn quarantine_artifacts(config: &ScanConfig, findings: &[ForensicFinding]) {
    let Some(directory) = &config.quarantine_dir else {
        return;
    };
    let Ok(dumper) = QuarantineDumper::new(directory) else {
        return;
    };

    for finding in findings {
        let Some(hex) = &finding.extracted_divergence_bytes else {
            continue;
        };
        let Some(bytes) = decode_hex(hex) else {
            continue;
        };
        let label = format!("{:?}", finding.anomaly_type);
        let _ = dumper.dump(finding.target_pid, &label, &bytes);
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
