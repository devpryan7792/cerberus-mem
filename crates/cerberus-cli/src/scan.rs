//! Multi-process scan orchestration.

use cerberus_core::reader::ProcessMemoryReader;
use cerberus_detect::fileless::check_fileless_execution;
use cerberus_detect::got_poison::inspect_process_got_with_context;
use cerberus_detect::hollowing::inspect_process_hollowing_with_context;
use cerberus_detect::inline_hook::inspect_inline_hooks_with_context;
use cerberus_detect::wxorx::scan_vma_anomalies;
use cerberus_procfs::maps::read_process_maps;
use cerberus_procfs::process::enumerate_all_pids;
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::ForensicFinding;
use cerberus_report::quarantine::QuarantineDumper;
use rayon::prelude::*;
use std::path::PathBuf;

/// Configuration for one scan invocation.
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Scan a single PID.
    pub pid: Option<i32>,
    /// Scan every visible process.
    pub all: bool,
    /// Optional quarantine directory for divergent byte ranges.
    pub quarantine_dir: Option<PathBuf>,
}

/// Scan one process with every detection engine.
pub fn scan_process(
    pid: i32,
    reader: &dyn ProcessMemoryReader,
    config: &ScanConfig,
) -> Vec<ForensicFinding> {
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
    findings.extend(inspect_process_hollowing_with_context(
        pid, &meta, &vmas, reader,
    ));
    findings.extend(inspect_process_got_with_context(pid, &meta, &vmas, reader));
    findings.extend(inspect_inline_hooks_with_context(pid, &meta, &vmas, reader));

    quarantine_artifacts(config, &findings);
    findings
}

/// Scan every host process in parallel.
pub fn sweep_host(reader: &dyn ProcessMemoryReader, config: &ScanConfig) -> Vec<ForensicFinding> {
    let pids = match enumerate_all_pids() {
        Ok(pids) => pids,
        Err(_) => return Vec::new(),
    };

    let mut findings: Vec<ForensicFinding> = pids
        .into_par_iter()
        .flat_map(|pid| scan_process(pid, reader, config))
        .collect();

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
