//! Differential on-disk vs. in-memory `.text` analysis (process hollowing).

use cerberus_core::reader::ProcessMemoryReader;
use cerberus_elf::disk::load_cached as load_disk_cached;
use cerberus_elf::reloc::RelocationMask;
use cerberus_procfs::auxv::AuxvReader;
use cerberus_procfs::maps::{read_process_maps, VmaBacking, VmaRecord};
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::inline_hook::disassemble_x86_64;

/// Refuse to allocate absurd text buffers from a hostile/corrupt ELF header.
const MAX_TEXT_BYTES: usize = 256 * 1024 * 1024;
/// Number of divergent bytes retained for reporting.
const DIVERGENCE_WINDOW: usize = 64;

/// Compare the live `.text` of `pid` against its on-disk executable.
pub fn inspect_process_hollowing(
    pid: i32,
    reader: &dyn ProcessMemoryReader,
) -> Vec<ForensicFinding> {
    let meta = match ProcessMetadata::extract(pid) {
        Ok(meta) => meta,
        Err(_) => return Vec::new(),
    };
    let vmas = match read_process_maps(pid) {
        Ok(vmas) => vmas,
        Err(_) => return Vec::new(),
    };
    inspect_process_hollowing_with_context(pid, &meta, &vmas, reader)
}

/// Hollowing inspection using already-collected process metadata and VMAs.
pub fn inspect_process_hollowing_with_context(
    pid: i32,
    meta: &ProcessMetadata,
    vmas: &[VmaRecord],
    reader: &dyn ProcessMemoryReader,
) -> Vec<ForensicFinding> {
    if meta.is_exe_deleted {
        return Vec::new();
    }

    let Some(exe_path) = meta.exe_target.as_ref().map(|path| strip_deleted(path)) else {
        return Vec::new();
    };

    let disk = match load_disk_cached(&exe_path) {
        Ok(disk) => disk,
        Err(_) => return Vec::new(),
    };

    let Some(load_base) = find_exe_load_base(vmas, &exe_path) else {
        return Vec::new();
    };

    let runtime_text = disk.runtime_text_address(load_base);
    let text_is_mapped = vmas
        .iter()
        .any(|vma| vma.is_executable() && vma.start <= runtime_text && runtime_text < vma.end);
    if !text_is_mapped {
        return Vec::new();
    }

    let Ok(size) = usize::try_from(disk.text.size) else {
        return Vec::new();
    };
    if size == 0 || size > MAX_TEXT_BYTES {
        return Vec::new();
    }

    let mut memory = vec![0u8; size];
    let read_len = match reader.read_memory(pid, runtime_text, &mut memory) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };
    if read_len == 0 {
        return Vec::new();
    }

    let mut disk_bytes = disk.text.data.clone();
    disk_bytes.truncate(read_len);
    memory.truncate(read_len);

    let mask = RelocationMask::from_relocations(&disk.relocations);
    mask.apply_mask(&mut disk_bytes);
    mask.apply_mask(&mut memory);

    let mut findings = Vec::new();

    if disk_bytes != memory {
        let first_diff = disk_bytes
            .iter()
            .zip(memory.iter())
            .position(|(disk_byte, mem_byte)| disk_byte != mem_byte)
            .unwrap_or(0);
        let diff_count = disk_bytes
            .iter()
            .zip(memory.iter())
            .filter(|(disk_byte, mem_byte)| disk_byte != mem_byte)
            .count();

        let start = first_diff.saturating_sub(16);
        let end = start.saturating_add(DIVERGENCE_WINDOW).min(read_len);

        findings.push(ForensicFinding {
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            target_pid: meta.pid as u32,
            process_comm: meta.comm.clone(),
            process_cmdline: meta.cmdline.clone(),
            severity: Severity::Critical,
            anomaly_type: AnomalyType::ProcessHollowing,
            description: format!(
                "Live .text diverges from on-disk image: {diff_count} byte(s) differ, first at offset 0x{first_diff:x}"
            ),
            affected_address_range: (runtime_text + start as u64, runtime_text + end as u64),
            backing_detail: exe_path.to_string_lossy().to_string(),
            disk_hash_sha256: Some(sha256_hex(&disk_bytes)),
            mem_hash_sha256: Some(sha256_hex(&memory)),
            extracted_divergence_bytes: Some(hex_encode(&memory[start..end])),
            disassembly_snippet: Some(disassemble_x86_64(
                &memory[start..end],
                runtime_text + start as u64,
            )),
        });
    }

    if let Ok(anchors) = AuxvReader::read_anchors(pid) {
        if let Some(entry_point) = anchors.entry_point {
            let expected = disk.runtime_entry_point(load_base);
            if entry_point != expected {
                findings.push(ForensicFinding {
                    timestamp_utc: chrono::Utc::now().to_rfc3339(),
                    target_pid: meta.pid as u32,
                    process_comm: meta.comm.clone(),
                    process_cmdline: meta.cmdline.clone(),
                    severity: Severity::High,
                    anomaly_type: AnomalyType::ProcessHollowing,
                    description: format!(
                        "AT_ENTRY 0x{entry_point:x} does not match the on-disk entry point 0x{expected:x}"
                    ),
                    affected_address_range: (expected, expected.saturating_add(1)),
                    backing_detail: exe_path.to_string_lossy().to_string(),
                    disk_hash_sha256: None,
                    mem_hash_sha256: None,
                    extracted_divergence_bytes: None,
                    disassembly_snippet: None,
                });
            }
        }
    }

    findings
}

/// Find the load base for a mapping backed by `path`.
pub(crate) fn find_exe_load_base(vmas: &[VmaRecord], path: &Path) -> Option<u64> {
    let target_name = path.file_name().map(|name| name.to_os_string());
    find_file_mapping(vmas, |candidate| {
        candidate == path
            || target_name
                .as_ref()
                .map(|name| candidate.file_name() == Some(name.as_os_str()))
                .unwrap_or(false)
    })
    .map(|(_, base)| base)
}

/// Find a mapping matching `predicate`, preferring the offset-zero load segment.
pub(crate) fn find_file_mapping<F>(vmas: &[VmaRecord], predicate: F) -> Option<(PathBuf, u64)>
where
    F: Fn(&Path) -> bool,
{
    let mut fallback = None;
    for vma in vmas {
        let path = match &vma.backing {
            VmaBacking::File(path) | VmaBacking::Deleted(path) => path,
            _ => continue,
        };
        if !predicate(path) {
            continue;
        }
        if vma.offset == 0 {
            return Some((path.clone(), vma.start));
        }
        if fallback.is_none() {
            fallback = Some((path.clone(), vma.start.saturating_sub(vma.offset)));
        }
    }
    fallback
}

fn strip_deleted(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.trim_end_matches(" (deleted)"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
