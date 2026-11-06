//! GOT/PLT pointer range verification.

use cerberus_core::reader::ProcessMemoryReader;
use cerberus_elf::dynamic::load_dynamic_info_cached;
use cerberus_procfs::maps::{read_process_maps, VmaBacking, VmaProtection, VmaRecord};
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};

use crate::hollowing::find_exe_load_base;

/// Forensic verdict for one GOT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotEntryForensic {
    /// Imported symbol name.
    pub symbol_name: String,
    /// Runtime address of the GOT slot.
    pub got_address: u64,
    /// Pointer value read from the slot.
    pub target_pointer: u64,
    /// Backing of the VMA containing the pointer target.
    pub target_vma_backing: Option<VmaBacking>,
    /// Whether the target resolves to an authorized executable mapping.
    pub is_valid: bool,
    /// Human-readable reason for invalidity.
    pub anomaly_reason: Option<String>,
}

/// Maximum span read in one syscall when slurping GOT slots.
const GOT_READ_WINDOW: u64 = 64 * 1024;

/// Verify that every supplied GOT pointer targets authorized executable code.
pub fn verify_got_entries(
    got_entries: &[(String, u64)],
    vmas: &[VmaRecord],
    reader: &dyn ProcessMemoryReader,
    pid: i32,
) -> Vec<GotEntryForensic> {
    let pointers = read_got_pointers(got_entries, reader, pid);
    let mut results = Vec::new();

    for ((symbol, got_addr), pointer) in got_entries.iter().zip(pointers) {
        let Some(target_pointer) = pointer else {
            continue;
        };

        // Zero is the legitimate value of an unresolved weak function.
        if target_pointer == 0 {
            results.push(GotEntryForensic {
                symbol_name: symbol.clone(),
                got_address: *got_addr,
                target_pointer,
                target_vma_backing: None,
                is_valid: true,
                anomaly_reason: None,
            });
            continue;
        }

        let containing_vma = vmas
            .iter()
            .find(|vma| target_pointer >= vma.start && target_pointer < vma.end);

        let (target_vma_backing, is_valid, anomaly_reason) = match containing_vma {
            None => (
                None,
                false,
                Some(format!(
                    "Target 0x{target_pointer:x} points outside all mapped VMAs"
                )),
            ),
            Some(vma) => {
                let backing = Some(vma.backing.clone());
                if !vma.is_executable() {
                    (
                        backing,
                        false,
                        Some(format!(
                            "Target 0x{target_pointer:x} resides in non-executable VMA"
                        )),
                    )
                } else if vma.perms.contains(VmaProtection::WRITE) {
                    (
                        backing,
                        false,
                        Some(format!(
                            "Target 0x{target_pointer:x} resides in a writable+executable VMA"
                        )),
                    )
                } else if matches!(
                    vma.backing,
                    VmaBacking::Anonymous | VmaBacking::Heap | VmaBacking::Stack
                ) {
                    (
                        backing,
                        false,
                        Some(format!(
                            "Target 0x{target_pointer:x} points to anonymous/heap/stack memory"
                        )),
                    )
                } else {
                    (backing, true, None)
                }
            }
        };

        results.push(GotEntryForensic {
            symbol_name: symbol.clone(),
            got_address: *got_addr,
            target_pointer,
            target_vma_backing,
            is_valid,
            anomaly_reason,
        });
    }

    results
}

/// Inspect the main executable's GOT/PLT and emit findings for poisoned slots.
pub fn inspect_process_got(pid: i32, reader: &dyn ProcessMemoryReader) -> Vec<ForensicFinding> {
    let meta = match ProcessMetadata::extract(pid) {
        Ok(meta) => meta,
        Err(_) => return Vec::new(),
    };
    let vmas = match read_process_maps(pid) {
        Ok(vmas) => vmas,
        Err(_) => return Vec::new(),
    };
    inspect_process_got_with_context(pid, &meta, &vmas, reader)
}

/// GOT inspection using already-collected process metadata and VMAs.
pub fn inspect_process_got_with_context(
    pid: i32,
    meta: &ProcessMetadata,
    vmas: &[VmaRecord],
    reader: &dyn ProcessMemoryReader,
) -> Vec<ForensicFinding> {
    if meta.is_exe_deleted {
        return Vec::new();
    }
    let Some(exe_path) = meta.exe_target.as_ref() else {
        return Vec::new();
    };

    let dynamic = match load_dynamic_info_cached(exe_path) {
        Ok(info) => info,
        Err(_) => return Vec::new(),
    };
    let Some(load_base) = find_exe_load_base(vmas, exe_path) else {
        return Vec::new();
    };

    let entries: Vec<(String, u64)> = dynamic
        .got_entries
        .iter()
        .map(|entry| {
            (
                entry.symbol_name.clone(),
                load_base.saturating_add(entry.got_vaddr.saturating_sub(dynamic.min_load_vaddr)),
            )
        })
        .collect();

    let verdicts = verify_got_entries(&entries, vmas, reader, pid);
    let plt_ranges = dynamic.runtime_plt_ranges(load_base);
    let mut findings = Vec::new();

    for verdict in verdicts {
        let mut is_valid = verdict.is_valid;
        let mut reason = verdict.anomaly_reason.clone();

        // A GOT slot may legitimately point into the main executable only while
        // it still references that executable's PLT stub. A pointer into the
        // main executable's ordinary .text is a hijack indicator.
        if is_valid {
            if let Some(VmaBacking::File(path) | VmaBacking::Deleted(path)) =
                &verdict.target_vma_backing
            {
                if same_file(path, exe_path) {
                    let in_plt = plt_ranges.iter().any(|(start, end)| {
                        verdict.target_pointer >= *start && verdict.target_pointer < *end
                    });
                    if !in_plt {
                        is_valid = false;
                        reason = Some(format!(
                            "Target 0x{:x} points into the main executable outside its PLT stubs",
                            verdict.target_pointer
                        ));
                    }
                }
            }
        }

        if is_valid {
            continue;
        }
        let reason = reason.unwrap_or_else(|| "unknown GOT anomaly".to_string());
        findings.push(ForensicFinding {
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            target_pid: meta.pid as u32,
            process_comm: meta.comm.clone(),
            process_cmdline: meta.cmdline.clone(),
            severity: Severity::Critical,
            anomaly_type: AnomalyType::GotPltHijack,
            description: format!(
                "GOT slot for '{}' at 0x{:x} points to 0x{:x}: {}",
                verdict.symbol_name, verdict.got_address, verdict.target_pointer, reason
            ),
            affected_address_range: (verdict.got_address, verdict.got_address.saturating_add(8)),
            backing_detail: format!("{:?}", verdict.target_vma_backing),
            disk_hash_sha256: None,
            mem_hash_sha256: None,
            extracted_divergence_bytes: None,
            disassembly_snippet: None,
        });
    }

    findings
}

fn read_got_pointers(
    got_entries: &[(String, u64)],
    reader: &dyn ProcessMemoryReader,
    pid: i32,
) -> Vec<Option<u64>> {
    let mut pointers = vec![None; got_entries.len()];
    if got_entries.is_empty() {
        return pointers;
    }

    // GOT slots are clustered, so one read covers many entries. Sort by address
    // and slurp contiguous windows instead of issuing one syscall per slot.
    let mut order: Vec<usize> = (0..got_entries.len()).collect();
    order.sort_unstable_by_key(|&index| got_entries[index].1);

    let mut cursor = 0usize;
    while cursor < order.len() {
        let group_start = got_entries[order[cursor]].1;
        let mut group_stop = group_start.saturating_add(8);
        let mut group_end = cursor + 1;
        while group_end < order.len() {
            let end = got_entries[order[group_end]].1.saturating_add(8);
            if end.saturating_sub(group_start) > GOT_READ_WINDOW {
                break;
            }
            group_stop = group_stop.max(end);
            group_end += 1;
        }

        if let Ok(length) = usize::try_from(group_stop.saturating_sub(group_start)) {
            let mut buffer = vec![0u8; length];
            if reader.read_memory(pid, group_start, &mut buffer).is_ok() {
                for &index in &order[cursor..group_end] {
                    let Some(offset) = got_entries[index].1.checked_sub(group_start) else {
                        continue;
                    };
                    let Ok(offset) = usize::try_from(offset) else {
                        continue;
                    };
                    let Some(slot) = buffer.get(offset..offset.saturating_add(8)) else {
                        continue;
                    };
                    let mut pointer_bytes = [0u8; 8];
                    pointer_bytes.copy_from_slice(slot);
                    pointers[index] = Some(u64::from_ne_bytes(pointer_bytes));
                }
            }
        }

        cursor = group_end;
    }

    pointers
}

fn same_file(left: &std::path::Path, right: &std::path::Path) -> bool {
    left == right || (left.file_name().is_some() && left.file_name() == right.file_name())
}
