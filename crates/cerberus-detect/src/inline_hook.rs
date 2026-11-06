//! Inline function hook detection in shared-library prologues.

use cerberus_core::reader::ProcessMemoryReader;
use cerberus_elf::dynamic::{load_dynamic_info_cached, DynamicInfo};
use cerberus_procfs::maps::{read_process_maps, VmaRecord};
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

use crate::hollowing::find_file_mapping;

/// Functions commonly hooked by Linux userland malware.
const CRITICAL_SYMBOLS: &[&str] = &[
    "openat", "execve", "read", "write", "ptrace", "connect", "system", "open",
];

/// Inspect the prologues of critical libc exports for rogue jump trampolines.
pub fn inspect_inline_hooks(pid: i32, reader: &dyn ProcessMemoryReader) -> Vec<ForensicFinding> {
    let meta = match ProcessMetadata::extract(pid) {
        Ok(meta) => meta,
        Err(_) => return Vec::new(),
    };
    let vmas = match read_process_maps(pid) {
        Ok(vmas) => vmas,
        Err(_) => return Vec::new(),
    };
    inspect_inline_hooks_with_context(pid, &meta, &vmas, reader)
}

/// Inline-hook inspection using already-collected process metadata and VMAs.
pub fn inspect_inline_hooks_with_context(
    pid: i32,
    meta: &ProcessMetadata,
    vmas: &[VmaRecord],
    reader: &dyn ProcessMemoryReader,
) -> Vec<ForensicFinding> {
    let Some((libc_path, libc_base)) = find_file_mapping(vmas, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("libc.so") || name.starts_with("libc-"))
            .unwrap_or(false)
    }) else {
        return Vec::new();
    };

    let dynamic = match load_dynamic_info_cached(&libc_path) {
        Ok(info) => info,
        Err(_) => return Vec::new(),
    };
    let (text_start, text_end) = dynamic.runtime_text_range(libc_base);

    let mut findings = Vec::new();
    for symbol in &dynamic.exported_functions {
        if !CRITICAL_SYMBOLS.contains(&symbol.name.as_str()) {
            continue;
        }

        let address = dynamic.runtime_symbol_address(libc_base, symbol);
        let mut prologue = [0u8; 16];
        let read_len = match reader.read_memory(pid, address, &mut prologue) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if read_len < 5 {
            continue;
        }

        let Some(target) = hook_target(&prologue[..read_len], address, reader, pid) else {
            continue;
        };
        if target >= text_start && target < text_end {
            continue;
        }

        findings.push(ForensicFinding {
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            target_pid: meta.pid as u32,
            process_comm: meta.comm.clone(),
            process_cmdline: meta.cmdline.clone(),
            severity: Severity::High,
            anomaly_type: AnomalyType::InlineFunctionHook,
            description: format!(
                "libc function '{}' at 0x{address:x} jumps to 0x{target:x}, outside libc .text [0x{text_start:x}-0x{text_end:x})",
                symbol.name
            ),
            affected_address_range: (address, address.saturating_add(read_len as u64)),
            backing_detail: libc_path.to_string_lossy().to_string(),
            disk_hash_sha256: None,
            mem_hash_sha256: None,
            extracted_divergence_bytes: None,
            disassembly_snippet: Some(disassemble_x86_64(&prologue[..read_len], address)),
        });
    }

    findings
}

fn hook_target(
    prologue: &[u8],
    address: u64,
    reader: &dyn ProcessMemoryReader,
    pid: i32,
) -> Option<u64> {
    let mut decoder = Decoder::with_ip(64, prologue, address, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let mut first = decoder.decode();
    // CET-enabled glibc may place a hook immediately after the ENDBR64
    // landing pad, so inspect the following instruction as well.
    if first.mnemonic() == Mnemonic::Endbr64 && decoder.can_decode() {
        first = decoder.decode();
    }

    match first.mnemonic() {
        Mnemonic::Jmp => {
            if matches!(
                first.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                let target = first.near_branch_target();
                return (target != 0).then_some(target);
            }
            if first.is_ip_rel_memory_operand() {
                let slot = first.ip_rel_memory_address();
                let mut pointer_bytes = [0u8; 8];
                if let Ok(8) = reader.read_memory(pid, slot, &mut pointer_bytes) {
                    let target = u64::from_ne_bytes(pointer_bytes);
                    return (target != 0).then_some(target);
                }
            }
            None
        }
        Mnemonic::Mov => {
            // movabs $target, %rax/%r11 followed by jmp *%rax/%r11
            if first.op0_kind() != OpKind::Register
                || first.op1_kind() != OpKind::Immediate64
                || !decoder.can_decode()
            {
                return None;
            }
            let second = decoder.decode();
            if second.mnemonic() != Mnemonic::Jmp || second.op0_kind() != OpKind::Register {
                return None;
            }
            Some(first.immediate64())
        }
        _ => None,
    }
}

/// Format a short x86-64 disassembly listing without requiring std formatting
/// support from iced-x86.
pub(crate) fn disassemble_x86_64(bytes: &[u8], ip: u64) -> Vec<String> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut lines = Vec::new();
    while decoder.can_decode() && lines.len() < 16 {
        let instruction = decoder.decode();
        lines.push(format!(
            "0x{:x}: {:?} {:?}",
            instruction.ip(),
            instruction.mnemonic(),
            instruction.op0_kind()
        ));
    }
    lines
}

/// Re-export for callers that already have parsed dynamic metadata.
pub fn libc_text_range(dynamic: &DynamicInfo, libc_base: u64) -> (u64, u64) {
    dynamic.runtime_text_range(libc_base)
}

/// Convenience check used by callers holding a pre-parsed VMA list.
pub fn libc_mapping(vmas: &[VmaRecord]) -> Option<(std::path::PathBuf, u64)> {
    find_file_mapping(vmas, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("libc.so") || name.starts_with("libc-"))
            .unwrap_or(false)
    })
}
