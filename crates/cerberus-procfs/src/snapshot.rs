//! Address-space snapshot consistency checks.
//!
//! A process can call `execve(2)` between the moment its `/proc/[pid]/maps`
//! file is read and the moment its memory is sampled. The two reads then
//! describe different address spaces, and findings computed from the mixture
//! are meaningless: GOT slots appear to point outside every mapping, and
//! disk-versus-memory comparisons report massive bogus divergence.
//!
//! These helpers detect that torn snapshot so the scanner can retry against a
//! fresh one instead of reporting phantom threats.

use crate::maps::{read_process_maps, VmaBacking, VmaRecord};
use crate::status::ProcessMetadata;
use std::path::{Path, PathBuf};

/// Load base of the mapping that backs `exe`, if it is mapped.
///
/// Mirrors the detector's own lookup so both agree on which mapping is the
/// executable image.
pub fn exe_load_base(vmas: &[VmaRecord], exe: &Path) -> Option<u64> {
    let target_name = exe.file_name().map(|name| name.to_os_string());
    let mut fallback = None;

    for vma in vmas {
        let path = match &vma.backing {
            VmaBacking::File(path) | VmaBacking::Deleted(path) => path,
            _ => continue,
        };
        let matches = path == exe
            || target_name
                .as_ref()
                .map(|name| path.file_name() == Some(name.as_os_str()))
                .unwrap_or(false);
        if !matches {
            continue;
        }
        if vma.offset == 0 {
            return Some(vma.start);
        }
        if fallback.is_none() {
            fallback = Some(vma.start.saturating_sub(vma.offset));
        }
    }

    fallback
}

/// Whether the target's address space was replaced since `vmas` was captured.
///
/// An `execve(2)` swaps the entire address space. It is detected by
/// comparing the executable's identity and load base against a fresh read.
///
/// Ordinary `mmap`/`munmap` activity does *not* trigger this: only the
/// executable image and its base address are compared, so JIT runtimes that
/// constantly remap anonymous memory are not mistaken for a replaced image.
pub fn address_space_replaced(pid: i32, meta: &ProcessMetadata, vmas: &[VmaRecord]) -> bool {
    // A process that exited mid-scan cannot be reasoned about.
    let Ok(fresh_exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return true;
    };
    if meta.exe_target.as_deref() != Some(fresh_exe.as_path()) {
        return true;
    }

    let Ok(fresh_vmas) = read_process_maps(pid) else {
        return true;
    };

    let Some(exe) = meta.exe_target.as_ref().map(|path| strip_deleted(path)) else {
        return false;
    };

    exe_load_base(&fresh_vmas, &exe) != exe_load_base(vmas, &exe)
}

/// Remove the kernel's `" (deleted)"` suffix from an executable path.
fn strip_deleted(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.trim_end_matches(" (deleted)"))
}
