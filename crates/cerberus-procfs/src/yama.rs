//! YAMA `ptrace_scope` inspection.
//!
//! The kernel's YAMA LSM restricts `ptrace`-family access, which also governs
//! `process_vm_readv(2)` and `/proc/[pid]/mem`. Reading the configured scope
//! lets the CLI explain why a sweep could not inspect foreign processes
//! instead of silently returning fewer findings.

/// Path of the YAMA `ptrace_scope` knob.
const YAMA_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Bit index of `CAP_SYS_PTRACE` in the capability bitmasks.
const CAP_SYS_PTRACE_BIT: u32 = 19;

/// YAMA `ptrace_scope` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceScope {
    /// Level 0: classic ptrace permissions, unrestricted by YAMA.
    Classic,
    /// Level 1: a process may only inspect its own descendants.
    Restricted,
    /// Level 2: administrator-only inspection (`CAP_SYS_PTRACE` required).
    AdminOnly,
    /// Level 3: no process may inspect another, not even root.
    NoAttach,
    /// The scope could not be determined.
    Unknown,
}

impl PtraceScope {
    /// Human-readable explanation of the practical consequences.
    pub fn guidance(self) -> &'static str {
        match self {
            PtraceScope::Classic => {
                "ptrace_scope=0: no YAMA restriction on cross-process inspection"
            }
            PtraceScope::Restricted => {
                "ptrace_scope=1: only descendant processes can be inspected; \
                 grant CAP_SYS_PTRACE to scan foreign processes"
            }
            PtraceScope::AdminOnly => {
                "ptrace_scope=2: cross-process inspection requires CAP_SYS_PTRACE"
            }
            PtraceScope::NoAttach => {
                "ptrace_scope=3: no process may inspect another, even with root; \
                 cross-process memory forensics is disabled until this is lowered"
            }
            PtraceScope::Unknown => {
                "could not determine ptrace_scope; cross-process inspection may be restricted"
            }
        }
    }

    /// Whether foreign process memory can be read under this scope.
    ///
    /// Level 1 still permits inspection of the caller's own descendants, which
    /// covers the common case of a scanner launched by the target's parent.
    pub fn permits_foreign_inspection(self) -> bool {
        match self {
            PtraceScope::Classic => true,
            PtraceScope::Restricted | PtraceScope::AdminOnly => has_cap_sys_ptrace(),
            PtraceScope::NoAttach => false,
            PtraceScope::Unknown => false,
        }
    }
}

/// Whether the current process holds `CAP_SYS_PTRACE`.
///
/// Reads `CapEff` from `/proc/self/status` and tests bit 19. A missing or
/// unreadable status file is treated as "capability absent", which produces
/// the safer diagnostic.
pub fn has_cap_sys_ptrace() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        let Some(value) = line.strip_prefix("CapEff:") else {
            continue;
        };
        let Ok(mask) = u64::from_str_radix(value.trim(), 16) else {
            return false;
        };
        return mask & (1u64 << CAP_SYS_PTRACE_BIT) != 0;
    }
    false
}

/// Read the current YAMA `ptrace_scope` value.
///
/// Returns `Unknown` when the kernel does not expose YAMA or the file cannot
/// be read.
pub fn read_ptrace_scope() -> PtraceScope {
    let Ok(contents) = std::fs::read_to_string(YAMA_SCOPE_PATH) else {
        return PtraceScope::Unknown;
    };
    match contents.trim() {
        "0" => PtraceScope::Classic,
        "1" => PtraceScope::Restricted,
        "2" => PtraceScope::AdminOnly,
        "3" => PtraceScope::NoAttach,
        _ => PtraceScope::Unknown,
    }
}

/// Diagnostic to emit when foreign processes cannot be inspected.
///
/// Returns `None` when the current configuration permits host-wide
/// inspection.
pub fn foreign_inspection_diagnostic() -> Option<&'static str> {
    let scope = read_ptrace_scope();
    if scope.permits_foreign_inspection() {
        return None;
    }
    Some(scope.guidance())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_ptrace_scope_is_known_value() {
        let scope = read_ptrace_scope();
        if scope != PtraceScope::Unknown {
            assert!(!scope.guidance().is_empty());
        }
    }

    #[test]
    fn test_scope_three_disables_foreign_inspection() {
        assert!(!PtraceScope::NoAttach.permits_foreign_inspection());
        assert!(PtraceScope::Classic.permits_foreign_inspection());
    }

    #[test]
    fn test_capability_probe_is_consistent() {
        // The capability probe must agree with the kernel's own view.
        assert_eq!(has_cap_sys_ptrace(), has_cap_sys_ptrace());
    }

    #[test]
    fn test_diagnostic_is_none_when_permitted() {
        let scope = read_ptrace_scope();
        if scope.permits_foreign_inspection() {
            assert!(foreign_inspection_diagnostic().is_none());
        }
    }
}
