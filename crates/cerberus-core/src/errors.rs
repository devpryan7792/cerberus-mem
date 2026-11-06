use thiserror::Error;

/// Errors produced by process memory acquisition.
#[derive(Error, Debug)]
pub enum MemoryReaderError {
    /// The target process no longer exists (`ESRCH`).
    #[error("Target process {pid} does not exist (ESRCH)")]
    ProcessNotFound { pid: i32 },

    /// The caller lacks the required ptrace access (`EPERM` / `EACCES`).
    #[error("Permission denied reading PID {pid}: missing CAP_SYS_PTRACE or blocked by YAMA LSM (EPERM)")]
    PermissionDenied { pid: i32 },

    /// The requested address range is unmapped or faulted (`EFAULT`).
    #[error("Address range 0x{start:x}-0x{end:x} unmapped or faulted (EFAULT)")]
    MemoryFault { start: u64, end: u64 },

    /// An underlying I/O operation failed.
    #[error("IO error while reading process memory: {0}")]
    Io(#[from] std::io::Error),

    /// A syscall failed with an errno that is not independently classified.
    #[error("Syscall error ({errno}): {description}")]
    SyscallFailed { errno: i32, description: String },
}
