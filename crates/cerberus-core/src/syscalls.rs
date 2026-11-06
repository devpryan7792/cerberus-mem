//! Direct Linux syscall bindings.
//!
//! These wrappers deliberately bypass libc's `process_vm_readv` symbol so the
//! engine controls errno handling and can observe the raw syscall result.

use libc::{c_long, c_ulong, c_void, pid_t, size_t, syscall, SYS_process_vm_readv};

/// A single remote I/O vector, ABI-compatible with `struct iovec`.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RemoteIoVec {
    /// Base address of the buffer.
    pub iov_base: *mut c_void,
    /// Length of the buffer in bytes.
    pub iov_len: size_t,
}

// SAFETY: `RemoteIoVec` is a plain data description of caller-owned buffers.
// Moving the descriptor between threads does not transfer ownership of the
// pointed-to memory; callers remain responsible for upholding the validity and
// aliasing rules of the referenced buffers.
unsafe impl Send for RemoteIoVec {}
// SAFETY: See the `Send` implementation above. The type has no interior
// mutability of its own.
unsafe impl Sync for RemoteIoVec {}

/// Invoke `process_vm_readv(2)` directly and return either the transferred byte
/// count or the raw errno value.
///
/// # Safety
///
/// `local_iov` and `remote_iov` must point to valid arrays of at least
/// `liovcnt` / `riovcnt` initialized `RemoteIoVec` entries, and the buffers
/// they describe must be valid for the requested lengths. `remote_iov` entries
/// refer to addresses in the target process identified by `pid`.
pub unsafe fn direct_process_vm_readv(
    pid: pid_t,
    local_iov: *const RemoteIoVec,
    liovcnt: c_ulong,
    remote_iov: *const RemoteIoVec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> Result<usize, i32> {
    // SAFETY: The caller upholds the pointer and lifetime requirements; the
    // kernel reads the iovec arrays and writes only to the local buffers.
    let ret = unsafe {
        syscall(
            SYS_process_vm_readv,
            pid as c_long,
            local_iov,
            liovcnt,
            remote_iov,
            riovcnt,
            flags,
        )
    };

    if ret < 0 {
        // SAFETY: `__errno_location` returns a valid pointer to this thread's
        // errno slot; the syscall wrapper does not modify it before this read.
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(ret as usize)
    }
}
