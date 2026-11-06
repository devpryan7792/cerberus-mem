//! Resilient process memory reading built on `process_vm_readv(2)`.

use crate::errors::MemoryReaderError;
use crate::syscalls::{direct_process_vm_readv, RemoteIoVec};

/// Fallback page size used only if `sysconf(_SC_PAGESIZE)` unexpectedly fails.
const FALLBACK_PAGE_SIZE: usize = 4096;

/// Read memory from another process without pausing it.
pub trait ProcessMemoryReader: Send + Sync {
    /// Read up to `buf.len()` bytes starting at `remote_addr` in `pid`.
    ///
    /// Returns the number of bytes actually transferred. Pages that are
    /// unmapped or faulted are zero-filled in `buf` but are not counted in the
    /// returned byte count, allowing callers to detect incomplete acquisitions.
    fn read_memory(
        &self,
        pid: i32,
        remote_addr: u64,
        buf: &mut [u8],
    ) -> Result<usize, MemoryReaderError>;
}

/// Memory reader that uses `process_vm_readv(2)` exclusively.
///
/// The kernel page size is resolved once at construction so the page-by-page
/// `EFAULT` fallback also works on aarch64 systems with 16 KiB or 64 KiB pages.
pub struct DirectSyscallReader {
    page_size: usize,
}

impl DirectSyscallReader {
    /// Create a reader and resolve the host page size.
    pub fn new() -> Self {
        let page_size = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            value if value > 0 => value as usize,
            _ => FALLBACK_PAGE_SIZE,
        };
        Self { page_size }
    }

    /// Create a reader with an explicitly supplied page size.
    ///
    /// A zero page size is rejected and replaced with the fallback so the
    /// subdivision logic can never divide by zero.
    pub fn with_page_size(page_size: usize) -> Self {
        Self {
            page_size: if page_size == 0 {
                FALLBACK_PAGE_SIZE
            } else {
                page_size
            },
        }
    }

    /// Page size used for `EFAULT` subdivision.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Read memory with automatic page-level subdivision on `EFAULT`.
    ///
    /// Unreadable pages are zero-filled and advance the cursor, but their bytes
    /// are not included in the returned count.
    fn read_chunk_resilient(
        &self,
        pid: i32,
        mut remote_addr: u64,
        mut buf: &mut [u8],
    ) -> Result<usize, MemoryReaderError> {
        let mut total_read = 0usize;
        let page_size = self.page_size as u64;

        while !buf.is_empty() {
            let chunk_len = buf.len();
            let local = RemoteIoVec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: chunk_len,
            };
            let remote = RemoteIoVec {
                iov_base: remote_addr as *mut libc::c_void,
                iov_len: chunk_len,
            };

            // SAFETY: Both iovec arrays contain one initialized entry, the
            // local buffer is valid for `chunk_len` bytes, and the remote range
            // is validated by the kernel.
            let res = unsafe { direct_process_vm_readv(pid, &local, 1, &remote, 1, 0) };

            match res {
                Ok(bytes) if bytes == chunk_len => {
                    total_read += bytes;
                    break;
                }
                Ok(bytes) if bytes > 0 => {
                    total_read += bytes;
                    remote_addr = advance_address(remote_addr, bytes)?;
                    buf = &mut buf[bytes..];
                }
                Ok(_) | Err(libc::EFAULT) => {
                    // The block read made no progress or hit an unmapped page.
                    // Subdivide to the next page boundary and retry.
                    let bytes_to_next_page = page_size - (remote_addr % page_size);
                    let step = bytes_to_next_page.min(buf.len() as u64) as usize;

                    let page_local = RemoteIoVec {
                        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: step,
                    };
                    let page_remote = RemoteIoVec {
                        iov_base: remote_addr as *mut libc::c_void,
                        iov_len: step,
                    };

                    // SAFETY: Same invariants as the block read above, with a
                    // range bounded by one page.
                    let page_res =
                        unsafe { direct_process_vm_readv(pid, &page_local, 1, &page_remote, 1, 0) };

                    match page_res {
                        Ok(0) | Err(libc::EFAULT) => {
                            // Uncommitted or unmapped page: zero-fill and skip.
                            buf[..step].fill(0);
                        }
                        Ok(bytes) if bytes < step => {
                            // Mapping ended partway through the page.
                            total_read += bytes;
                            buf[bytes..step].fill(0);
                        }
                        Ok(bytes) => {
                            total_read += bytes;
                        }
                        Err(errno) => return Err(map_errno(pid, errno)),
                    }

                    remote_addr = advance_address(remote_addr, step)?;
                    buf = &mut buf[step..];
                }
                Err(errno) => return Err(map_errno(pid, errno)),
            }
        }

        Ok(total_read)
    }
}

impl Default for DirectSyscallReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMemoryReader for DirectSyscallReader {
    fn read_memory(
        &self,
        pid: i32,
        remote_addr: u64,
        buf: &mut [u8],
    ) -> Result<usize, MemoryReaderError> {
        self.read_chunk_resilient(pid, remote_addr, buf)
    }
}

fn advance_address(address: u64, delta: usize) -> Result<u64, MemoryReaderError> {
    address
        .checked_add(delta as u64)
        .ok_or_else(|| MemoryReaderError::SyscallFailed {
            errno: libc::EOVERFLOW,
            description: "remote address overflow while advancing read cursor".to_string(),
        })
}

fn map_errno(pid: i32, errno: i32) -> MemoryReaderError {
    match errno {
        libc::ESRCH => MemoryReaderError::ProcessNotFound { pid },
        libc::EPERM | libc::EACCES => MemoryReaderError::PermissionDenied { pid },
        _ => MemoryReaderError::SyscallFailed {
            errno,
            description: std::io::Error::from_raw_os_error(errno).to_string(),
        },
    }
}
