# Phased Implementation Specification: Cerberus-Mem

**Target Artifact**: `linux-mem-forensics`  
**Classification**: Implementation Specification for Junior Developers & Autonomous Agents  
**Author**: Principal Systems Architect  
**Strict Directive**: ZERO VIBE-CODING. Implement code strictly according to the defined structs, function signatures, algorithms, and verification gates below.

---

## 1. Workspace Layout & Module Architecture

The project must be structured as a Cargo workspace with granular crate separation to ensure strict compile boundaries and fast iteration:

```
linux-mem-forensics/
├── Cargo.toml                          # Workspace root
├── crates/
│   ├── cerberus-core/                  # Low-level syscalls & memory reading abstractions
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── syscalls.rs             # Direct libc/syscall bindings for process_vm_readv
│   │       ├── reader.rs               # MemoryReader trait and chunked reading engine
│   │       └── errors.rs               # Core error types
│   ├── cerberus-procfs/                # Zero-allocation procfs parsing
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── maps.rs                 # Zero-alloc streaming /proc/[pid]/maps parser
│   │       ├── auxv.rs                 # Auxiliary vector parser (AT_ENTRY, AT_PHDR)
│   │       ├── status.rs               # Status, comm, cmdline parser
│   │       └── process.rs              # System-wide process enumerator
│   ├── cerberus-elf/                   # ELF binary and relocation analysis
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── disk.rs                 # On-disk ELF header and segment reader
│   │       ├── reloc.rs                # Relocation mask generator for dynamic symbols
│   │       └── dynamic.rs              # Dynamic section, GOT, PLT, and dynsym parser
│   ├── cerberus-detect/                # Threat detection heuristic engines
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── fileless.rs             # memfd_create and deleted executable detector
│   │       ├── wxorx.rs                # W^X and anonymous executable VMA scanner
│   │       ├── hollowing.rs            # Differential memory vs disk .text analyzer
│   │       ├── got_poison.rs           # Out-of-bounds GOT/PLT pointer detector
│   │       └── inline_hook.rs          # Function prologue JMP trampoline disassembler
│   ├── cerberus-report/                # Reporting and artifact quarantine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── models.rs               # Forensic finding data structures
│   │       ├── jsonl.rs                # JSON-Lines streaming emitter
│   │       └── quarantine.rs           # Secure memory dumper with 0700 permissions
│   └── cerberus-cli/                   # Command-line interface and scanner daemon
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           └── scan.rs                 # Multi-threaded Rayon scanning orchestrator
└── tests/                              # Integration & adversarial test harnesses
    ├── synthetic_memfd.rs              # Anonymous memfd_create test binary
    ├── synthetic_hollower.rs           # In-memory code overwriter test binary
    └── synthetic_got_hooker.rs         # Self-GOT-patching test binary
```

---

## 2. Micro-Phase 1: Workspace & Root Cargo Configuration

### File: `Cargo.toml`
Create the workspace manifest:
```toml
[workspace]
resolver = "2"
members = [
    "crates/cerberus-core",
    "crates/cerberus-procfs",
    "crates/cerberus-elf",
    "crates/cerberus-detect",
    "crates/cerberus-report",
    "crates/cerberus-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["Dev Team <dev@local>"]
license = "Apache-2.0"

[workspace.dependencies]
libc = "0.2.158"
bitflags = "2.6.0"
thiserror = "1.0.63"
serde = { version = "1.0.209", features = ["derive"] }
serde_json = "1.0.128"
goblin = "0.8.2"
rayon = "1.10.0"
clap = { version = "4.5.17", features = ["derive"] }
sha2 = "0.10.8"
log = "0.4.22"
env_logger = "0.11.5"
iced-x86 = { version = "1.21.0", default-features = false, features = ["decoder", "no_std"] }
```

### Verification Gate
Execute:
```bash
cargo check
```
Must compile with zero errors.

---

## 3. Micro-Phase 2: Core Syscall Abstraction & Resilient Memory Reader

### Target Files
- `crates/cerberus-core/src/syscalls.rs`
- `crates/cerberus-core/src/reader.rs`
- `crates/cerberus-core/src/errors.rs`

### Contracts & Signatures

#### `crates/cerberus-core/src/errors.rs`
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryReaderError {
    #[error("Target process {pid} does not exist (ESRCH)")]
    ProcessNotFound { pid: i32 },

    #[error("Permission denied reading PID {pid}: missing CAP_SYS_PTRACE or blocked by YAMA LSM (EPERM)")]
    PermissionDenied { pid: i32 },

    #[error("Address range 0x{start:x}-0x{end:x} unmapped or faulted (EFAULT)")]
    MemoryFault { start: u64, end: u64 },

    #[error("IO error while reading process memory: {0}")]
    Io(#[from] std::io::Error),

    #[error("Syscall error ({errno}): {description}")]
    SyscallFailed { errno: i32, description: String },
}
```

#### `crates/cerberus-core/src/syscalls.rs`
```rust
use libc::{c_int, c_long, c_ulong, c_void, pid_t, size_t, syscall, SYS_process_vm_readv};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RemoteIoVec {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

unsafe impl Send for RemoteIoVec {}
unsafe impl Sync for RemoteIoVec {}

pub unsafe fn direct_process_vm_readv(
    pid: pid_t,
    local_iov: *const RemoteIoVec,
    liovcnt: c_ulong,
    remote_iov: *const RemoteIoVec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> Result<usize, i32> {
    let ret = syscall(
        SYS_process_vm_readv,
        pid as c_long,
        local_iov,
        liovcnt,
        remote_iov,
        riovcnt,
        flags,
    );

    if ret < 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(ret as usize)
    }
}
```

#### `crates/cerberus-core/src/reader.rs`
```rust
use crate::errors::MemoryReaderError;
use crate::syscalls::{direct_process_vm_readv, RemoteIoVec};
use std::os::unix::io::RawFd;

pub trait ProcessMemoryReader: Send + Sync {
    fn read_memory(&self, pid: i32, remote_addr: u64, buf: &mut [u8]) -> Result<usize, MemoryReaderError>;
}

pub struct DirectSyscallReader;

impl DirectSyscallReader {
    pub fn new() -> Self {
        Self
    }

    /// Reads memory with automatic page-level subdivision on EFAULT
    fn read_chunk_resilient(
        &self,
        pid: i32,
        mut remote_addr: u64,
        mut buf: &mut [u8],
    ) -> Result<usize, MemoryReaderError> {
        let mut total_read = 0usize;
        let page_size = 4096u64;

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

            let res = unsafe {
                direct_process_vm_readv(pid, &local, 1, &remote, 1, 0)
            };

            match res {
                Ok(bytes) => {
                    total_read += bytes;
                    if bytes == chunk_len {
                        break;
                    }
                    remote_addr += bytes as u64;
                    buf = &mut buf[bytes..];
                }
                Err(libc::EFAULT) => {
                    // Page fault: Subdivide into individual 4096-byte page reads
                    let bytes_to_next_page = (page_size - (remote_addr % page_size)) as usize;
                    let step = bytes_to_next_page.min(buf.len());

                    let page_local = RemoteIoVec {
                        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: step,
                    };
                    let page_remote = RemoteIoVec {
                        iov_base: remote_addr as *mut libc::c_void,
                        iov_len: step,
                    };

                    let page_res = unsafe {
                        direct_process_vm_readv(pid, &page_local, 1, &page_remote, 1, 0)
                    };

                    match page_res {
                        Ok(b) => {
                            total_read += b;
                        }
                        Err(libc::EFAULT) => {
                            // Uncommitted page: fill buffer with zero and advance
                            buf[..step].fill(0);
                        }
                        Err(errno) => return Err(map_errno(pid, errno)),
                    }

                    remote_addr += step as u64;
                    buf = &mut buf[step..];
                }
                Err(errno) => return Err(map_errno(pid, errno)),
            }
        }

        Ok(total_read)
    }
}

impl ProcessMemoryReader for DirectSyscallReader {
    fn read_memory(&self, pid: i32, remote_addr: u64, buf: &mut [u8]) -> Result<usize, MemoryReaderError> {
        self.read_chunk_resilient(pid, remote_addr, buf)
    }
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
```

### Verification Gate
Write unit tests in `crates/cerberus-core/tests/reader_test.rs`:
1. Read memory of current process (`std::process::id()`) from a known stack string variable. Verify exact match.
2. Read an invalid memory address (`0x0` or `0xdeadbeef000`). Assert returns `MemoryReaderError::MemoryFault` or zero-filled on unmapped page.

---

## 4. Micro-Phase 3: Zero-Allocation Streaming Procfs Maps Parser

### Target Files
- `crates/cerberus-procfs/src/maps.rs`

### Contracts & Signatures
Implement `MapsParser<'a>` as specified in `ARCHITECTURE_SPEC.md` Section 3.3.

#### Algorithm Steps:
1. Open `/proc/[pid]/maps` using `std::fs::File` and read contents into a pre-allocated stack/heap buffer (reuse across sweeps).
2. Scan buffer line by line using single-byte delimiter `\n` without allocating new `String` instances.
3. For each line, parse:
   - Hex start and end addresses separated by `-`.
   - 4-character permissions string (`rwxp`, `r-xs`, etc.) into `VmaProtection` bitflags.
   - Offset hex into `u64`.
   - Device major:minor hex into `u32`.
   - Inode decimal into `u64`.
   - Pathname classification:
     - Empty -> `VmaBacking::Anonymous`
     - `[heap]` -> `VmaBacking::Heap`
     - `[stack*]` -> `VmaBacking::Stack`
     - `[vdso]` -> `VmaBacking::Vdso`
     - `[vvar]` -> `VmaBacking::Vvar`
     - Starts with `/memfd:` -> `VmaBacking::Memfd(name)`
     - Ends with ` (deleted)` -> `VmaBacking::Deleted(clean_path)`
     - Other -> `VmaBacking::File(path)`

### Verification Gate
Execute:
```bash
cargo test -p cerberus-procfs -- test_maps_parsing
```
Test with synthetic maps files containing standard lines, deleted binaries, anonymous pages, and memfd mappings.

---

## 5. Micro-Phase 4: Auxiliary Vector & Process Metadata Extraction

### Target Files
- `crates/cerberus-procfs/src/auxv.rs`
- `crates/cerberus-procfs/src/status.rs`

### Contracts & Signatures

#### `crates/cerberus-procfs/src/auxv.rs`
```rust
pub struct AuxvReader;

impl AuxvReader {
    pub fn read_anchors(pid: i32) -> Result<ProcessAuxvAnchors, std::io::Error> {
        let path = format!("/proc/{}/auxv", pid);
        let data = std::fs::read(path)?;
        ProcessAuxvAnchors::parse_from_bytes(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
```

#### `crates/cerberus-procfs/src/status.rs`
```rust
pub struct ProcessMetadata {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub exe_target: Option<std::path::PathBuf>,
    pub is_exe_deleted: bool,
}

impl ProcessMetadata {
    pub fn extract(pid: i32) -> Result<Self, std::io::Error> {
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))?
            .trim_end_matches('\n')
            .to_string();

        let cmdline_raw = std::fs::read(format!("/proc/{}/cmdline", pid))?;
        let cmdline: Vec<String> = cmdline_raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();

        let exe_link = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();
        let is_exe_deleted = match &exe_link {
            Some(path) => path.to_string_lossy().ends_with(" (deleted)"),
            None => false,
        };

        Ok(Self {
            pid,
            ppid: 0,
            comm,
            cmdline,
            exe_target: exe_link,
            is_exe_deleted,
        })
    }
}
```

### Verification Gate
Verify reading metadata of current process: ensure `exe_target` points to the test runner binary and `comm` matches `cargo` or the test binary name.

---

## 6. Micro-Phase 5: Fileless & W^X Detection Engine

### Target Files
- `crates/cerberus-detect/src/fileless.rs`
- `crates/cerberus-detect/src/wxorx.rs`

### Implementation Logic

#### `crates/cerberus-detect/src/fileless.rs`
```rust
use cerberus_procfs::maps::{VmaBacking, VmaRecord};
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};

pub fn check_fileless_execution(
    meta: &ProcessMetadata,
    vmas: &[VmaRecord],
) -> Vec<ForensicFinding> {
    let mut findings = Vec::new();

    // Check 1: /proc/$PID/exe pointing to memfd
    if let Some(exe_path) = &meta.exe_target {
        let exe_str = exe_path.to_string_lossy();
        if exe_str.starts_with("/memfd:") || exe_str.contains("memfd:") {
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity: Severity::Critical,
                anomaly_type: AnomalyType::FilelessMemfdExecution,
                description: format!("Process executable is backed by anonymous memory file descriptor: {}", exe_str),
                affected_address_range: (0, 0),
                backing_detail: exe_str.to_string(),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        } else if meta.is_exe_deleted {
            findings.push(ForensicFinding {
                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                target_pid: meta.pid as u32,
                process_comm: meta.comm.clone(),
                process_cmdline: meta.cmdline.clone(),
                severity: Severity::High,
                anomaly_type: AnomalyType::DeletedBinaryExecution,
                description: format!("Process executable has been unlinked from disk: {}", exe_str),
                affected_address_range: (0, 0),
                backing_detail: exe_str.to_string(),
                disk_hash_sha256: None,
                mem_hash_sha256: None,
                extracted_divergence_bytes: None,
                disassembly_snippet: None,
            });
        }
    }

    findings
}
```

#### `crates/cerberus-detect/src/wxorx.rs`
Inspect every `VmaRecord` in the process:
- If `vma.is_rwx()` -> Flag as `AnomalyType::WxorXViolation` with `Severity::High`.
- If `vma.is_anonymous_exec()` -> Flag as `AnomalyType::AnonymousExecutableMapping` with `Severity::Medium` (or `Critical` if size > 64KB and not an authorized JIT runtime).

---

## 7. Micro-Phase 6: Disk vs. Memory Differential Engine

### Target Files
- `crates/cerberus-elf/src/disk.rs`
- `crates/cerberus-elf/src/reloc.rs`
- `crates/cerberus-detect/src/hollowing.rs`

### Implementation Logic
1. **Load On-Disk Binary**: Read executable file pointed to by `/proc/[pid]/exe`. Parse ELF using `goblin::elf::Elf`.
2. **Locate `.text` Section & Dynamic Relocations**:
   - Extract `.text` file offset, size, and runtime virtual address (`sh_addr`).
   - Extract dynamic relocations (`.rela.dyn`, `.rela.plt`). For each relocation falling within the `.text` virtual address range, calculate the exact relative offset within `.text`.
   - Build a `RelocationMask` containing these intervals.
3. **Read Live Memory `.text`**:
   - Query VMA map for the region covering `.text` runtime address.
   - Using `DirectSyscallReader`, read the exact `.text` byte span from target process virtual memory.
4. **Apply Mask & Compare**:
   - Apply `RelocationMask` to zero out relocation sites on both disk buffer and memory buffer.
   - Compute SHA-256 of masked disk bytes and masked memory bytes.
   - If hashes diverge:
     - Scan byte by byte to find divergent blocks.
     - Extract up to 64 bytes of modified memory.
     - Disassemble using `iced-x86` decoder to reveal injected instructions.
     - Flag `AnomalyType::ProcessHollowing` or `TextSegmentModification`.

---

## 8. Micro-Phase 7: GOT/PLT Table & Inline Trampoline Verifier

### Target Files
- `crates/cerberus-elf/src/dynamic.rs`
- `crates/cerberus-detect/src/got_poison.rs`
- `crates/cerberus-detect/src/inline_hook.rs`

### Implementation Logic
1. **GOT Poisoning**:
   - Parse `.got.plt` from disk binary to identify relocations (`R_X86_64_JUMP_SLOT`) and their target symbol names.
   - For each slot, read the 8-byte pointer from the running process memory.
   - Check against `VmaRecord` collection:
     - Pointer must resolve inside an executable VMA belonging to an authorized DSO (e.g. `libc.so`, `libpthread.so`).
     - If pointer points to anonymous memory (`[anon]`, `[heap]`, or stack), flag `AnomalyType::GotPltHijack`.
2. **Inline Trampoline Hooking**:
   - For critical functions (`libc.so!read`, `libc.so!write`, `libc.so!connect`, `libc.so!execve`):
     - Read the first 16 bytes of the function from the target process's mapped `libc.so`.
     - Decode instructions using `iced-x86`.
     - Check if instruction 0 is an absolute or relative jump:
       - `JMP rel32` (`0xE9 ...`)
       - `MOVABS %rax, <imm64>; JMP *%rax`
       - `JMPQ *(%rip)`
     - Calculate target address. If target points outside `libc.so` `.text`, flag `AnomalyType::InlineFunctionHook`.

---

## 9. Micro-Phase 8: Multi-Threaded Host Scanner & CLI Orchestrator

### Target Files
- `crates/cerberus-cli/src/main.rs`
- `crates/cerberus-cli/src/scan.rs`

### Command-Line Interface Specification
```bash
# Scan a specific PID with detailed console output
cerberus-mem --pid 1337

# Perform a full host sweep across all active PIDs
cerberus-mem --all --jsonl /var/log/cerberus/findings.jsonl

# Continuous daemon mode: sweep every 30 seconds
cerberus-mem --daemon --interval 30 --quarantine-dir /var/log/cerberus/quarantine/
```

### Scanner Flow:
```rust
pub fn sweep_host(config: &ScanConfig) -> Vec<ForensicFinding> {
    let pids = cerberus_procfs::process::enumerate_all_pids().unwrap();
    let reader = DirectSyscallReader::new();

    pids.into_par_iter()
        .flat_map(|pid| {
            scan_process(pid, &reader, config)
        })
        .collect()
}
```

---

## 10. Micro-Phase 9: Synthetic Threat Test Harnesses

### Target Files
- `tests/synthetic_memfd.rs`
- `tests/synthetic_hollower.rs`
- `tests/synthetic_got_hooker.rs`

### 1. `tests/synthetic_memfd.rs`
- Spawns child using `memfd_create("payload", MFD_CLOEXEC)`.
- Writes minimal statically linked ELF (`x86_64` shell that executes `pause()`).
- Calls `fexecve(fd, ...)`.
- Integration test runs `cerberus-mem --pid <child_pid>` and asserts finding with `AnomalyType::FilelessMemfdExecution`.

### 2. `tests/synthetic_hollower.rs`
- Spawns child running `sleep 60`.
- Attaches or opens `/proc/[child_pid]/mem`.
- Overwrites `.text` with a NOP sled (`0x90...`) and `int3` or `pause`.
- Integration test asserts finding with `AnomalyType::ProcessHollowing`.

---

## 11. Acceptance & Anti-Vibe-Coding Checklist

Before declaring any micro-phase complete, OpenCode must verify:
- [ ] No `unwrap()` on runtime inputs (`/proc` reads, syscall returns, user arguments). All errors must propagate via `Result<T, E>`.
- [ ] Direct syscalls use `libc::syscall` with proper errno checking via `libc::__errno_location()`.
- [ ] All buffers passed to `process_vm_readv` must be page-aligned or handled cleanly across 4KB page boundaries.
- [ ] Zero compiler warnings with `cargo clippy --all-targets -- -D warnings`.
- [ ] Miri verification passes on pointer handling routines.
