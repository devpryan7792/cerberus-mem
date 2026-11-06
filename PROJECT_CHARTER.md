# Project Charter: Linux In-Memory Forensics & EDR Evasion Detector (Cerberus-Mem)

**Repository Name**: `linux-mem-forensics`  
**Binary Name**: `cerberus-mem`  
**Target Platform**: Linux x86_64 / aarch64 (Linux Kernel >= 5.15 LTS)  
**Primary Language**: Rust (1.80+ Stable, `edition = "2021"`, Nightly for Miri / AddressSanitizer verification)  
**Classification**: Defensive Systems Security, Memory Forensics & Runtime Integrity Auditing  

---

## 1. Executive Summary & Problem Space

### 1.1 The Linux EDR Blind Spot
Over 95% of contemporary endpoint detection and response (EDR) engineering and publicly accessible offensive security research centers on Windows (`ntdll` unhooking, reflective DLL loading, process hollowing, early-bird APC injection). Conversely, enterprise Linux security monitoring historically relies almost entirely on legacy primitives:
1. **Auditd / Audit Subsystem**: High CPU overhead, easily overwhelmed by high-throughput IO, blind to in-memory code modifications that do not execute subsequent file-backed syscalls.
2. **Static Disk Scanners (ClamAV, YARA disk hooks)**: Wholly bypassed by fileless execution vectors such as anonymous memory file descriptors (`memfd_create`) and memory-only unpacking.
3. **Naive Procfs / Sysfs Scanners**: Easily spoofed via `/proc/[pid]/cmdline` or `/proc/[pid]/comm` rewriting, environment variable scrubbing, and unlinked file masking.

Modern Linux malware (e.g., Symbiote, BPFDoor, Shikitega, perf_event rootkits, and advanced cryptominers) actively leverages Linux virtual memory semantics to achieve zero-disk residence. Once executing in virtual memory, adversary code alters dynamic linker (`ld-linux.so`) data structures, overwrites Procedure Linkage Table (PLT) / Global Offset Table (GOT) entries, injects anonymous executable mappings via `/proc/[pid]/mem` or `process_vm_writev(2)`, or hollows legitimate daemon processes.

### 1.2 Mission Statement
`cerberus-mem` is a zero-compromise, high-performance in-memory forensics and evasion detection engine written in pure Rust. It operates as an authoritative forensic inspector that performs differential binary analysis between the immutable disk artifact and live virtual memory allocations (VMAs), detects unlinked execution, discovers hook trampolines, identifies GOT/PLT poisoning, and uncovers stealth in-memory thread execution without destabilizing host production workloads.

---

## 2. Threat Model & Adversarial Vector Taxonomy

```
+---------------------------------------------------------------------------------------------------+
|                                 LINUX IN-MEMORY ATTACK SURFACE                                    |
+---------------------------------------------------------------------------------------------------+
|  [Vector 1: Fileless Execution]                                                                    |
|    memfd_create(2) -> write(ELF) -> fexecve(2) / execveat(2)                                      |
|    Target: /proc/$PID/exe points to "/memfd:name (deleted)"                                       |
+---------------------------------------------------------------------------------------------------+
|  [Vector 2: Process Hollowing & Code Injection]                                                   |
|    ptrace(PTRACE_ATTACH) / process_vm_writev(2) / /proc/$PID/mem write                             |
|    Target: Overwriting .text segment with shellcode; Divergence between AT_ENTRY and active RIP    |
+---------------------------------------------------------------------------------------------------+
|  [Vector 3: Dynamic Shared Object (DSO) & Linker Tampering]                                       |
|    GOT Hijacking: Overwriting function pointers in .got.plt to redirect to payload                |
|    Inline Hooking: Hot-patching 5-byte/12-byte JMP trampolines into libc.so (e.g., read, write)    |
|    Preload Hijacking: Injecting rogue DSOs via LD_PRELOAD or in-memory dynamic link maps          |
+---------------------------------------------------------------------------------------------------+
|  [Vector 4: Memory Permission Anomalies & Stack Pivoting]                                         |
|    W^X Violations: Pages allocated or transitioned to PROT_READ | PROT_WRITE | PROT_EXEC           |
|    Anonymous Executable Pages: Executable regions lacking backing file or marked as [anon]        |
|    Stack Pivoting: RSP pointing outside designated [stack] VMA into anonymous heap or mmap region |
+---------------------------------------------------------------------------------------------------+
```

### 2.1 Vector 1: Fileless Execution via Anonymous Memory Descriptors
* **Mechanism**: Adversary invokes `memfd_create("kworker", MFD_CLOEXEC)`, streams a raw ELF binary into the resulting anonymous file descriptor, and triggers execution via `fexecve(fd, argv, envp)` or `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.
* **Footprint**: The resulting process has no valid backing inode on a physical or pseudo filesystem. In `/proc/[pid]/exe`, the symlink resolves to a path ending in ` (deleted)` or explicitly begins with `/memfd:`.
* **Forensic Objective**: Detect all processes executing out of RAM-backed memory file descriptors, extract the raw ELF binary directly from memory, and calculate cryptographic hashes (SHA-256) for threat intelligence attribution.

### 2.2 Vector 2: Process Hollowing & Virtual Memory Injection
* **Mechanism**: 
  1. Adversary spawns a benign host process (e.g., `/usr/sbin/sshd` or `sleep 86400`).
  2. Adversary attaches via `ptrace(PTRACE_ATTACH, pid)` or opens `/proc/[pid]/mem` with `O_RDWR`.
  3. The base image's `.text` code section or dynamic heap is overwritten with malicious payload code.
  4. Registers (`RIP`, `RSP`) are manipulated via `ptrace(PTRACE_SETREGS)` or stack frames are adjusted to redirect execution flow.
* **Footprint**:
  - Divergence between the disk-backed ELF `.text` hash and the live memory `.text` VMA hash.
  - The process's entry point (`AT_ENTRY` auxiliary vector) does not match the initial execution trajectory.
  - Discrepancy between thread instruction pointer register (`RIP`) and known valid symbol boundaries in loaded ELFs.
* **Forensic Objective**: Byte-level differential analysis between on-disk ELF segments and in-memory VMAs, isolating exact hooked or hollowed byte ranges.

### 2.3 Vector 3: DSO & Dynamic Linker Tampering
* **Mechanism**:
  - **PLT/GOT Redirection**: ELF binaries compiled without full RELRO (`-z relro -z now`) leave the Global Offset Table (`.got.plt`) writable (`PROT_READ | PROT_WRITE`). Malware overwrites function addresses (e.g., `connect`, `sendto`, `getpwnam`) with pointers to injected code.
  - **Inline Trampoline Hooking**: Overwriting the prelude of standard library functions in `libc.so` (e.g., `sys_read`, `sys_write`) with an absolute jump instruction (`movabs $target, %rax; jmpq *%rax`) to intercept execution before returning to the original function.
  - **Link Map Injection**: Traversal of the runtime linker's internal linked list (`struct link_map` in glibc) to insert hidden shared libraries not present in `/proc/[pid]/maps` or disk configuration.
* **Forensic Objective**: Inspect all entries in `.got` and `.got.plt` to ensure every target address resolves within the legitimate `.text` segment of the expected shared object. Disassemble the first 16 bytes of exported symbol entries in shared libraries to detect foreign `JMP` / `CALL` trampolines.

### 2.4 Vector 4: Memory Mapping Anomalies & W^X Violations
* **Mechanism**: Shellcode execution engines (e.g., Metasploit, Cobalt Strike Linux stagers) require memory that is both writable (for staging) and executable (for running). Alternatively, they allocate `PROT_READ | PROT_WRITE`, write shellcode, and invoke `mprotect(addr, len, PROT_READ | PROT_EXEC)`.
* **Footprint**:
  - Virtual memory areas (VMAs) exhibiting `rwxp` permissions.
  - Anonymous memory allocations (`[anon]`) marked with `PROT_EXEC` that are not the official thread stacks or authorized JIT runtimes (V8, JVM, Mono).
  - Threads whose Stack Pointer (`RSP`) points outside the thread's designated stack VMA (detected via `/proc/[pid]/task/[tid]/stat` and `maps`).
* **Forensic Objective**: Scan and categorize every VMA across all running processes, alerting on anomalous executable anonymous pages, W^X violations, and stack pivots.

---

## 3. High-Level Technical Objectives

1. **Zero Crash Guarantee**: Under no circumstances should forensic inspection trigger a kernel panic, target process crash (`SIGSEGV`, `SIGBUS`), or thread deadlock. Inspection must default to passive, zero-copy kernel syscalls (`process_vm_readv(2)`).
2. **Minimal Target Overhead**: Scanning must execute in sub-millisecond windows per target process. For a typical system running 300 processes with 15,000 combined VMAs, a complete host memory integrity sweep must complete in under 500 milliseconds on modern multi-core x86_64 hardware.
3. **Deterministic Differential Analysis**: Eliminate false positives caused by runtime relocations (`R_X86_64_RELATIVE`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`) and copy-on-write (`COW`) zero-page allocations by applying relocation masks before computing cryptographic hashes.
4. **Autonomous JIT Classification**: Provide configurable heuristic engines to distinguish legitimate Just-In-Time compilers (NodeJS, Java, Chromium) from rogue anonymous shellcode injectors.
5. **Machine-Readable Forensic Output**: Export all findings in structured JSON-Lines (`.jsonl`) format adhering to strict schema definitions, facilitating ingestion into SIEMs (Splunk, Elastic) or security data pipelines.

---

## 4. Operational Boundaries & Non-Goals

### 4.1 In Scope
- Deep differential analysis of ELF binaries and loaded DSOs for running processes.
- Parsing of Linux procfs (`/proc/[pid]/maps`, `/proc/[pid]/smaps`, `/proc/[pid]/auxv`, `/proc/[pid]/mem`, `/proc/[pid]/status`, `/proc/[pid]/cmdline`).
- High-performance, zero-allocation memory extraction using `process_vm_readv(2)`.
- Verification of GOT/PLT pointer integrity against dynamic linker metadata.
- Extraction of dumped memory regions, reconstructed ELFs, and suspicious payloads to an isolated quarantine directory with strict permission controls (`0700`, owned by root).
- Generation of forensic reports with cryptographic hashes (SHA-256), entropy scores, and disassembly of detected hook trampolines.

### 4.2 Out of Scope / Non-Goals
- **Active Process Termination**: `cerberus-mem` is a forensic discovery and verification engine. It will not execute `kill -9` or forcefully unmap pages; process mitigation belongs to EDR remediation daemons.
- **Kernel-Space Rootkit Removal**: If an adversary has compromised ring 0 (kernel space) with an LKM or corrupted `/proc` via eBPF fexit hooks, userland procfs cannot be fully trusted. Detection of ring 0 rootkits requires dedicated kernel integrity tools.
- **Windows / macOS Support**: `cerberus-mem` is strictly engineered for the Linux kernel ABI and ELF specifications.

---

## 5. Security & Permission Constraints

1. **Privilege Requirements**: Full memory inspection across foreign user namespaces requires `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The binary should run as root or with specific file capabilities:
   ```bash
   sudo setcap cap_sys_ptrace,cap_dac_read_search+ep target/release/cerberus-mem
   ```
2. **Ptrace YAMA LSM Awareness**: On systems with `/proc/sys/kernel/yama/ptrace_scope` set to 1, 2, or 3, direct `ptrace` usage is heavily restricted. `cerberus-mem` prioritizes `process_vm_readv(2)` and `/proc/[pid]/mem` file descriptors, which operate under `PTRACE_MODE_READ_REALCREDS`.
3. **Safe File Handling**: Any memory dump written to disk must be written with the `O_NOFOLLOW` and `O_CREAT | O_EXCL` flags in a secure, non-world-writable directory (`/var/log/cerberus/dumps/`) to prevent symlink attacks and race conditions (`TOCTOU`).

---

## 6. Stakeholders & Success Criteria

| Role | Responsibility | Success Metric |
| :--- | :--- | :--- |
| **Principal Architect** | System design, kernel ABI contract enforcement, zero-unsafe leak | 100% test coverage under Miri; zero memory leaks or UB |
| **OpenCode (Junior Dev)** | Implementation of micro-phases as defined in `PHASED_IMPLEMENTATION.md` | Code passes all CI gates, strictly meets trait contracts |
| **Security Engineer** | Threat validation, synthetic hollower test harnesses | 100% detection rate on test suite; zero false positives on benign base system |
| **Incident Responder** | Operational triage, output consumption | Forensic reports parse cleanly in `jq`, provide actionable shellcode disassembly |
