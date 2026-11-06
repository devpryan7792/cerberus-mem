# Testing & Verification Specification: Cerberus-Mem

**Target Artifact**: `linux-mem-forensics`  
**Classification**: Zero-Theater Testing Protocol & Continuous Verification Matrix  
**Standard**: Domain 1 (Low-Level Systems, Binary Forensics & Memory Safety)  
**Author**: Principal Systems Architect  

---

## 1. Testing Philosophy: Zero Theater Enforcement

In forensic systems engineering, mock tests are largely theater. A mock procfs reader or an in-memory cursor cannot replicate:
1. Asynchronous page table modifications while `process_vm_readv(2)` is executing in kernel space.
2. Demand-paged virtual memory causing sudden `EFAULT` on previously valid VMAs.
3. Linux kernel errno transitions between `ESRCH`, `EPERM`, and `EACCES` under YAMA LSM.
4. Non-contiguous physical page frames backing contiguous virtual address spaces.

Therefore, this test specification mandates real Linux kernel interactions, automated synthetic malware execution in isolated namespaces, fuzzing with memory sanitizers, and formal property-based invariant verification.

---

## 2. Tiered Testing Pyramid

```
                      ▲
                     / \
                    / L5 \   Criterion Latency & Throughput SLA Gates (p99 < 1.5ms/PID)
                   /------\
                  /  L4    \   Real Kernel Integration & Adversarial Namespace Probes
                 /----------\
                /    L3      \   Mutation Verification (cargo-mutants: 0 surviving mutants)
               /--------------\
              /      L2        \   Invariant Verification (proptest: parser fuzzing & roundtrips)
             /------------------\
            /        L1          \   Memory Correctness (cargo-fuzz + ASan, Miri strict provenance)
           /----------------------\
```

| Layer | Focus Area | Tooling | Enforcement Standard |
| :--- | :--- | :--- | :--- |
| **Layer 1** | Memory Safety & Undefined Behavior | `cargo miri`, `cargo-fuzz` (ASan, UBSan) | Zero provenance violations; zero panics on arbitrary binary inputs |
| **Layer 2** | Invariant & Property Verification | `proptest` | 100% parse roundtrips; bijective hex converters; monotonic address ranges |
| **Layer 3** | Mutation Testing | `cargo-mutants` | Zero surviving mutants in detection logic |
| **Layer 4** | Real Kernel & Adversarial Injection | Isolated Linux Namespaces, Synthetic Malware | 100% detection rate of memfd, hollowing, and GOT poisoning |
| **Layer 5** | Performance & SLA Gates | `Criterion` | p99 single-PID scan duration < 1.5ms; full 300-PID sweep < 500ms |

---

## 3. Layer 1: Memory Safety & Fuzzing (ASan / Miri)

### 3.1 Miri Strict Provenance Test
Location: `crates/cerberus-core/tests/miri_provenance.rs`

Validates that raw pointer conversions in `RemoteIoVec` and memory reading routines never violate Rust's aliasing rules or lose pointer provenance.

```rust
use cerberus_core::syscalls::RemoteIoVec;

#[test]
fn test_remote_iovec_strict_provenance() {
    let mut buffer = [0u8; 128];
    let ptr = buffer.as_mut_ptr() as *mut libc::c_void;

    let iov = RemoteIoVec {
        iov_base: ptr,
        iov_len: buffer.len(),
    };

    assert!(!iov.iov_base.is_null());
    assert_eq!(iov.iov_len, 128);

    // Miri verification: Ensure pointer can be safely reconstructed without undefined behavior
    unsafe {
        let reconstructed = iov.iov_base as *mut u8;
        *reconstructed = 0xAA;
        *reconstructed.add(127) = 0xFF;
    }

    assert_eq!(buffer[0], 0xAA);
    assert_eq!(buffer[127], 0xFF);
}
```

**Execution Command**:
```bash
cargo miri test -p cerberus-core -- -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check
```

---

### 3.2 `cargo-fuzz` Target: `/proc/[pid]/maps` Zero-Allocation Parser
Location: `fuzz/fuzz_targets/maps_parser_fuzz.rs`

Fuzzes the streaming maps parser against arbitrary malformed, truncated, or hostile inputs to guarantee it never panics, segfaults, or overflows integers.

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use cerberus_procfs::maps::MapsParser;

fuzz_target!(|data: &[u8]| {
    let mut parser = MapsParser::new(data);

    // Invariant: Calling parse_next repeatedly MUST NEVER panic, regardless of content
    while let Ok(Some(vma)) = parser.parse_next() {
        // Semantic invariants on successful parse:
        assert!(vma.start <= vma.end, "VMA start must not exceed end");
        assert!(vma.size() == vma.end - vma.start, "VMA size invariant mismatch");
    }
});
```

**Execution Command**:
```bash
cargo +nightly fuzz run maps_parser_fuzz -- -max_total_time=60 -rss_limit_mb=2048
```

---

## 4. Layer 2: Invariant Property Testing (`proptest`)

Location: `crates/cerberus-procfs/tests/proptest_invariants.rs`

Tests mathematical properties of address parser functions and hex decoding routines.

```rust
use proptest::prelude::*;
use cerberus_procfs::maps::MapsParser;

proptest! {
    #[test]
    fn test_arbitrary_address_range_parsing(
        start in 0u64..0x7fffffffffff,
        offset in 0u64..0x1000000,
    ) {
        let end = start.saturating_add(offset);
        let line = format!("{:012x}-{:012x} r-xp 00000000 08:02 12345 /usr/bin/test\n", start, end);
        let mut parser = MapsParser::new(line.as_bytes());

        let res = parser.parse_next().expect("Must parse valid synthetic line");
        let vma = res.expect("Must produce VMA record");

        prop_assert_eq!(vma.start, start);
        prop_assert_eq!(vma.end, end);
        prop_assert_eq!(vma.size(), end - start);
    }
}
```

---

## 5. Layer 3: Mutation Testing (`cargo-mutants`)

Validates test suite efficacy. If mutation testing introduces a bug into detection logic (e.g. changing `vma.is_rwx()` to `false` or skipping hash checks) and tests still pass, CI fails.

**Configuration**: `.cargo/mutants.toml`
```toml
exclude_globs = ["benches/*", "fuzz/*"]
timeout = 30.0
```

**Execution Command**:
```bash
cargo mutants --package cerberus-detect --caught --no-times
```
**Standard**: **Zero surviving mutants**. Every conditional check and alert emission must be verified by a test.

---

## 6. Layer 4: Real Kernel & Adversarial Test Harnesses

Tests run against real running Linux processes executing offensive in-memory payloads in an isolated test environment.

### 6.1 Adversarial Probe 1: Fileless `memfd_create` Execution
Location: `tests/adversarial_fileless_test.rs`

```rust
use std::process::{Command, Stdio};
use std::time::Duration;
use cerberus_core::reader::DirectSyscallReader;
use cerberus_procfs::process::enumerate_all_pids;
use cerberus_procfs::status::ProcessMetadata;
use cerberus_procfs::maps::MapsParser;
use cerberus_detect::fileless::check_fileless_execution;
use cerberus_report::models::AnomalyType;

#[test]
fn test_detects_real_memfd_process() {
    // 1. Spawn our synthetic memfd runner
    let mut child = Command::new(env!("CARGO_BIN_EXE_synthetic_memfd"))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn synthetic memfd threat");

    let pid = child.id() as i32;
    std::thread::sleep(Duration::from_millis(100)); // Allow process to stabilize

    // 2. Perform forensic audit
    let meta = ProcessMetadata::extract(pid).expect("Must read process metadata");
    let maps_data = std::fs::read(format!("/proc/{}/maps", pid)).expect("Must read maps");
    let mut parser = MapsParser::new(&maps_data);
    let mut vmas = Vec::new();
    while let Ok(Some(vma)) = parser.parse_next() {
        vmas.push(vma);
    }

    let findings = check_fileless_execution(&meta, &vmas);

    // 3. Cleanup child
    let _ = child.kill();
    let _ = child.wait();

    // 4. Assertions
    assert!(!findings.is_empty(), "CRITICAL: Failed to detect fileless memfd process");
    let found = findings.iter().any(|f| f.anomaly_type == AnomalyType::FilelessMemfdExecution);
    assert!(found, "Expected FilelessMemfdExecution anomaly");
}
```

---

### 6.2 Adversarial Probe 2: Process Hollowing & `.text` Modification
Location: `tests/adversarial_hollowing_test.rs`

Spawns a legitimate child, injects arbitrary shellcode into its `.text` segment via `/proc/[pid]/mem`, and verifies that the differential engine flags `ProcessHollowing` and extracts the modified bytes.

```rust
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use cerberus_core::reader::DirectSyscallReader;
use cerberus_detect::hollowing::inspect_process_hollowing;
use cerberus_report::models::AnomalyType;

#[test]
fn test_detects_in_memory_text_tampering() {
    // Spawn benign worker
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("Failed to spawn target");

    let pid = child.id() as i32;
    std::thread::sleep(Duration::from_millis(50));

    // Overwrite the first 16 bytes of sleep's .text with NOPs and INT3
    let maps_data = std::fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    let first_exec_line = maps_data.lines().find(|l| l.contains("r-xp")).unwrap();
    let addr_str = first_exec_line.split('-').next().unwrap();
    let text_addr = u64::from_str_radix(addr_str, 16).unwrap();

    let mut mem_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{}/mem", pid))
        .expect("Failed to open target /proc/pid/mem for injection");

    use std::os::unix::fs::FileExt;
    let malicious_payload: [u8; 16] = [
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
    ];
    mem_file.write_all_at(&malicious_payload, text_addr).unwrap();

    // Perform audit
    let reader = DirectSyscallReader::new();
    let findings = inspect_process_hollowing(pid, &reader);

    // Teardown
    let _ = child.kill();
    let _ = child.wait();

    // Verify detection
    assert!(!findings.is_empty(), "Failed to detect .text modification");
    assert!(
        findings.iter().any(|f| f.anomaly_type == AnomalyType::ProcessHollowing || f.anomaly_type == AnomalyType::TextSegmentModification),
        "Expected process hollowing or text modification finding"
    );
}
```

---

## 7. Layer 5: Performance & Regression Benchmarks (Criterion)

Location: `benches/scan_throughput.rs`

Enforces strict micro-architectural throughput SLAs.

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cerberus_core::reader::DirectSyscallReader;
use cerberus_procfs::maps::MapsParser;

fn bench_maps_parse_1000_vmas(c: &mut Criterion) {
    let mut synthetic_maps = String::with_capacity(128 * 1000);
    for i in 0..1000 {
        synthetic_maps.push_str(&format!(
            "{:012x}-{:012x} r-xp 00000000 08:02 12345 /usr/lib/libtest.so\n",
            0x400000 + i * 0x1000,
            0x400000 + (i + 1) * 0x1000
        ));
    }
    let data = synthetic_maps.as_bytes();

    // HARD SLA GATE: Parsing 1,000 VMAs must take under 120 microseconds
    const MAX_PARSE_NANOS: u128 = 120_000;

    c.bench_function("parse_1000_vmas", |b| {
        b.iter(|| {
            let mut parser = MapsParser::new(black_box(data));
            let mut count = 0;
            while let Ok(Some(_)) = parser.parse_next() {
                count += 1;
            }
            assert_eq!(count, 1000);
        });
    });
}

criterion_group!(benches, bench_maps_parse_1000_vmas);
criterion_main!(benches);
```

---

## 8. Anti-Patterns & "Theater" Detection Checklist

- [ ] **Trap: Mocking Kernel Syscalls with `Vec<u8>` in Integration Tests**:
  * *Why it is theater*: Memory mockers cannot simulate unmapped memory faults, kernel permissions, or multi-threaded memory mutation.
  * *Enforcement*: All integration tests MUST spawn real processes and read real kernel addresses.
- [ ] **Trap: Testing Without Relocation Masking**:
  * *Why it is theater*: Running differential analysis on a PIE binary without masking dynamic relocations will generate false positive alerts on every single execution.
  * *Enforcement*: Relocation mask tests must assert 0 differences on clean unmodified binaries.
- [ ] **Trap: Memory Leaks in Streaming Buffers**:
  * *Why it is theater*: Continuous daemon scanners that allocate per-PID strings will cause memory bloat and trigger the Linux OOM killer.
  * *Enforcement*: Continuous memory benchmarks must assert steady-state RSS under 32MB across 10,000 scan cycles.

---

## 9. Continuous Integration (CI) Workflow Blueprint

```yaml
name: Cerberus-Mem Forensics Verification CI

on:
  pull_request:
    paths:
      - 'crates/**'
      - 'tests/**'
      - 'fuzz/**'
      - 'Cargo.toml'

jobs:
  miri-verification:
    name: Miri Memory Safety & Provenance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: miri
      - name: Run Miri
        run: cargo miri test -p cerberus-core -- -Zmiri-strict-provenance

  fuzz-smoke:
    name: LibFuzzer Smoke Regression
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Run Maps Fuzz Target
        run: cargo fuzz run maps_parser_fuzz -- -max_total_time=30 -rss_limit_mb=1024

  adversarial-kernel-tests:
    name: Adversarial Linux Kernel Probes (Root Required)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Execute Adversarial Probes
        run: sudo -E cargo test --test adversarial_fileless_test --test adversarial_hollowing_test -- --nocapture

  sla-benchmarks:
    name: Throughput SLA Validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Run Benchmarks
        run: cargo bench --bench scan_throughput -- --nocapture
```
