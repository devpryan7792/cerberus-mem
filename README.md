# Cerberus-Mem

**Linux in-memory forensics and EDR evasion detection engine, written in pure Rust.**

Cerberus-Mem inspects live processes without pausing them. It compares each
process's on-disk ELF image against its mapped memory, validates dynamic-linker
data structures, and flags code that only exists in RAM. The engine is passive:
it uses `process_vm_readv(2)` with a `/proc/[pid]/mem` fallback, never `ptrace`,
so targets do not stop and anti-debug checks do not trip.

```text
$ cerberus-mem --all
[High] pid=1631 WxorXViolation: Mapping at 0x7f0401a2e000-0x7f0401a3e000 is
simultaneously writable and executable (VmaProtection(READ | WRITE | EXEC | PRIVATE))
 (0x7f0401a2e000-0x7f0401a3e000)
cerberus-mem: 1 finding(s)
```

## Detection coverage

| Engine | What it finds |
|---|---|
| **Fileless execution** | Processes whose `/proc/[pid]/exe` resolves to `memfd:` or a deleted/unlinked file |
| **Process hollowing** | Relocation-masked SHA-256 divergence between disk `.text` and the live mapping, plus byte-level extraction of divergent ranges |
| **GOT/PLT poisoning** | Imported function slots that resolve outside the expected module's executable ranges or PLT |
| **Inline hooks** | `JMP`/`CALL` trampolines in exported libc prologues that redirect into foreign mappings |
| **W^X violations** | VMAs that are simultaneously writable and executable |
| **Anonymous executable mappings** | Unbacked executable pages, with an allowlist for known JIT runtimes |

Findings carry severity, PID/comm/cmdline, the affected address range, backing
detail, optional disk/memory hashes, and optional disassembly. Output is
human-readable by default or JSON-Lines for SIEM ingestion.

## Architecture

```
crates/
├── cerberus-core     # process_vm_readv + /proc/[pid]/mem readers, syscall ABI, errors
├── cerberus-procfs   # streaming parsers for maps, status, auxv, process enumeration
├── cerberus-elf      # mmap-backed disk ELF, relocations, dynamic symbols, GOT/PLT metadata
├── cerberus-detect   # fileless, hollowing, GOT poisoning, inline hook, W^X engines
├── cerberus-report   # finding models, JSON-Lines emitter, secure quarantine
└── cerberus-cli      # cerberus-mem binary, Rayon sweep orchestration, benchmarks
```

VMA and ELF data are parsed once per PID and shared by every detector. On-disk
executables are memory-mapped rather than copied into the heap, and GOT slot
reads are batched into 64 KiB windows.

## Requirements

- Linux kernel 5.15+ on x86_64 or aarch64
- Rust stable (edition 2021)
- `CAP_SYS_PTRACE` (and usually `CAP_DAC_READ_SEARCH`) for host-wide inspection.
  Same-user targets work unprivileged when YAMA `ptrace_scope` allows it.

## Build

```bash
cargo build --release
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep target/release/cerberus-mem
```

Or run the binary as root. The capability only needs to be set once.

## Usage

```bash
# One process
cerberus-mem --pid 1234

# Full host sweep
cerberus-mem --all

# JSON-Lines output (append mode)
cerberus-mem --all --jsonl findings.jsonl

# Continuous sweep with artifact quarantine
cerberus-mem --daemon --interval 30 --quarantine-dir /var/log/cerberus/dumps
```

Example finding:

```json
{
  "timestamp_utc": "2026-11-06T12:40:27.397059885+00:00",
  "target_pid": 1631,
  "process_comm": "quickshell",
  "process_cmdline": ["quickshell", "-d"],
  "severity": "high",
  "anomaly_type": "wxor_x_violation",
  "description": "Mapping at 0x7f0401a2e000-0x7f0401a3e000 is simultaneously writable and executable",
  "affected_address_range": [139655184048128, 139655184113664],
  "backing_detail": "Anonymous",
  "disk_hash_sha256": null,
  "mem_hash_sha256": null,
  "extracted_divergence_bytes": null,
  "disassembly_snippet": null
}
```

Quarantined artifacts are written under a `0700` directory with exclusively
created `0600` files using `O_NOFOLLOW | O_CREAT | O_EXCL`, so existing symlinks
or files are never followed or overwritten.

## Performance

Measured on a 12-core x86_64 host with 316 visible PIDs:

| Gate | Result | Target |
|---|---|---|
| Single-PID scan, p99 | ~94 µs | < 1.5 ms |
| Full host sweep | ~112 ms | < 500 ms |

```bash
cargo bench -p cerberus-cli
cargo test -p cerberus-cli --release --test sla_test -- --ignored --nocapture
```

## Testing

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

The suite includes real-kernel adversarial probes: an actual `memfd_create` +
`fexecve` payload, in-memory `.text` tampering, a synthetic GOT hijack, clean
process false-positive checks, and JSON-Lines emission.

## Limitations

- Differential analysis is byte-level with relocation masking; legitimate
  runtime self-modifying code (JITs) is handled by W^X/XOR allowlists, not by
  the hollowing engine.
- `TextSegmentModification` and stack-pivot anomaly types exist in the schema
  but are not currently emitted.
- Inline-hook detection validates jump destinations; it does not yet compare
  the on-disk prologue byte-for-byte.
- Kernel-space rootkits and compromised `/proc` are out of scope.
- Miri, `cargo-fuzz`, proptest, and `cargo-mutants` are documented targets but
  are not wired into CI.

## Documentation

- [`PROJECT_CHARTER.md`](PROJECT_CHARTER.md) — threat model, scope, constraints
- [`ARCHITECTURE_SPEC.md`](ARCHITECTURE_SPEC.md) — data structures and algorithms
- [`PHASED_IMPLEMENTATION.md`](PHASED_IMPLEMENTATION.md) — implementation contract
- [`TESTING_AND_VERIFICATION.md`](TESTING_AND_VERIFICATION.md) — test strategy
- [`ROADMAP.md`](ROADMAP.md) — milestones

## License

Apache-2.0. See [`LICENSE`](LICENSE).
