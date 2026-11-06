//! Forensic finding data structures and severity taxonomy.

use serde::{Deserialize, Serialize};

/// Severity assigned to a forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational observation.
    Info,
    /// Low-confidence anomaly.
    Low,
    /// Medium-confidence anomaly.
    Medium,
    /// High-confidence malicious behavior.
    High,
    /// Critical, actionable compromise indicator.
    Critical,
}

/// Classification of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Executable is backed by an anonymous memory file descriptor.
    FilelessMemfdExecution,
    /// Executable has been unlinked from disk.
    DeletedBinaryExecution,
    /// Live code diverges from the on-disk image.
    ProcessHollowing,
    /// A text segment was modified in memory.
    TextSegmentModification,
    /// A GOT/PLT slot points outside authorized executable code.
    GotPltHijack,
    /// A shared library function prologue contains a rogue trampoline.
    InlineFunctionHook,
    /// A mapping is simultaneously writable and executable.
    WxorXViolation,
    /// An anonymous or heap mapping is executable.
    AnonymousExecutableMapping,
    /// A thread stack pointer points outside its designated stack.
    StackPivoting,
}

/// Structured forensic finding emitted as one JSON-Lines record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicFinding {
    /// RFC 3339 timestamp of detection.
    pub timestamp_utc: String,
    /// Target process identifier.
    pub target_pid: u32,
    /// Target command name.
    pub process_comm: String,
    /// Target command line.
    pub process_cmdline: Vec<String>,
    /// Finding severity.
    pub severity: Severity,
    /// Anomaly classification.
    pub anomaly_type: AnomalyType,
    /// Human-readable description.
    pub description: String,
    /// Affected virtual address range.
    pub affected_address_range: (u64, u64),
    /// Backing object detail.
    pub backing_detail: String,
    /// SHA-256 of the on-disk artifact, if applicable.
    pub disk_hash_sha256: Option<String>,
    /// SHA-256 of the in-memory artifact, if applicable.
    pub mem_hash_sha256: Option<String>,
    /// Hex-encoded divergent bytes, if applicable.
    pub extracted_divergence_bytes: Option<String>,
    /// Disassembly of the suspicious code, if applicable.
    pub disassembly_snippet: Option<Vec<String>>,
}
