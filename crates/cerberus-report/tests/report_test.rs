use cerberus_report::jsonl::{JsonlEmitter, JsonlError};
use cerberus_report::models::{AnomalyType, ForensicFinding, Severity};
use cerberus_report::quarantine::QuarantineDumper;

fn sample_finding(pid: u32) -> ForensicFinding {
    ForensicFinding {
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        target_pid: pid,
        process_comm: "test".to_string(),
        process_cmdline: vec!["test".to_string()],
        severity: Severity::High,
        anomaly_type: AnomalyType::WxorXViolation,
        description: "rwx mapping".to_string(),
        affected_address_range: (0x1000, 0x2000),
        backing_detail: "[anon]".to_string(),
        disk_hash_sha256: None,
        mem_hash_sha256: None,
        extracted_divergence_bytes: None,
        disassembly_snippet: Some(vec!["nop".to_string()]),
    }
}

#[test]
fn test_jsonl_emit_roundtrip() {
    let mut output = Vec::new();
    {
        let mut emitter = JsonlEmitter::new(&mut output);
        emitter.emit(&sample_finding(1234)).expect("emit failed");
        emitter.emit(&sample_finding(5678)).expect("emit failed");
    }

    let text = String::from_utf8(output).expect("jsonl must be utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);

    let parsed: ForensicFinding = serde_json::from_str(lines[0]).expect("valid finding");
    assert_eq!(parsed.target_pid, 1234);
    assert_eq!(parsed.anomaly_type, AnomalyType::WxorXViolation);
    assert_eq!(parsed.severity, Severity::High);
}

#[test]
fn test_jsonl_emit_error_is_reported() {
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut emitter = JsonlEmitter::new(FailingWriter);
    let result = emitter.emit(&sample_finding(1));
    assert!(matches!(result, Err(JsonlError::Serialize(_))));
}

#[test]
fn test_quarantine_creates_secure_file() {
    use std::os::unix::fs::PermissionsExt;

    let unique = format!(
        "cerberus-test-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let root = std::env::temp_dir().join(unique);

    let dumper = QuarantineDumper::new(&root).expect("quarantine dir");
    let path = dumper
        .dump(42, "../../evil label", b"payload")
        .expect("dump should succeed");

    assert!(path.starts_with(&root));
    assert_eq!(std::fs::read(&path).expect("read dump"), b"payload");

    let file_mode = std::fs::metadata(&path)
        .expect("file metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600);

    let dir_mode = std::fs::metadata(&root)
        .expect("dir metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);

    let _ = std::fs::remove_dir_all(&root);
}
