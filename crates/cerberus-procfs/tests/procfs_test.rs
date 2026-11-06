use cerberus_procfs::auxv::{
    AuxvReader, ProcessAuxvAnchors, AT_BASE, AT_ENTRY, AT_NULL, AT_PHDR, AT_PHNUM,
};
use cerberus_procfs::status::ProcessMetadata;

fn auxv_bytes(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (a_type, a_val) in entries {
        bytes.extend_from_slice(&a_type.to_ne_bytes());
        bytes.extend_from_slice(&a_val.to_ne_bytes());
    }
    bytes
}

#[test]
fn test_auxv_parse_synthetic() {
    let data = auxv_bytes(&[
        (AT_PHDR, 0x400040),
        (AT_PHNUM, 13),
        (AT_BASE, 0x7f0000000000),
        (AT_ENTRY, 0x401000),
        (AT_NULL, 0),
        (AT_ENTRY, 0xdead),
    ]);

    let anchors = ProcessAuxvAnchors::parse_from_bytes(&data).expect("auxv should parse");
    assert_eq!(anchors.phdr_addr, Some(0x400040));
    assert_eq!(anchors.phnum, Some(13));
    assert_eq!(anchors.base_addr, Some(0x7f0000000000));
    assert_eq!(anchors.entry_point, Some(0x401000));
}

#[test]
fn test_auxv_rejects_truncated_buffer() {
    assert!(ProcessAuxvAnchors::parse_from_bytes(&[0u8; 15]).is_err());
}

#[test]
fn test_read_current_process_auxv() {
    let pid = std::process::id() as i32;
    let anchors = AuxvReader::read_anchors(pid).expect("auxv read should succeed");
    assert!(anchors.entry_point.is_some());
    assert!(anchors.phdr_addr.is_some());
}

#[test]
fn test_process_metadata_current_process() {
    let pid = std::process::id() as i32;
    let meta = ProcessMetadata::extract(pid).expect("metadata should be readable");
    assert_eq!(meta.pid, pid);
    assert!(meta.ppid > 0);
    assert!(!meta.comm.is_empty());
    assert!(meta.exe_target.is_some());
    assert!(!meta.is_exe_deleted);
}
