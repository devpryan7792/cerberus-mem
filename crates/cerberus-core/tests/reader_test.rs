#![cfg(not(miri))]

use cerberus_core::errors::MemoryReaderError;
use cerberus_core::reader::{
    DirectSyscallReader, FallbackReader, ProcMemReader, ProcessMemoryReader,
};

#[test]
fn test_read_current_process_stack_memory() {
    let pid = std::process::id() as i32;
    let reader = DirectSyscallReader::new();

    let source = *b"cerberus-mem self-read verification payload";
    // Prevent the compiler from eliding or const-promoting the source buffer.
    let source = std::hint::black_box(source);
    let remote_addr = source.as_ptr() as u64;

    let mut out = vec![0u8; source.len()];
    let result = reader.read_memory(pid, remote_addr, &mut out);

    match result {
        Ok(bytes) => {
            assert_eq!(bytes, source.len(), "expected a full contiguous read");
            assert_eq!(&out[..bytes], &source[..], "read bytes must match source");
        }
        Err(err) => panic!("self-read failed: {err}"),
    }
}

#[test]
fn test_read_invalid_address_degrades_to_zero_fill() {
    let pid = std::process::id() as i32;
    let reader = DirectSyscallReader::new();

    let mut out = [0xAAu8; 64];
    let result = reader.read_memory(pid, 0x0, &mut out);

    match result {
        Ok(bytes) => {
            // The EFAULT fallback zero-fills unreadable pages but does not count
            // them as transferred bytes.
            assert_eq!(
                bytes, 0,
                "no bytes should be reported for an unmapped range"
            );
            assert!(
                out.iter().all(|&byte| byte == 0),
                "unmapped range must be zero-filled"
            );
        }
        Err(MemoryReaderError::MemoryFault { .. }) => {}
        Err(err) => panic!("unexpected error for invalid address: {err}"),
    }
}

#[test]
fn test_page_size_is_resolved() {
    let reader = DirectSyscallReader::new();
    assert!(reader.page_size() >= 4096, "page size must be sane");
    assert!(
        reader.page_size().is_power_of_two(),
        "page size must be a power of two"
    );
}

#[test]
fn test_proc_mem_reader_reads_current_process() {
    let pid = std::process::id() as i32;
    let reader = ProcMemReader::open(pid).expect("open /proc/self/mem");

    let source = *b"proc-mem pread fallback verification payload";
    let source = std::hint::black_box(source);
    let mut out = vec![0u8; source.len()];

    let bytes = reader
        .read_exact_at(&mut out, source.as_ptr() as u64)
        .expect("pread should succeed");
    assert_eq!(bytes, source.len());
    assert_eq!(out, source);
}

#[test]
fn test_proc_mem_reader_zero_fills_unmapped() {
    let pid = std::process::id() as i32;
    let reader = ProcMemReader::open(pid).expect("open /proc/self/mem");

    let mut out = [0xAAu8; 64];
    let bytes = reader
        .read_memory(pid, 0, &mut out)
        .expect("unmapped read should degrade");
    assert_eq!(bytes, 0);
    assert!(out.iter().all(|&byte| byte == 0));
}

#[test]
fn test_fallback_reader_reads_current_process() {
    let pid = std::process::id() as i32;
    let reader = FallbackReader::new();

    let source = *b"fallback reader verification payload";
    let source = std::hint::black_box(source);
    let mut out = vec![0u8; source.len()];

    let bytes = reader
        .read_memory(pid, source.as_ptr() as u64, &mut out)
        .expect("self read should succeed via process_vm_readv");
    assert_eq!(bytes, source.len());
    assert_eq!(out, source);
}
