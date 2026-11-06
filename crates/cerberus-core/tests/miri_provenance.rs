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

    // Miri verification: ensure the pointer can be reconstructed and used
    // without losing provenance or violating alignment.
    unsafe {
        let reconstructed = iov.iov_base as *mut u8;
        *reconstructed = 0xAA;
        *reconstructed.add(127) = 0xFF;
    }

    assert_eq!(buffer[0], 0xAA);
    assert_eq!(buffer[127], 0xFF);
}
