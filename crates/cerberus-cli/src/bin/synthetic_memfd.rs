//! Synthetic fileless-execution harness: executes this binary from a memfd.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

fn main() {
    if let Err(err) = run() {
        eprintln!("synthetic_memfd: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("child") {
        write_all(
            libc::STDOUT_FILENO,
            b"synthetic-memfd: child running from memfd\n",
        )?;
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    let executable = std::fs::read("/proc/self/exe")?;
    let name = CString::new("payload")?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    write_all(fd, &executable)?;
    unsafe {
        libc::lseek(fd, 0, libc::SEEK_SET);
    }

    let arg0 = CString::new("synthetic_memfd")?;
    let arg1 = CString::new("child")?;
    let argv: [*mut libc::c_char; 3] = [
        arg0.as_ptr() as *mut libc::c_char,
        arg1.as_ptr() as *mut libc::c_char,
        std::ptr::null_mut(),
    ];
    let empty = CString::new("")?;
    let envp: [*mut libc::c_char; 1] = [std::ptr::null_mut()];

    let result = unsafe {
        libc::execveat(
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(())
}

fn write_all(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let written = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero-length write to memfd",
            ));
        }
        data = &data[written as usize..];
    }
    Ok(())
}
