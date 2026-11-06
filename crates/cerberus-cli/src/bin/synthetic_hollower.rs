//! Synthetic hollowing harness: patches the `.text` of a spawned `sleep`.

use cerberus_elf::disk::ElfDiskImage;
use cerberus_procfs::maps::{read_process_maps, VmaBacking};
use std::ffi::CString;
use std::io;
use std::process::{Child, Command};
use std::time::Duration;

fn main() {
    if let Err(err) = run() {
        eprintln!("synthetic_hollower: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("sleep").arg("60").spawn()?;
    let pid = child.id() as i32;
    std::thread::sleep(Duration::from_millis(150));

    let result = patch_target(pid);
    match result {
        Ok(address) => {
            println!("synthetic-hollower: patched pid {pid} at 0x{address:x}");
            std::thread::sleep(Duration::from_secs(30));
        }
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    }

    terminate(&mut child);
    Ok(())
}

fn patch_target(pid: i32) -> Result<u64, Box<dyn std::error::Error>> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    let vmas = read_process_maps(pid)?;

    let Some(load_base) = vmas
        .iter()
        .find(|vma| {
            matches!(&vma.backing, VmaBacking::File(path) | VmaBacking::Deleted(path) if path == &exe)
                && vma.offset == 0
        })
        .map(|vma| vma.start)
    else {
        return Err("could not resolve target load base".into());
    };

    let disk = ElfDiskImage::load(&exe)?;
    let runtime_text = disk.runtime_text_address(load_base);

    let memory_path = CString::new(format!("/proc/{pid}/mem"))?;
    let fd = unsafe { libc::open(memory_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let payload: [u8; 16] = [
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC,
    ];
    let written = unsafe {
        libc::pwrite(
            fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            runtime_text as libc::off_t,
        )
    };
    let close_result = unsafe { libc::close(fd) };
    let _ = close_result;

    if written < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if written as usize != payload.len() {
        return Err("short write to target memory".into());
    }

    Ok(runtime_text)
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
