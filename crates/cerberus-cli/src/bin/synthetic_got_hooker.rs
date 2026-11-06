//! Synthetic GOT-hooking harness: redirects this binary's `puts` GOT slot.

use cerberus_elf::dynamic::load_dynamic_info;
use cerberus_procfs::maps::{read_process_maps, VmaBacking};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static HOOKED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn hooked_puts(_message: *const libc::c_char) -> libc::c_int {
    HOOKED.store(true, Ordering::SeqCst);
    let marker = b"synthetic-got-hooker: redirected puts invoked\n";
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            marker.as_ptr() as *const libc::c_void,
            marker.len(),
        );
    }
    0
}

fn main() {
    if let Err(err) = run() {
        eprintln!("synthetic_got_hooker: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let pid = std::process::id() as i32;
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
        return Err("could not resolve own load base".into());
    };

    let dynamic = load_dynamic_info(&exe)?;
    let entry = dynamic
        .got_entries
        .iter()
        .find(|entry| entry.symbol_name == "puts")
        .ok_or("binary has no puts GOT entry")?;

    let got_address =
        load_base.saturating_add(entry.got_vaddr.saturating_sub(dynamic.min_load_vaddr));

    let page_size = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        value if value > 0 => value as u64,
        _ => 4096,
    };
    let page_start = (got_address / page_size) * page_size;

    let result = unsafe {
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }

    unsafe {
        std::ptr::write_volatile(got_address as *mut usize, hooked_puts as *const () as usize);
        libc::puts(c"original puts call".as_ptr());
    }

    let status = if HOOKED.load(Ordering::SeqCst) {
        "hooked"
    } else {
        "not-hooked"
    };
    let message =
        format!("synthetic-got-hooker: pid={pid} got=0x{got_address:x} status={status}\n");
    unsafe {
        libc::write(
            libc::STDOUT_FILENO,
            message.as_ptr() as *const libc::c_void,
            message.len(),
        );
    }

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
