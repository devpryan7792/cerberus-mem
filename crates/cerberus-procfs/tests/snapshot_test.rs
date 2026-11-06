//! Address-space snapshot consistency tests.

use cerberus_procfs::maps::{read_process_maps, VmaBacking, VmaRecord};
use cerberus_procfs::snapshot::{address_space_replaced, exe_load_base};
use cerberus_procfs::status::ProcessMetadata;
use std::path::Path;
use std::process::{Child, Command, Stdio};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sleep() -> (i32, ChildGuard) {
    let child = Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id() as i32;
    (pid, ChildGuard(child))
}

#[test]
fn test_stable_process_is_not_reported_as_replaced() {
    let (pid, _guard) = spawn_sleep();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let meta = ProcessMetadata::extract(pid).expect("metadata");
    let vmas = read_process_maps(pid).expect("maps");

    assert!(
        !address_space_replaced(pid, &meta, &vmas),
        "a stable process must not be reported as having a replaced address space"
    );
}

#[test]
fn test_exe_load_base_matches_detector_lookup() {
    let (pid, _guard) = spawn_sleep();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let meta = ProcessMetadata::extract(pid).expect("metadata");
    let vmas = read_process_maps(pid).expect("maps");
    let exe = meta.exe_target.expect("exe target");

    let base = exe_load_base(&vmas, Path::new(&exe)).expect("load base");
    let mapping = vmas
        .iter()
        .find(|vma| vma.start == base && vma.offset == 0)
        .expect("base mapping");

    assert!(
        matches!(
            &mapping.backing,
            VmaBacking::File(path) | VmaBacking::Deleted(path)
                if path.file_name() == exe.file_name()
        ),
        "load base must point at the executable image"
    );
}

#[test]
fn test_vanished_process_counts_as_replaced() {
    let mut child = Command::new("true")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = child.id() as i32;
    let status = child.wait().expect("wait");
    assert!(status.success());

    // The process is gone, so any snapshot of it is stale by definition.
    let vmas: Vec<VmaRecord> = Vec::new();
    let meta = ProcessMetadata {
        pid,
        ppid: 0,
        comm: "true".to_string(),
        cmdline: Vec::new(),
        exe_target: Some("/usr/bin/true".into()),
        is_exe_deleted: false,
    };

    assert!(
        address_space_replaced(pid, &meta, &vmas),
        "a vanished process must be treated as a replaced address space"
    );
}

#[test]
fn test_stale_exe_identity_counts_as_replaced() {
    let (pid, _guard) = spawn_sleep();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let vmas = read_process_maps(pid).expect("maps");
    let mut meta = ProcessMetadata::extract(pid).expect("metadata");

    // Simulate a snapshot captured before an `execve` into a different image.
    meta.exe_target = Some("/bin/false".into());

    assert!(
        address_space_replaced(pid, &meta, &vmas),
        "a snapshot whose executable identity changed must be treated as replaced"
    );
}

#[test]
fn test_changed_load_base_counts_as_replaced() {
    let (pid, _guard) = spawn_sleep();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let meta = ProcessMetadata::extract(pid).expect("metadata");
    let mut vmas = read_process_maps(pid).expect("maps");

    // Simulate a snapshot whose load base no longer matches the live image.
    for vma in &mut vmas {
        if vma.offset == 0 {
            vma.start = vma.start.wrapping_add(0x1_0000_0000);
            vma.end = vma.end.wrapping_add(0x1_0000_0000);
        }
    }

    assert!(
        address_space_replaced(pid, &meta, &vmas),
        "a snapshot with a stale load base must be treated as replaced"
    );
}
