use cerberus_core::reader::DirectSyscallReader;
use cerberus_detect::fileless::check_fileless_execution;
use cerberus_detect::got_poison::inspect_process_got;
use cerberus_detect::hollowing::inspect_process_hollowing;
use cerberus_detect::inline_hook::inspect_inline_hooks;
use cerberus_elf::disk::ElfDiskImage;
use cerberus_procfs::maps::{read_process_maps, VmaBacking, VmaRecord};
use cerberus_procfs::status::ProcessMetadata;
use cerberus_report::models::{AnomalyType, ForensicFinding};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find_load_base(vmas: &[VmaRecord], exe: &Path) -> Option<u64> {
    vmas.iter()
        .find(|vma| {
            matches!(&vma.backing, VmaBacking::File(path) | VmaBacking::Deleted(path) if path == exe)
                && vma.offset == 0
        })
        .map(|vma| vma.start)
}

fn load_base_for(pid: i32) -> (PathBuf, Vec<VmaRecord>, u64) {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).expect("read exe link");
    let vmas = read_process_maps(pid).expect("read maps");
    let base = find_load_base(&vmas, &exe).expect("resolve load base");
    (exe, vmas, base)
}

#[test]
fn test_detects_real_memfd_process() {
    let child = Command::new(env!("CARGO_BIN_EXE_synthetic_memfd"))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn synthetic memfd");
    let _guard = ChildGuard(child);
    let pid = _guard.0.id() as i32;

    std::thread::sleep(Duration::from_millis(250));

    let meta = ProcessMetadata::extract(pid).expect("metadata for memfd child");
    let vmas = read_process_maps(pid).expect("maps for memfd child");
    let findings = check_fileless_execution(&meta, &vmas);

    assert!(
        findings
            .iter()
            .any(|finding| finding.anomaly_type == AnomalyType::FilelessMemfdExecution),
        "expected FilelessMemfdExecution for pid {pid}, got {findings:?}"
    );
}

#[test]
fn test_detects_in_memory_text_tampering() {
    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep target");
    let _guard = ChildGuard(child);
    let pid = _guard.0.id() as i32;

    std::thread::sleep(Duration::from_millis(150));

    let (exe, _vmas, base) = load_base_for(pid);
    let disk = ElfDiskImage::load(&exe).expect("load target ELF");
    let runtime_text = disk.runtime_text_address(base);
    let reader = DirectSyscallReader::new();

    let clean = inspect_process_hollowing(pid, &reader);
    assert!(
        !clean.iter().any(|finding| matches!(
            finding.anomaly_type,
            AnomalyType::ProcessHollowing | AnomalyType::TextSegmentModification
        )),
        "benign target produced a false positive: {clean:?}"
    );

    let payload: [u8; 16] = [
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC,
    ];
    let memory = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .expect("open target memory");
    memory
        .write_all_at(&payload, runtime_text)
        .expect("inject payload");

    let findings = inspect_process_hollowing(pid, &reader);
    assert!(
        findings.iter().any(|finding| matches!(
            finding.anomaly_type,
            AnomalyType::ProcessHollowing | AnomalyType::TextSegmentModification
        )),
        "failed to detect .text modification at 0x{runtime_text:x}: {findings:?}"
    );
    let finding = findings
        .iter()
        .find(|finding| finding.anomaly_type == AnomalyType::ProcessHollowing)
        .expect("hollowing finding");
    assert_eq!(finding.backing_detail, exe.to_string_lossy());
    assert!(finding.disk_hash_sha256.is_some());
    assert!(finding.mem_hash_sha256.is_some());
    assert!(finding.extracted_divergence_bytes.is_some());
}

#[test]
fn test_got_and_inline_hook_scanners_do_not_flag_benign_process() {
    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep target");
    let _guard = ChildGuard(child);
    let pid = _guard.0.id() as i32;

    std::thread::sleep(Duration::from_millis(150));
    let reader = DirectSyscallReader::new();

    let got_findings = inspect_process_got(pid, &reader);
    assert!(
        !got_findings
            .iter()
            .any(|finding| finding.anomaly_type == AnomalyType::GotPltHijack),
        "benign process produced GOT false positives: {got_findings:?}"
    );

    let inline_findings = inspect_inline_hooks(pid, &reader);
    assert!(
        !inline_findings
            .iter()
            .any(|finding| finding.anomaly_type == AnomalyType::InlineFunctionHook),
        "benign process produced inline-hook false positives: {inline_findings:?}"
    );
}

#[test]
fn test_detects_synthetic_got_hijack() {
    let child = Command::new(env!("CARGO_BIN_EXE_synthetic_got_hooker"))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn synthetic GOT hooker");
    let _guard = ChildGuard(child);
    let pid = _guard.0.id() as i32;

    std::thread::sleep(Duration::from_millis(500));
    let reader = DirectSyscallReader::new();
    let findings = inspect_process_got(pid, &reader);

    assert!(
        findings
            .iter()
            .any(|finding| finding.anomaly_type == AnomalyType::GotPltHijack),
        "failed to detect synthetic GOT hijack for pid {pid}: {findings:?}"
    );
}

#[test]
fn test_cli_emits_jsonl_for_memfd_target() {
    let child = Command::new(env!("CARGO_BIN_EXE_synthetic_memfd"))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn synthetic memfd");
    let _guard = ChildGuard(child);
    let pid = _guard.0.id() as i32;
    std::thread::sleep(Duration::from_millis(300));

    let unique = format!(
        "cerberus-jsonl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    );
    let path = std::env::temp_dir().join(unique);

    let pid_arg = pid.to_string();
    let path_arg = path.to_string_lossy().into_owned();
    let status = Command::new(env!("CARGO_BIN_EXE_cerberus-mem"))
        .args(["--pid", pid_arg.as_str(), "--jsonl", path_arg.as_str()])
        .status()
        .expect("run cerberus-mem");
    assert!(status.success(), "cerberus-mem exited with {status}");

    let contents = std::fs::read_to_string(&path).expect("read jsonl output");
    let _ = std::fs::remove_file(&path);

    let findings: Vec<ForensicFinding> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid JSON-Lines finding"))
        .collect();

    assert!(
        findings
            .iter()
            .any(|finding| finding.anomaly_type == AnomalyType::FilelessMemfdExecution),
        "CLI JSONL output missed the memfd finding: {findings:?}"
    );
}
