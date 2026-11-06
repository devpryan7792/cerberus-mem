//! Process metadata extraction from procfs.

use std::path::PathBuf;

/// Metadata describing a running process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMetadata {
    /// Process identifier.
    pub pid: i32,
    /// Parent process identifier, or zero if unavailable.
    pub ppid: i32,
    /// Kernel command name (`comm`).
    pub comm: String,
    /// NUL-separated command line arguments.
    pub cmdline: Vec<String>,
    /// Resolved `/proc/[pid]/exe` target, if accessible.
    pub exe_target: Option<PathBuf>,
    /// Whether the executable has been unlinked.
    pub is_exe_deleted: bool,
}

impl ProcessMetadata {
    /// Extract metadata for `pid`.
    pub fn extract(pid: i32) -> Result<Self, std::io::Error> {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))?
            .trim_end_matches('\n')
            .to_string();

        let cmdline_raw = std::fs::read(format!("/proc/{pid}/cmdline"))?;
        let cmdline: Vec<String> = cmdline_raw
            .split(|&b| b == 0)
            .filter(|segment| !segment.is_empty())
            .map(|segment| String::from_utf8_lossy(segment).to_string())
            .collect();

        let exe_link = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let is_exe_deleted = match &exe_link {
            Some(path) => path.to_string_lossy().ends_with(" (deleted)"),
            None => false,
        };

        let ppid = read_ppid(pid).unwrap_or(0);

        Ok(Self {
            pid,
            ppid,
            comm,
            cmdline,
            exe_target: exe_link,
            is_exe_deleted,
        })
    }
}

fn read_ppid(pid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<i32>().ok();
        }
    }
    None
}
