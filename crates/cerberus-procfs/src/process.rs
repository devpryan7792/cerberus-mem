//! Host-wide process enumeration.

/// Enumerate all numeric process IDs currently visible in `/proc`.
pub fn enumerate_all_pids() -> Result<Vec<i32>, std::io::Error> {
    let mut pids = Vec::new();

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        match name.parse::<i32>() {
            Ok(pid) if pid > 0 => pids.push(pid),
            _ => {}
        }
    }

    pids.sort_unstable();
    Ok(pids)
}
