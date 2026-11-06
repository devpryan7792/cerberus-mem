//! Secure quarantine dumper for extracted forensic artifacts.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Directory-scoped dumper using `O_NOFOLLOW | O_CREAT | O_EXCL` and mode 0600.
pub struct QuarantineDumper {
    root: PathBuf,
}

impl QuarantineDumper {
    /// Create (or reuse) a quarantine directory and enforce mode 0700.
    pub fn new(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    /// Quarantine directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `data` to a new, uniquely named file inside the quarantine.
    ///
    /// The label is sanitized to prevent path traversal, and the file is
    /// created with `O_NOFOLLOW | O_CREAT | O_EXCL` so an existing symlink or
    /// file can never be followed or overwritten.
    pub fn dump(&self, pid: u32, label: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        let sanitized = sanitize_label(label);
        let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ");
        let file_name = format!("{pid}-{sanitized}-{timestamp}.bin");
        let path = self.root.join(file_name);

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;

        file.write_all(data)?;
        file.sync_all()?;
        Ok(path)
    }
}

fn sanitize_label(label: &str) -> String {
    let mut output = String::with_capacity(label.len().min(64));
    for ch in label.chars().take(64) {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() || output == "." || output == ".." {
        output.push_str("artifact");
    }
    output
}
