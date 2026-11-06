//! Streaming `/proc/[pid]/maps` parser and VMA data model.

use bitflags::bitflags;
use std::path::PathBuf;

bitflags! {
    /// Protection and sharing flags of a virtual memory area.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VmaProtection: u8 {
        /// Page is readable.
        const READ    = 0b0000_0001;
        /// Page is writable.
        const WRITE   = 0b0000_0010;
        /// Page is executable.
        const EXEC    = 0b0000_0100;
        /// Mapping is shared.
        const SHARED  = 0b0000_1000;
        /// Mapping is private (copy-on-write).
        const PRIVATE = 0b0001_0000;
    }
}

/// Backing object classification for a VMA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmaBacking {
    /// Anonymous mapping with no pathname.
    Anonymous,
    /// File-backed mapping.
    File(PathBuf),
    /// The process heap.
    Heap,
    /// A thread or process stack.
    Stack,
    /// The kernel-provided vDSO.
    Vdso,
    /// The kernel-provided vvar page.
    Vvar,
    /// The legacy vsyscall page.
    Vsyscall,
    /// An anonymous memory file descriptor, optionally with a `(deleted)` marker.
    Memfd(String),
    /// A file-backed mapping whose file has been unlinked.
    Deleted(PathBuf),
}

/// One parsed `/proc/[pid]/maps` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmaRecord {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Protection and sharing flags.
    pub perms: VmaProtection,
    /// File offset of the mapping.
    pub offset: u64,
    /// Device major number.
    pub dev_major: u32,
    /// Device minor number.
    pub dev_minor: u32,
    /// Inode of the backing file, or zero for anonymous mappings.
    pub inode: u64,
    /// Backing object classification.
    pub backing: VmaBacking,
}

impl VmaRecord {
    /// Size of the mapping in bytes.
    #[inline(always)]
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the mapping is executable.
    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        self.perms.contains(VmaProtection::EXEC)
    }

    /// Whether the mapping is readable, writable, and executable.
    #[inline(always)]
    pub fn is_rwx(&self) -> bool {
        self.perms
            .contains(VmaProtection::READ | VmaProtection::WRITE | VmaProtection::EXEC)
    }

    /// Whether the mapping is anonymous/heap and executable.
    #[inline(always)]
    pub fn is_anonymous_exec(&self) -> bool {
        self.is_executable() && matches!(self.backing, VmaBacking::Anonymous | VmaBacking::Heap)
    }
}

/// Errors produced while parsing a maps line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapsParseError {
    /// The address range was malformed.
    InvalidAddressRange,
    /// The permissions field was malformed.
    InvalidPermissions,
    /// The file offset was malformed.
    InvalidOffset,
    /// The device field was malformed.
    InvalidDevice,
    /// The inode field was malformed.
    InvalidInode,
    /// The line ended before all mandatory fields were present.
    UnexpectedEof,
}

/// Zero-allocation parser over a pre-read `/proc/[pid]/maps` buffer.
///
/// The parser borrows the input bytes and allocates only when constructing the
/// backing `PathBuf` / `String` for file-backed and memfd records.
pub struct MapsParser<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> MapsParser<'a> {
    /// Create a parser over `buffer`.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Parse the next VMA record, or `None` at end of input.
    pub fn parse_next(&mut self) -> Result<Option<VmaRecord>, MapsParseError> {
        if self.cursor >= self.buffer.len() {
            return Ok(None);
        }

        let line_end = match self.buffer[self.cursor..].iter().position(|&b| b == b'\n') {
            Some(idx) => self.cursor + idx,
            None => self.buffer.len(),
        };

        let line = &self.buffer[self.cursor..line_end];
        self.cursor = if line_end < self.buffer.len() {
            line_end + 1
        } else {
            line_end
        };

        if line.is_empty() {
            return Ok(None);
        }

        Self::parse_line(line).map(Some)
    }

    fn parse_line(line: &[u8]) -> Result<VmaRecord, MapsParseError> {
        // Split into at most six fields so a pathname containing spaces (and
        // the trailing " (deleted)" marker) survives intact.
        let mut parts = line.splitn(6, |&b| b == b' ');

        let addr_range = parts.next().ok_or(MapsParseError::UnexpectedEof)?;
        let dash_pos = addr_range
            .iter()
            .position(|&b| b == b'-')
            .ok_or(MapsParseError::InvalidAddressRange)?;
        let start =
            parse_hex_u64(&addr_range[..dash_pos]).ok_or(MapsParseError::InvalidAddressRange)?;
        let end = parse_hex_u64(&addr_range[dash_pos + 1..])
            .ok_or(MapsParseError::InvalidAddressRange)?;

        let perms_bytes = parts.next().ok_or(MapsParseError::UnexpectedEof)?;
        if perms_bytes.len() < 4 {
            return Err(MapsParseError::InvalidPermissions);
        }
        let mut perms = VmaProtection::empty();
        if perms_bytes[0] == b'r' {
            perms |= VmaProtection::READ;
        }
        if perms_bytes[1] == b'w' {
            perms |= VmaProtection::WRITE;
        }
        if perms_bytes[2] == b'x' {
            perms |= VmaProtection::EXEC;
        }
        if perms_bytes[3] == b's' {
            perms |= VmaProtection::SHARED;
        }
        if perms_bytes[3] == b'p' {
            perms |= VmaProtection::PRIVATE;
        }

        let offset_bytes = parts.next().ok_or(MapsParseError::UnexpectedEof)?;
        let offset = parse_hex_u64(offset_bytes).ok_or(MapsParseError::InvalidOffset)?;

        let dev_bytes = parts.next().ok_or(MapsParseError::UnexpectedEof)?;
        let colon_pos = dev_bytes
            .iter()
            .position(|&b| b == b':')
            .ok_or(MapsParseError::InvalidDevice)?;
        let dev_major =
            parse_hex_u32(&dev_bytes[..colon_pos]).ok_or(MapsParseError::InvalidDevice)?;
        let dev_minor =
            parse_hex_u32(&dev_bytes[colon_pos + 1..]).ok_or(MapsParseError::InvalidDevice)?;

        let inode_bytes = parts.next().ok_or(MapsParseError::UnexpectedEof)?;
        let inode = parse_decimal_u64(inode_bytes).ok_or(MapsParseError::InvalidInode)?;

        let pathname = parts
            .next()
            .map(|path| path.trim_ascii())
            .filter(|path| !path.is_empty());
        let backing = match pathname {
            None => VmaBacking::Anonymous,
            Some(path) => classify_backing(path),
        };

        Ok(VmaRecord {
            start,
            end,
            perms,
            offset,
            dev_major,
            dev_minor,
            inode,
            backing,
        })
    }
}

fn classify_backing(path: &[u8]) -> VmaBacking {
    let s = match std::str::from_utf8(path) {
        Ok(value) => value,
        Err(_) => {
            return VmaBacking::File(PathBuf::from(String::from_utf8_lossy(path).into_owned()))
        }
    };

    if s == "[heap]" {
        VmaBacking::Heap
    } else if s == "[stack]" || s.starts_with("[stack:") {
        VmaBacking::Stack
    } else if s == "[vdso]" {
        VmaBacking::Vdso
    } else if s == "[vvar]" {
        VmaBacking::Vvar
    } else if s == "[vsyscall]" {
        VmaBacking::Vsyscall
    } else if s.starts_with("/memfd:") {
        VmaBacking::Memfd(s.to_string())
    } else if let Some(clean_path) = s.strip_suffix(" (deleted)") {
        VmaBacking::Deleted(PathBuf::from(clean_path))
    } else {
        VmaBacking::File(PathBuf::from(s))
    }
}

/// Read and parse `/proc/[pid]/maps` into a vector of VMA records.
pub fn read_process_maps(pid: i32) -> Result<Vec<VmaRecord>, std::io::Error> {
    let path = format!("/proc/{pid}/maps");
    let data = std::fs::read(path)?;
    let mut parser = MapsParser::new(&data);
    let mut vmas = Vec::new();

    loop {
        match parser.parse_next() {
            Ok(Some(vma)) => vmas.push(vma),
            Ok(None) => break,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse maps entry: {err:?}"),
                ))
            }
        }
    }

    Ok(vmas)
}

#[inline(always)]
fn parse_hex_u64(slice: &[u8]) -> Option<u64> {
    if slice.is_empty() {
        return None;
    }
    let mut val = 0u64;
    for &b in slice {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        val = val.checked_mul(16)?.checked_add(digit)?;
    }
    Some(val)
}

#[inline(always)]
fn parse_hex_u32(slice: &[u8]) -> Option<u32> {
    u32::try_from(parse_hex_u64(slice)?).ok()
}

#[inline(always)]
fn parse_decimal_u64(slice: &[u8]) -> Option<u64> {
    if slice.is_empty() {
        return None;
    }
    let mut val = 0u64;
    for &b in slice {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(val)
}
