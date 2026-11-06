//! `/proc/[pid]/auxv` parsing and forensic anchor extraction.

/// Auxiliary vector terminator.
pub const AT_NULL: u64 = 0;
/// Address of the program headers in virtual memory.
pub const AT_PHDR: u64 = 3;
/// Size of one program header entry.
pub const AT_PHENT: u64 = 4;
/// Number of program header entries.
pub const AT_PHNUM: u64 = 5;
/// System page size.
pub const AT_PAGESZ: u64 = 6;
/// Base address of the dynamic linker.
pub const AT_BASE: u64 = 7;
/// Loader flags.
pub const AT_FLAGS: u64 = 8;
/// Entry point address of the main executable.
pub const AT_ENTRY: u64 = 9;
/// Pointer to the executable filename string.
pub const AT_EXECFN: u64 = 31;

/// One 64-bit auxiliary vector entry.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Elf64AuxvEntry {
    /// Entry type.
    pub a_type: u64,
    /// Entry value.
    pub a_val: u64,
}

/// Immutable process anchors recovered from the auxiliary vector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessAuxvAnchors {
    /// `AT_PHDR` value.
    pub phdr_addr: Option<u64>,
    /// `AT_PHENT` value.
    pub phent_size: Option<u64>,
    /// `AT_PHNUM` value.
    pub phnum: Option<u64>,
    /// `AT_BASE` value.
    pub base_addr: Option<u64>,
    /// `AT_ENTRY` value.
    pub entry_point: Option<u64>,
    /// `AT_EXECFN` value.
    pub execfn_ptr: Option<u64>,
}

impl ProcessAuxvAnchors {
    /// Parse a raw auxiliary vector byte buffer.
    pub fn parse_from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let entry_size = std::mem::size_of::<Elf64AuxvEntry>();
        if !data.len().is_multiple_of(entry_size) {
            return Err("Malformed auxv buffer size");
        }

        let mut anchors = Self::default();
        for chunk in data.chunks_exact(entry_size) {
            let mut type_bytes = [0u8; 8];
            let mut value_bytes = [0u8; 8];
            type_bytes.copy_from_slice(&chunk[0..8]);
            value_bytes.copy_from_slice(&chunk[8..16]);
            let a_type = u64::from_ne_bytes(type_bytes);
            let a_val = u64::from_ne_bytes(value_bytes);

            match a_type {
                AT_NULL => break,
                AT_PHDR => anchors.phdr_addr = Some(a_val),
                AT_PHENT => anchors.phent_size = Some(a_val),
                AT_PHNUM => anchors.phnum = Some(a_val),
                AT_BASE => anchors.base_addr = Some(a_val),
                AT_ENTRY => anchors.entry_point = Some(a_val),
                AT_EXECFN => anchors.execfn_ptr = Some(a_val),
                _ => {}
            }
        }

        Ok(anchors)
    }
}

/// Reader for `/proc/[pid]/auxv`.
pub struct AuxvReader;

impl AuxvReader {
    /// Read and parse the auxiliary vector of `pid`.
    pub fn read_anchors(pid: i32) -> Result<ProcessAuxvAnchors, std::io::Error> {
        let path = format!("/proc/{pid}/auxv");
        let data = std::fs::read(path)?;
        ProcessAuxvAnchors::parse_from_bytes(&data)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}
