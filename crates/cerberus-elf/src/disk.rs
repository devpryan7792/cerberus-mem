//! On-disk ELF parsing: text section, load bias reference, and relocations.

use goblin::elf::reloc::RelocSection;
use goblin::elf::{program_header::PT_LOAD, Elf};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Errors produced while loading or parsing an on-disk ELF image.
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    /// The file could not be read.
    #[error("failed to read ELF file {path}: {source}")]
    Io {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Goblin rejected the ELF image.
    #[error("failed to parse ELF file {path}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying parse error.
        source: goblin::error::Error,
    },
    /// The image has no `.text` section.
    #[error("ELF file {path} has no .text section")]
    MissingText {
        /// Path that lacked `.text`.
        path: PathBuf,
    },
    /// A section or relocation range overflowed the file bounds.
    #[error("ELF file {path} contains invalid section bounds")]
    InvalidBounds {
        /// Path with invalid bounds.
        path: PathBuf,
    },
}

/// A loaded `.text` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSection {
    /// File offset of the section.
    pub file_offset: u64,
    /// Link-time virtual address of the section.
    pub virtual_address: u64,
    /// Section size in bytes.
    pub size: u64,
    /// Raw bytes copied from disk.
    pub data: Vec<u8>,
}

/// A dynamic relocation that lands inside `.text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationRecord {
    /// Offset relative to the start of `.text`.
    pub offset_in_text: u64,
    /// ELF relocation type.
    pub relocation_type: u32,
    /// Width of the patched field in bytes.
    pub width: usize,
}

/// Parsed on-disk view of an ELF executable or shared object.
#[derive(Debug, Clone)]
pub struct ElfDiskImage {
    /// Path of the loaded artifact.
    pub path: PathBuf,
    /// ELF entry point (link-time virtual address).
    pub entry_point: u64,
    /// Lowest `PT_LOAD` virtual address, used to derive the runtime base.
    pub min_load_vaddr: u64,
    /// Parsed `.text` section.
    pub text: TextSection,
    /// Dynamic relocations inside `.text`.
    pub relocations: Vec<RelocationRecord>,
}

/// Read-only memory map of an on-disk file.
///
/// Mapping avoids copying multi-hundred-megabyte executables into the heap
/// merely to inspect a few ELF tables.
pub(crate) struct MappedFile {
    ptr: *mut libc::c_void,
    len: usize,
}

impl MappedFile {
    /// Map `path` read-only.
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;

        let file = std::fs::File::open(path)?;
        let length = file.metadata()?.len();
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty ELF file",
            ));
        }
        let len = usize::try_from(length).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "ELF file too large to map")
        })?;

        // SAFETY: `len` is the exact file length reported by fstat, the fd is
        // valid for the duration of the call, and the mapping is read-only.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { ptr, len })
    }

    /// Borrow the mapped bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` was returned by a successful `mmap` of `len` bytes and
        // remains valid until `Drop`; the mapping is read-only.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` describe the live mapping created in `open`.
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

impl ElfDiskImage {
    /// Load and parse `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ElfError> {
        let path = path.as_ref().to_path_buf();
        let mapping = MappedFile::open(&path).map_err(|source| ElfError::Io {
            path: path.clone(),
            source,
        })?;
        let bytes = mapping.as_slice();
        let elf = Elf::parse(bytes).map_err(|source| ElfError::Parse {
            path: path.clone(),
            source,
        })?;

        let (virtual_address, file_offset, size) = find_text_section(&elf, &path)?;
        let offset = usize::try_from(file_offset)
            .map_err(|_| ElfError::InvalidBounds { path: path.clone() })?;
        let length =
            usize::try_from(size).map_err(|_| ElfError::InvalidBounds { path: path.clone() })?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| ElfError::InvalidBounds { path: path.clone() })?;
        let data = bytes
            .get(offset..end)
            .ok_or_else(|| ElfError::InvalidBounds { path: path.clone() })?
            .to_vec();

        let min_load_vaddr = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .map(|header| header.p_vaddr)
            .min()
            .unwrap_or(0);

        let text_end = virtual_address
            .checked_add(size)
            .ok_or_else(|| ElfError::InvalidBounds { path: path.clone() })?;

        let mut relocations = Vec::new();
        collect_text_relocations(&elf.dynrelas, virtual_address, text_end, &mut relocations);
        collect_text_relocations(&elf.dynrels, virtual_address, text_end, &mut relocations);
        collect_text_relocations(&elf.pltrelocs, virtual_address, text_end, &mut relocations);

        relocations.sort_unstable_by_key(|reloc| reloc.offset_in_text);
        relocations.dedup_by_key(|reloc| reloc.offset_in_text);

        Ok(Self {
            path,
            entry_point: elf.header.e_entry,
            min_load_vaddr,
            text: TextSection {
                file_offset,
                virtual_address,
                size,
                data,
            },
            relocations,
        })
    }

    /// Runtime address of `.text` for a mapping whose load base is `load_base`.
    pub fn runtime_text_address(&self, load_base: u64) -> u64 {
        load_base.saturating_add(
            self.text
                .virtual_address
                .saturating_sub(self.min_load_vaddr),
        )
    }

    /// Runtime entry point for a mapping whose load base is `load_base`.
    pub fn runtime_entry_point(&self, load_base: u64) -> u64 {
        load_base.saturating_add(self.entry_point.saturating_sub(self.min_load_vaddr))
    }
}

/// Process-wide cache of parsed ELF images.
static DISK_CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<ElfDiskImage>>>> = OnceLock::new();

/// Load an ELF image, reusing a previously parsed copy when possible.
///
/// Many processes share the same executable inode; caching avoids repeatedly
/// reading and parsing it during a host sweep.
pub fn load_cached(path: impl AsRef<Path>) -> Result<Arc<ElfDiskImage>, ElfError> {
    let path = path.as_ref();
    let cache = DISK_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(image) = guard.get(path) {
            return Ok(Arc::clone(image));
        }
    }

    let image = Arc::new(ElfDiskImage::load(path)?);
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(path.to_path_buf(), Arc::clone(&image));
    Ok(image)
}

/// Clear the parsed ELF image cache. Call between host sweeps so replaced
/// binaries are re-read from disk.
pub fn clear_cache() {
    if let Some(cache) = DISK_CACHE.get() {
        let mut guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
    }
}

fn find_text_section(elf: &Elf<'_>, path: &Path) -> Result<(u64, u64, u64), ElfError> {
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".text" {
                return Ok((section.sh_addr, section.sh_offset, section.sh_size));
            }
        }
    }
    Err(ElfError::MissingText {
        path: path.to_path_buf(),
    })
}

fn collect_text_relocations(
    section: &RelocSection<'_>,
    text_start: u64,
    text_end: u64,
    output: &mut Vec<RelocationRecord>,
) {
    const RELOCATION_WIDTH: usize = 8;

    for reloc in section.iter() {
        let width = RELOCATION_WIDTH as u64;
        let Some(reloc_end) = reloc.r_offset.checked_add(width) else {
            continue;
        };
        if reloc.r_offset >= text_start && reloc_end <= text_end {
            output.push(RelocationRecord {
                offset_in_text: reloc.r_offset - text_start,
                relocation_type: reloc.r_type,
                width: RELOCATION_WIDTH,
            });
        }
    }
}
