//! Dynamic symbol, GOT/PLT, and relocation parsing.

use crate::disk::{ElfError, MappedFile};
use goblin::elf::reloc::RelocSection;
use goblin::elf::sym::{STT_FUNC, STT_GNU_IFUNC};
use goblin::elf::Elf;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// A GOT/PLT slot that is populated by the dynamic linker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotEntry {
    /// Imported symbol name.
    pub symbol_name: String,
    /// Link-time virtual address of the GOT slot.
    pub got_vaddr: u64,
    /// Slot width in bytes.
    pub slot_size: usize,
}

/// An exported function symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSymbol {
    /// Symbol name.
    pub name: String,
    /// Link-time virtual address.
    pub value: u64,
    /// Symbol size in bytes, or zero if unknown.
    pub size: u64,
}

/// Dynamic linking metadata extracted from an on-disk ELF image.
#[derive(Debug, Clone)]
pub struct DynamicInfo {
    /// GOT/PLT slots and their imported symbol names.
    pub got_entries: Vec<GotEntry>,
    /// Exported function symbols.
    pub exported_functions: Vec<ExportedSymbol>,
    /// Link-time virtual address of `.text`.
    pub text_vaddr: u64,
    /// Size of `.text`.
    pub text_size: u64,
    /// Link-time PLT ranges (`.plt`, `.plt.sec`, `.plt.got`, `.iplt`).
    pub plt_ranges: Vec<(u64, u64)>,
    /// Lowest `PT_LOAD` virtual address.
    pub min_load_vaddr: u64,
}

impl DynamicInfo {
    /// Runtime address of an exported symbol for a given load base.
    pub fn runtime_symbol_address(&self, load_base: u64, symbol: &ExportedSymbol) -> u64 {
        load_base.saturating_add(symbol.value.saturating_sub(self.min_load_vaddr))
    }

    /// Runtime range of the executable `.text` section for a given load base.
    pub fn runtime_text_range(&self, load_base: u64) -> (u64, u64) {
        let start = load_base.saturating_add(self.text_vaddr.saturating_sub(self.min_load_vaddr));
        (start, start.saturating_add(self.text_size))
    }

    /// Runtime PLT ranges for a given load base.
    pub fn runtime_plt_ranges(&self, load_base: u64) -> Vec<(u64, u64)> {
        self.plt_ranges
            .iter()
            .map(|(start, size)| {
                let runtime_start =
                    load_base.saturating_add(start.saturating_sub(self.min_load_vaddr));
                (runtime_start, runtime_start.saturating_add(*size))
            })
            .collect()
    }
}

/// Load dynamic linking metadata from `path`.
pub fn load_dynamic_info(path: impl AsRef<Path>) -> Result<DynamicInfo, ElfError> {
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

    let (text_vaddr, text_size) = find_text_section(&elf, &path)?;
    let min_load_vaddr = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|header| header.p_vaddr)
        .min()
        .unwrap_or(0);

    let mut got_entries = Vec::new();
    collect_got_entries(&elf, &elf.dynrelas, &mut got_entries);
    collect_got_entries(&elf, &elf.dynrels, &mut got_entries);
    collect_got_entries(&elf, &elf.pltrelocs, &mut got_entries);
    got_entries.sort_unstable_by(|left, right| {
        left.got_vaddr
            .cmp(&right.got_vaddr)
            .then_with(|| left.symbol_name.cmp(&right.symbol_name))
    });
    got_entries.dedup_by(|left, right| {
        left.got_vaddr == right.got_vaddr && left.symbol_name == right.symbol_name
    });

    let mut exported_functions = Vec::new();
    for symbol in elf.dynsyms.iter() {
        let symbol_type = symbol.st_type();
        if symbol_type != STT_FUNC && symbol_type != STT_GNU_IFUNC {
            continue;
        }
        if symbol.st_value == 0 {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        exported_functions.push(ExportedSymbol {
            name: name.to_string(),
            value: symbol.st_value,
            size: symbol.st_size,
        });
    }

    let mut plt_ranges = Vec::new();
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") && section.sh_size > 0 {
                plt_ranges.push((section.sh_addr, section.sh_size));
            }
        }
    }
    plt_ranges.sort_unstable();

    Ok(DynamicInfo {
        got_entries,
        exported_functions,
        text_vaddr,
        text_size,
        plt_ranges,
        min_load_vaddr,
    })
}

/// Process-wide cache of parsed dynamic linking metadata.
static DYNAMIC_CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<DynamicInfo>>>> = OnceLock::new();
/// Per-path load locks for dynamic metadata.
static DYNAMIC_LOAD_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

fn dynamic_load_lock(path: &Path) -> Arc<Mutex<()>> {
    let locks = DYNAMIC_LOAD_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        guard
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

/// Load dynamic linking metadata, reusing a previously parsed copy when possible.
pub fn load_dynamic_info_cached(path: impl AsRef<Path>) -> Result<Arc<DynamicInfo>, ElfError> {
    let path = path.as_ref();
    let cache = DYNAMIC_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(info) = guard.get(path) {
            return Ok(Arc::clone(info));
        }
    }

    let load_lock = dynamic_load_lock(path);
    let _loading = load_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    {
        let guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(info) = guard.get(path) {
            return Ok(Arc::clone(info));
        }
    }

    let info = Arc::new(load_dynamic_info(path)?);
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(path.to_path_buf(), Arc::clone(&info));
    Ok(info)
}

/// Clear the parsed dynamic-info cache. Call between host sweeps.
pub fn clear_cache() {
    if let Some(cache) = DYNAMIC_CACHE.get() {
        let mut guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
    }
    if let Some(locks) = DYNAMIC_LOAD_LOCKS.get() {
        let mut guard = locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
    }
}

fn find_text_section(elf: &Elf<'_>, path: &Path) -> Result<(u64, u64), ElfError> {
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".text" {
                return Ok((section.sh_addr, section.sh_size));
            }
        }
    }
    Err(ElfError::MissingText {
        path: path.to_path_buf(),
    })
}

fn collect_got_entries(elf: &Elf<'_>, section: &RelocSection<'_>, output: &mut Vec<GotEntry>) {
    for reloc in section.iter() {
        if reloc.r_sym == 0 {
            continue;
        }
        let Some(symbol) = elf.dynsyms.get(reloc.r_sym) else {
            continue;
        };
        // GOT pointer validation applies to function imports. Data symbols
        // (stdout, environ, typeinfo, ...) legitimately point at writable data.
        let symbol_type = symbol.st_type();
        if symbol_type != STT_FUNC && symbol_type != STT_GNU_IFUNC {
            continue;
        }
        if !symbol.is_import() {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        output.push(GotEntry {
            symbol_name: name.to_string(),
            got_vaddr: reloc.r_offset,
            slot_size: 8,
        });
    }
}
