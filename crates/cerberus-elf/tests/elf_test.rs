use cerberus_elf::disk::{load_cached, ElfDiskImage, RelocationRecord};
use cerberus_elf::dynamic::{load_dynamic_info, load_dynamic_info_cached};
use cerberus_elf::reloc::RelocationMask;
use std::sync::Arc;

#[test]
fn test_load_current_executable() {
    let exe = std::env::current_exe().expect("current exe");
    let image = ElfDiskImage::load(&exe).expect("ELF should parse");

    assert!(!image.text.data.is_empty());
    assert_eq!(image.text.data.len() as u64, image.text.size);
    assert_eq!(image.path, exe);
    assert_eq!(
        image.runtime_text_address(0x1000),
        0x1000u64.saturating_add(
            image
                .text
                .virtual_address
                .saturating_sub(image.min_load_vaddr)
        )
    );
}

#[test]
fn test_dynamic_info_current_executable() {
    let exe = std::env::current_exe().expect("current exe");
    let info = load_dynamic_info(&exe).expect("dynamic info should parse");

    assert!(info.text_size > 0);
    assert!(!info.plt_ranges.is_empty(), "test binary should have a PLT");
    let (start, end) = info.runtime_text_range(0x1000);
    assert!(start < end);
    let plt = info.runtime_plt_ranges(0x1000);
    assert!(!plt.is_empty());
    assert!(plt.iter().all(|(start, end)| start < end));
}

#[test]
fn test_relocation_mask_zeroes_intervals() {
    let mut mask = RelocationMask::new();
    mask.add_interval(4, 8);
    mask.add_interval(100, 8);

    let mut buffer = [0xAAu8; 16];
    mask.apply_mask(&mut buffer);

    assert_eq!(&buffer[..4], &[0xAA; 4]);
    assert_eq!(&buffer[4..12], &[0; 8]);
    assert_eq!(&buffer[12..], &[0xAA; 4]);
}

#[test]
fn test_relocation_mask_from_records_clamps() {
    let records = [RelocationRecord {
        offset_in_text: 14,
        relocation_type: 8,
        width: 8,
    }];
    let mask = RelocationMask::from_relocations(&records);
    let mut buffer = [0xFFu8; 16];
    mask.apply_mask(&mut buffer);
    assert_eq!(&buffer[..14], &[0xFF; 14]);
    assert_eq!(&buffer[14..], &[0; 2]);
}

#[test]
fn test_masked_eq_ignores_exempted_bytes() {
    let mut mask = RelocationMask::new();
    mask.add_interval(4, 8);

    let left = [0u8; 16];
    let mut right = [0u8; 16];
    right[6] = 0xFF;
    assert!(mask.masked_eq(&left, &right));

    right[2] = 0xFF;
    assert!(!mask.masked_eq(&left, &right));
}

#[test]
fn test_masked_eq_handles_unsorted_overlapping_intervals() {
    let mut mask = RelocationMask::new();
    mask.add_interval(10, 4);
    mask.add_interval(2, 8);
    mask.add_interval(6, 8);

    let left = [0u8; 20];
    let mut right = [0u8; 20];
    right[2..14].fill(0xFF);
    assert!(mask.masked_eq(&left, &right));

    right[15] = 0xFF;
    assert!(!mask.masked_eq(&left, &right));
}

#[test]
fn test_masked_eq_rejects_different_lengths() {
    let mask = RelocationMask::new();
    assert!(!mask.masked_eq(&[0u8; 4], &[0u8; 5]));
}

#[test]
fn test_rejects_non_elf_input() {
    let path = std::env::temp_dir().join(format!(
        "cerberus-elf-not-elf-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, b"this is not an elf").expect("write fixture");
    let result = ElfDiskImage::load(&path);
    let _ = std::fs::remove_file(&path);
    assert!(result.is_err());
}

#[test]
fn test_elf_caches_return_shared_arcs() {
    let exe = std::env::current_exe().expect("current exe");

    let first = load_cached(&exe).expect("cached disk image");
    let second = load_cached(&exe).expect("cached disk image");
    assert!(Arc::ptr_eq(&first, &second));

    let first_dynamic = load_dynamic_info_cached(&exe).expect("cached dynamic info");
    let second_dynamic = load_dynamic_info_cached(&exe).expect("cached dynamic info");
    assert!(Arc::ptr_eq(&first_dynamic, &second_dynamic));
}
