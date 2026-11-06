use cerberus_procfs::maps::{MapsParser, VmaBacking, VmaProtection};
use std::path::PathBuf;

const SYNTHETIC_MAPS: &[u8] = b"\
00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon\n\
00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon\n\
00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/dbus-daemon\n\
7fff5be2a000-7fff5be4b000 rw-p 00000000 00:00 0   [stack]\n\
7fff5be7f000-7fff5be83000 r--p 00000000 00:00 0   [vvar]\n\
7fff5be83000-7fff5be85000 r-xp 00000000 00:00 0   [vdso]\n\
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n\
7f0000000000-7f0000001000 rwxp 00000000 00:00 0\n\
7f0000100000-7f0000102000 r-xp 00001000 00:00 1234 /memfd:payload (deleted)\n\
7f0000200000-7f0000201000 r--p 00000000 08:02 9999 /usr/lib/libdeleted.so (deleted)\n\
7f0000300000-7f0000301000 rw-p 00000000 00:00 0\n";

#[test]
fn test_maps_parsing() {
    let mut parser = MapsParser::new(SYNTHETIC_MAPS);

    let first = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(first.start, 0x0040_0000);
    assert_eq!(first.end, 0x0045_2000);
    assert_eq!(first.size(), 0x52_000);
    assert!(first.is_executable());
    assert!(!first.is_rwx());
    assert_eq!(first.offset, 0);
    assert_eq!(first.dev_major, 0x08);
    assert_eq!(first.dev_minor, 0x02);
    assert_eq!(first.inode, 173521);
    assert_eq!(
        first.backing,
        VmaBacking::File(PathBuf::from("/usr/bin/dbus-daemon"))
    );

    let second = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(second.perms, VmaProtection::READ | VmaProtection::PRIVATE);
    assert_eq!(second.offset, 0x51000);

    let third = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(
        third.perms,
        VmaProtection::READ | VmaProtection::WRITE | VmaProtection::PRIVATE
    );

    let stack = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(stack.backing, VmaBacking::Stack);

    let vvar = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(vvar.backing, VmaBacking::Vvar);

    let vdso = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(vdso.backing, VmaBacking::Vdso);
    assert!(vdso.is_executable());

    let vsyscall = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(vsyscall.backing, VmaBacking::Vsyscall);
    assert!(vsyscall.is_executable());

    let rwx = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert!(rwx.is_rwx());
    assert!(rwx.is_anonymous_exec());
    assert_eq!(rwx.backing, VmaBacking::Anonymous);

    let memfd = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(
        memfd.backing,
        VmaBacking::Memfd("/memfd:payload (deleted)".to_string())
    );

    let deleted = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(
        deleted.backing,
        VmaBacking::Deleted(PathBuf::from("/usr/lib/libdeleted.so"))
    );

    let anonymous = parser
        .parse_next()
        .expect("line should parse")
        .expect("VMA");
    assert_eq!(anonymous.backing, VmaBacking::Anonymous);

    assert!(parser
        .parse_next()
        .expect("end of input should parse")
        .is_none());
}

#[test]
fn test_maps_parser_rejects_malformed_lines() {
    let mut parser = MapsParser::new(b"not-an-address r-xp 00000000 08:02 1 /bin/x\n");
    assert!(parser.parse_next().is_err());
}

#[test]
fn test_read_current_process_maps() {
    let pid = std::process::id() as i32;
    let vmas = cerberus_procfs::maps::read_process_maps(pid).expect("maps should parse");
    assert!(!vmas.is_empty());
    assert!(vmas.iter().all(|vma| vma.start < vma.end));
    assert!(vmas.iter().any(|vma| vma.is_executable()));
}
