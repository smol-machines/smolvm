use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn request(server: &mut Server, kind: u8, body: Vec<u8>) -> Result<Vec<u8>> {
    server.request(kind, 7, &mut Packet(&body))
}
fn path(body: &mut Vec<u8>, p: &std::path::Path) {
    wire::string(body, p.as_os_str().as_bytes());
}

#[test]
fn malformed_requests_cannot_mutate_or_allocate_unbounded_storage() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("keep");
    fs::write(&file, b"unchanged").unwrap();
    let mut server = Server::default();
    let mut body = Vec::new();
    path(&mut body, &file);
    body.push(99);
    assert_eq!(request(&mut server, 13, body).unwrap_err().code, 5);
    assert_eq!(fs::read(&file).unwrap(), b"unchanged");
    for header in [0u32, 4, MAX_PACKET as u32, u32::MAX] {
        assert!(wire::read(&mut &header.to_be_bytes()[..]).is_err());
    }
    assert!(wire::read(&mut &[0, 1][..]).is_err());
    assert!(wire::read(&mut &[][..]).unwrap().is_none());
    let mut p = Packet(&[0, 0, 0, 2, b'x', 0]);
    assert!(p.path().is_err());
}
#[test]
fn rename_and_posix_rename_have_distinct_atomic_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::write(&a, b"new").unwrap();
    fs::write(&b, b"old").unwrap();
    let mut server = Server::default();
    let mut body = Vec::new();
    path(&mut body, &a);
    path(&mut body, &b);
    assert!(request(&mut server, 18, body).is_err());
    assert_eq!(fs::read(&b).unwrap(), b"old");
    let mut body = Vec::new();
    wire::string(&mut body, b"posix-rename@openssh.com");
    path(&mut body, &a);
    path(&mut body, &b);
    request(&mut server, 200, body).unwrap();
    assert_eq!(fs::read(&b).unwrap(), b"new");
    assert!(!a.exists());
}
#[test]
fn file_attributes_and_handles_survive_rename_but_not_close() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::write(&a, b"abcdefgh").unwrap();
    let mut server = Server::default();
    let mut body = Vec::new();
    path(&mut body, &a);
    wire::u32(&mut body, 3);
    wire::u32(&mut body, 0);
    let reply = request(&mut server, 3, body).unwrap();
    let handle = Packet(&reply[5..]).string().unwrap().to_vec();
    fs::rename(&a, &b).unwrap();
    let mut body = Vec::new();
    wire::string(&mut body, &handle);
    wire::u32(&mut body, 13);
    wire::u64(&mut body, 3);
    wire::u32(&mut body, 0o640);
    wire::u32(&mut body, 1234567890);
    wire::u32(&mut body, 1234567891);
    request(&mut server, 10, body).unwrap();
    let meta = fs::metadata(&b).unwrap();
    assert_eq!(meta.len(), 3);
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(meta.mtime(), 1234567891);
    let mut body = Vec::new();
    wire::string(&mut body, &handle);
    request(&mut server, 4, body.clone()).unwrap();
    assert!(request(&mut server, 8, body).is_err());
}
#[test]
fn canonical_paths_support_missing_final_names_and_dangling_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("missing");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("missing", &link).unwrap();
    assert_eq!(files::realpath(&target).unwrap(), target);
    assert_eq!(files::realpath(&link).unwrap(), target);
    assert!(files::realpath(&dir.path().join("absent/child")).is_err());
    std::os::unix::fs::symlink("cycle", dir.path().join("cycle")).unwrap();
    assert!(files::realpath(&dir.path().join("cycle")).is_err());
}
#[test]
fn readdir_is_paged_and_preserves_non_utf8_names() {
    use std::ffi::OsStr;
    let dir = tempfile::tempdir().unwrap();
    for n in 0..130 {
        fs::write(dir.path().join(n.to_string()), b"").unwrap();
    }
    fs::write(dir.path().join(OsStr::from_bytes(b"raw-\xff")), b"").unwrap();
    let mut server = Server::default();
    let mut body = Vec::new();
    path(&mut body, dir.path());
    let reply = request(&mut server, 11, body).unwrap();
    let handle = Packet(&reply[5..]).string().unwrap().to_vec();
    let mut count = 0;
    let mut raw = false;
    loop {
        let mut body = Vec::new();
        wire::string(&mut body, &handle);
        let reply = match request(&mut server, 12, body) {
            Ok(reply) => reply,
            Err(e) => {
                assert_eq!(e.code, 1);
                break;
            }
        };
        let mut p = Packet(&reply[5..]);
        let n = p.u32().unwrap();
        assert!(n <= 64);
        count += n;
        for _ in 0..n {
            raw |= p.string().unwrap() == b"raw-\xff";
            p.string().unwrap();
            Attributes::read(&mut p).unwrap();
        }
        p.end().unwrap();
    }
    assert_eq!(count, 131);
    assert!(raw);
}

#[test]
fn concurrent_removals_do_not_end_directory_listing_early() {
    let dir = tempfile::tempdir().unwrap();
    for n in 0..65 {
        fs::write(dir.path().join(n.to_string()), b"").unwrap();
    }
    // Retain real entries, as a directory cursor can do before clients remove
    // files. Arrange one full page of vanished entries before a surviving one.
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .collect::<io::Result<_>>()
        .unwrap();
    for entry in &entries[..64] {
        fs::remove_file(entry.path()).unwrap();
    }
    let surviving_name = entries[64].file_name();
    let mut entries = entries.into_iter().map(Ok);
    let reply = read_directory(7, &mut entries).unwrap();
    let mut packet = Packet(&reply[5..]);
    assert_eq!(packet.u32().unwrap(), 1);
    assert_eq!(packet.string().unwrap(), surviving_name.as_bytes());
    packet.string().unwrap();
    Attributes::read(&mut packet).unwrap();
    packet.end().unwrap();
    assert_eq!(read_directory(8, &mut entries).unwrap_err().code, 1);
}
