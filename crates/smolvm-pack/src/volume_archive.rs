//! Streaming transfer of quiesced engine-managed virtiofs volumes.
//!
//! The tar payload retains sparse files and hardlinks. Per-entry PAX metadata
//! carries the raw share's guest-visible owners and modes, independently of the
//! transferring host's uid, permissions and xattr conventions. This is the view
//! *before* any container idmap, which a saved guest may still have installed.
//! Callers must fence every writer for the entire export and must not publish an
//! imported volume until the complete workload transfer has been validated.

use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

// Linux guest file-type bits, independent of the host libc mode_t width.
const TYPE_MASK: u32 = 0o170000;
const DIRECTORY: u32 = 0o040000;
const REGULAR: u32 = 0o100000;
const SYMLINK: u32 = 0o120000;

const STAT: &str = "user.containers.override_stat";
const LINKS: &str = "user.krun.symlink_owners";
const PAX: &str = "SMOL.volume.metadata.v1";
const END: &str = "SMOL_VOLUME_COMPLETE_V1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    mtime_ns: u32,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("NUL in volume path"))
}

// Read without following links. Missing attributes are normal; other errors
// must not silently turn an unreadable ownership record into a host uid.
fn attribute(path: &Path, name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
    let path = c_path(path)?;
    let name = name.map(CString::new).transpose().map_err(invalid_error)?;
    let call = |buffer: *mut libc::c_void, len| unsafe {
        #[cfg(target_os = "linux")]
        {
            match &name {
                Some(name) => libc::lgetxattr(path.as_ptr(), name.as_ptr(), buffer, len),
                None => libc::llistxattr(path.as_ptr(), buffer.cast(), len),
            }
        }
        #[cfg(target_os = "macos")]
        {
            match &name {
                Some(name) => libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    buffer,
                    len,
                    0,
                    libc::XATTR_NOFOLLOW,
                ),
                None => libc::listxattr(path.as_ptr(), buffer.cast(), len, libc::XATTR_NOFOLLOW),
            }
        }
    };
    let len = call(std::ptr::null_mut(), 0);
    if len < 0 {
        let error = io::Error::last_os_error();
        #[cfg(target_os = "linux")]
        let missing = libc::ENODATA;
        #[cfg(target_os = "macos")]
        let missing = libc::ENOATTR;
        return if name.is_some() && error.raw_os_error() == Some(missing) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let mut value = vec![0; len as usize];
    let actual = call(value.as_mut_ptr().cast(), value.len());
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual != len {
        return Err(invalid("volume attributes changed during export"));
    }
    Ok(Some(value))
}

fn invalid_error(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

fn guest_metadata(path: &Path, host: &Metadata) -> io::Result<GuestMetadata> {
    for name in attribute(path, None)?
        .unwrap_or_default()
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty())
    {
        if name != STAT.as_bytes() && !(host.is_dir() && name == LINKS.as_bytes()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "volume entry {} has unsupported attribute {}",
                    path.display(),
                    String::from_utf8_lossy(name)
                ),
            ));
        }
    }
    let mut result = GuestMetadata {
        uid: host.uid(),
        gid: host.gid(),
        mode: host.mode(),
        mtime: host.mtime(),
        mtime_ns: host.mtime_nsec().try_into().map_err(invalid_error)?,
    };
    #[cfg(target_os = "linux")]
    if host.file_type().is_symlink() {
        result.uid = 0;
        result.gid = 0;
        if let Some(records) = attribute(
            path.parent().ok_or_else(|| invalid("link has no parent"))?,
            Some(LINKS),
        )? {
            let mut parts = records
                .strip_suffix(&[0])
                .ok_or_else(|| invalid("invalid symlink ownership table"))?
                .split(|b| *b == 0);
            while let Some(name) = parts.next() {
                let owner = parts
                    .next()
                    .ok_or_else(|| invalid("invalid symlink ownership table"))?;
                if name == path.file_name().unwrap().as_bytes() {
                    let owner = std::str::from_utf8(owner).map_err(invalid_error)?;
                    let (uid, gid) = owner
                        .split_once(':')
                        .ok_or_else(|| invalid("invalid symlink owner"))?;
                    result.uid = uid.parse().map_err(invalid_error)?;
                    result.gid = gid.parse().map_err(invalid_error)?;
                    break;
                }
            }
        }
        return Ok(result);
    }
    if let Some(value) = attribute(path, Some(STAT))? {
        let value = std::str::from_utf8(&value).map_err(invalid_error)?;
        let fields: Vec<_> = value.split(':').collect();
        if fields.len() != 3 {
            return Err(invalid("invalid volume ownership record"));
        }
        if fields[0] != "x" {
            result.uid = fields[0].parse().map_err(invalid_error)?;
        }
        if fields[1] != "x" {
            result.gid = fields[1].parse().map_err(invalid_error)?;
        }
        if fields[2] != "x" {
            let mode = u32::from_str_radix(fields[2], 8).map_err(invalid_error)?;
            result.mode = if mode & TYPE_MASK != 0 {
                mode
            } else {
                (host.mode() & TYPE_MASK) | mode
            };
        }
    }
    if result.mode & TYPE_MASK != host.mode() & TYPE_MASK || result.mode & !0o177777 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "virtual special files cannot be transferred",
        ));
    }
    Ok(result)
}

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

/// Stream a volume whose writers have all been fenced into a portable tar.
///
/// Only engine-managed shares using recorded ownership and no default owner
/// override are supported. Arbitrary host bind mounts, sockets, devices, ACLs
/// and unrecognized xattrs are refused rather than copied with reduced fidelity.
/// An error invalidates the entire output. This function does not pause writers;
/// its mutation checks are a backstop, not a substitute for a transfer fence.
pub fn write_quiesced<W: Write>(root: &Path, output: W) -> io::Result<()> {
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err(invalid("volume root must be a directory"));
    }
    let mut builder = tar::Builder::new(output);
    builder.follow_symlinks(false);
    let mut links = HashMap::new();
    append_tree(&mut builder, root, Path::new("data"), &mut links)?;
    let mut end = tar::Header::new_gnu();
    end.set_size(0);
    end.set_mode(0o600);
    builder.append_data(&mut end, END, io::empty())?;
    builder.finish()
}

fn append_tree<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    name: &Path,
    links: &mut HashMap<(u64, u64), PathBuf>,
) -> io::Result<()> {
    let before = fs::symlink_metadata(path)?;
    if !(before.is_dir() || before.is_file() || before.file_type().is_symlink()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported volume entry {}", path.display()),
        ));
    }
    let metadata = guest_metadata(path, &before)?;
    let encoded = serde_json::to_vec(&metadata).map_err(invalid_error)?;
    builder.append_pax_extensions([
        (PAX, encoded.as_slice()),
        ("path", name.as_os_str().as_bytes()),
    ])?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&before);
    if before.is_dir() {
        header.set_size(0);
        builder.append_data(&mut header, name, io::empty())?;
        let mut entries = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            append_tree(builder, &entry.path(), &name.join(entry.file_name()), links)?;
        }
    } else if before.file_type().is_symlink() {
        header.set_size(0);
        builder.append_link(&mut header, name, fs::read_link(path)?)?;
    } else if let Some(first) = links.get(&(before.dev(), before.ino())) {
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        builder.append_link(&mut header, name, first)?;
    } else {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        if !unchanged(&before, &file.metadata()?) {
            return Err(invalid("volume file changed during export"));
        }
        #[cfg(target_os = "macos")]
        let sparse = crate::assets::append_macos_sparse_file(builder, path, Path::new("data"))?;
        #[cfg(not(target_os = "macos"))]
        let sparse = false;
        if !sparse {
            builder.append_file(name, &mut file)?;
        }
        if !unchanged(&before, &file.metadata()?) {
            return Err(invalid("volume file changed during export"));
        }
        links.insert((before.dev(), before.ino()), name.to_owned());
    }
    if !unchanged(&before, &fs::symlink_metadata(path)?) {
        return Err(invalid("volume entry changed during export"));
    }
    Ok(())
}

fn relative(path: &Path) -> io::Result<PathBuf> {
    let mut parts = path.components();
    if parts.next() != Some(Component::Normal("data".as_ref())) {
        return Err(invalid("entry outside volume root"));
    }
    let mut relative = PathBuf::new();
    for component in parts {
        let Component::Normal(name) = component else {
            return Err(invalid("invalid volume entry path"));
        };
        relative.push(name);
    }
    Ok(relative)
}

fn apply_metadata(path: &Path, metadata: &GuestMetadata) -> io::Result<()> {
    let mode = metadata.mode;
    #[cfg(target_os = "linux")]
    if mode & TYPE_MASK == SYMLINK {
        if (metadata.uid, metadata.gid) != (0, 0) {
            let parent = path.parent().ok_or_else(|| invalid("link has no parent"))?;
            let mut record = attribute(parent, Some(LINKS))?.unwrap_or_default();
            record.extend_from_slice(path.file_name().unwrap().as_bytes());
            record.push(0);
            record.extend_from_slice(format!("{}:{}", metadata.uid, metadata.gid).as_bytes());
            record.push(0);
            crate::extract::set_user_xattr(parent, LINKS, &record)?;
        }
    } else {
        crate::extract::set_user_xattr(
            path,
            STAT,
            format!("{}:{}:0{mode:o}", metadata.uid, metadata.gid).as_bytes(),
        )?;
    }
    #[cfg(target_os = "macos")]
    crate::extract::set_user_xattr(
        path,
        STAT,
        format!("{}:{}:0{mode:o}", metadata.uid, metadata.gid).as_bytes(),
    )?;
    let times = [libc::timespec {
        tv_sec: metadata.mtime,
        tv_nsec: metadata.mtime_ns.into(),
    }; 2];
    let path = c_path(path)?;
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Extract into a new private temporary directory, removed automatically on error.
///
/// The returned directory is staging only: its caller owns publication and
/// workload admission. Guest ownership is recorded without host chown or setuid;
/// host files remain 0600 and directories 0700. Links can refer outside the guest
/// volume, but are never followed during extraction. Incomplete streams, duplicate
/// names, forward hardlinks and metadata that cannot be represented are errors.
pub fn read_staged<R: Read>(input: R, staging_parent: &Path) -> io::Result<tempfile::TempDir> {
    let stage = tempfile::Builder::new()
        .prefix(".smol-volume-")
        .tempdir_in(staging_parent)?;
    let mut archive = tar::Archive::new(input);
    archive.set_overwrite(false);
    archive.set_preserve_ownerships(false);
    let mut seen = BTreeMap::<PathBuf, GuestMetadata>::new();
    let mut directories = Vec::new();
    let mut complete = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        let kind = entry.header().entry_type();
        if complete {
            return Err(invalid("entries after volume completion marker"));
        }
        if name == Path::new(END) {
            if !kind.is_file() || entry.size() != 0 || !seen.contains_key(Path::new("")) {
                return Err(invalid("invalid volume completion marker"));
            }
            complete = true;
            continue;
        }
        let relative = relative(&name)?;
        if seen.contains_key(&relative) {
            return Err(invalid("duplicate volume entry"));
        }
        if relative.as_os_str().is_empty() {
            if !seen.is_empty() || !kind.is_dir() {
                return Err(invalid("volume root must be the first directory"));
            }
        } else if !seen
            .get(relative.parent().unwrap())
            .is_some_and(|m| m.mode & TYPE_MASK == DIRECTORY)
        {
            return Err(invalid("volume entry parent is absent or not a directory"));
        }
        let mut metadata = None;
        if let Some(extensions) = entry.pax_extensions()? {
            for extension in extensions {
                let extension = extension?;
                if extension.key_bytes() == PAX.as_bytes() {
                    if metadata.is_some() {
                        return Err(invalid("duplicate volume metadata"));
                    }
                    metadata = Some(
                        serde_json::from_slice::<GuestMetadata>(extension.value_bytes())
                            .map_err(invalid_error)?,
                    );
                } else if !matches!(extension.key_bytes(), b"path" | b"linkpath") {
                    return Err(invalid("unsupported volume archive extension"));
                }
            }
        }
        let metadata = metadata.ok_or_else(|| invalid("missing volume metadata"))?;
        let expected = if kind.is_file() || kind.is_gnu_sparse() || kind.is_hard_link() {
            REGULAR
        } else if kind.is_dir() {
            DIRECTORY
        } else if kind.is_symlink() {
            SYMLINK
        } else {
            return Err(invalid("unsupported volume entry type"));
        };
        if metadata.mode & TYPE_MASK != expected
            || metadata.mode & !0o177777 != 0
            || metadata.mtime_ns >= 1_000_000_000
            || (expected == SYMLINK && metadata.mode & 0o7777 != 0o777)
        {
            return Err(invalid("invalid volume metadata"));
        }
        if !(kind.is_file() || kind.is_gnu_sparse()) && entry.size() != 0 {
            return Err(invalid("data attached to a volume link or directory"));
        }
        let path = stage.path().join(&relative);
        if kind.is_dir() {
            if !relative.as_os_str().is_empty() {
                fs::DirBuilder::new().mode(0o700).create(&path)?;
            }
            directories.push((path, metadata.clone()));
        } else {
            if kind.is_symlink() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| invalid("missing symlink target"))?;
                std::os::unix::fs::symlink(target, &path)?;
            } else if kind.is_hard_link() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| invalid("missing hardlink target"))?;
                let target = relative_path(&target)?;
                if seen.get(&target) != Some(&metadata) || metadata.mode & TYPE_MASK != REGULAR {
                    return Err(invalid(
                        "hardlink target is absent or has different metadata",
                    ));
                }
                fs::hard_link(stage.path().join(target), &path)?;
            } else {
                entry.set_mask(0o7777);
                entry.set_preserve_mtime(false);
                entry.unpack(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            apply_metadata(&path, &metadata)?;
            if expected == REGULAR {
                File::open(&path)?.sync_all()?;
            }
        }
        seen.insert(relative, metadata);
    }
    if !complete {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete volume archive",
        ));
    }
    for (path, metadata) in directories.into_iter().rev() {
        apply_metadata(&path, &metadata)?;
        File::open(path)?.sync_all()?;
    }
    Ok(stage)
}

// Avoid shadowing the validated relative path local in the importer.
fn relative_path(path: &Path) -> io::Result<PathBuf> {
    relative(path)
}

use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn archive(source: &Path) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_quiesced(source, &mut bytes).unwrap();
        bytes
    }

    fn set_guest(path: &Path, uid: u32, gid: u32, mode: u32) {
        let mut metadata = guest_metadata(path, &fs::symlink_metadata(path).unwrap()).unwrap();
        metadata.uid = uid;
        metadata.gid = gid;
        metadata.mode = (metadata.mode & TYPE_MASK) | mode;
        metadata.mtime = 1_700_000_000;
        metadata.mtime_ns = 123_456_789;
        apply_metadata(path, &metadata).unwrap();
    }

    #[test]
    fn volume_roundtrip_retains_guest_metadata_links_names_and_sparse_data() {
        let source = fixture();
        let parent = fixture();
        let root = source.path();
        let dir = root.join("data\nwith a newline");
        fs::create_dir(&dir).unwrap();
        // APFS refuses non-UTF-8 names at creation; Linux volumes can contain
        // them and must retain their bytes when moved to another Linux host.
        #[cfg(target_os = "linux")]
        let name = std::ffi::OsString::from_vec(b"nonutf8-\xff".to_vec());
        #[cfg(target_os = "macos")]
        let name = std::ffi::OsString::from("utf8-\u{e9}");
        let file = dir.join(name);
        fs::write(&file, b"state that must survive").unwrap();
        fs::hard_link(&file, dir.join("same-inode")).unwrap();
        std::os::unix::fs::symlink("/missing/guest/path", dir.join("link")).unwrap();
        let sparse_name = "s".repeat(160);
        let sparse = root.join(&sparse_name);
        let mut sparse_file = File::create(&sparse).unwrap();
        sparse_file.set_len(64 << 20).unwrap();
        sparse_file.seek(SeekFrom::Start(32 << 20)).unwrap();
        sparse_file.write_all(b"allocated").unwrap();
        drop(sparse_file);
        set_guest(&file, 42001, 42002, 0o6751);
        set_guest(&dir.join("link"), 54001, 54002, 0o777);
        set_guest(&dir, 42001, 42002, 0o1770);
        set_guest(root, 43001, 43002, 0o750);
        let original_mode = fs::metadata(&file).unwrap().mode();
        let bytes = archive(root);
        assert!(
            bytes.len() < 1 << 20,
            "sparse file expanded: {}",
            bytes.len()
        );
        let stage = read_staged(bytes.as_slice(), parent.path()).unwrap();
        for path in [
            Path::new(""),
            Path::new(&sparse_name),
            dir.strip_prefix(root).unwrap(),
            file.strip_prefix(root).unwrap(),
            dir.join("link").strip_prefix(root).unwrap(),
        ] {
            let before = root.join(path);
            let after = stage.path().join(path);
            assert_eq!(
                guest_metadata(&before, &fs::symlink_metadata(&before).unwrap()).unwrap(),
                guest_metadata(&after, &fs::symlink_metadata(&after).unwrap()).unwrap(),
                "{}",
                path.display()
            );
        }
        let copied = stage.path().join(file.strip_prefix(root).unwrap());
        assert_eq!(fs::read(&copied).unwrap(), b"state that must survive");
        assert_eq!(
            fs::metadata(&copied).unwrap().ino(),
            fs::metadata(copied.parent().unwrap().join("same-inode"))
                .unwrap()
                .ino()
        );
        assert_eq!(fs::metadata(&copied).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&file).unwrap().mode(), original_mode);
        let sparse_meta = fs::metadata(stage.path().join(&sparse_name)).unwrap();
        assert_eq!(sparse_meta.len(), 64 << 20);
        assert!(sparse_meta.blocks() * 512 < 1 << 20);
        let mut sparse_file = File::open(stage.path().join(&sparse_name)).unwrap();
        sparse_file.seek(SeekFrom::Start(32 << 20)).unwrap();
        let mut data = [0; 9];
        sparse_file.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"allocated");
        // Exporting the restored host representation produces the same guest metadata.
        let second = read_staged(archive(stage.path()).as_slice(), parent.path()).unwrap();
        assert_eq!(
            fs::read(second.path().join(file.strip_prefix(root).unwrap())).unwrap(),
            b"state that must survive"
        );
    }

    #[test]
    fn incomplete_volume_stream_never_publishes_partial_data() {
        let source = fixture();
        let parent = fixture();
        fs::write(source.path().join("data"), b"value").unwrap();
        let bytes = archive(source.path());
        let marker = bytes
            .windows(END.len())
            .position(|b| b == END.as_bytes())
            .unwrap();
        for len in [0, 512, marker, marker - 1] {
            assert!(read_staged(&bytes[..len], parent.path()).is_err());
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn unrepresented_attributes_and_sockets_are_refused() {
        let source = fixture();
        let file = source.path().join("file");
        fs::write(&file, b"data").unwrap();
        crate::extract::set_user_xattr(&file, "user.application", b"important").unwrap();
        assert_eq!(
            write_quiesced(source.path(), Vec::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        fs::remove_file(file).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(source.path().join("socket")).unwrap();
        assert_eq!(
            write_quiesced(source.path(), Vec::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    fn crafted(entries: &[(&str, tar::EntryType, Option<&str>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, target) in entries {
            let mode = if kind.is_dir() {
                DIRECTORY
            } else if kind.is_symlink() {
                SYMLINK
            } else {
                REGULAR
            };
            let metadata = GuestMetadata {
                uid: 0,
                gid: 0,
                mode: mode | 0o755,
                mtime: 0,
                mtime_ns: 0,
            };
            let encoded = serde_json::to_vec(&metadata).unwrap();
            builder
                .append_pax_extensions([(PAX, encoded.as_slice())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(0);
            header.set_mode(0o755);
            if let Some(target) = target {
                builder.append_link(&mut header, name, target).unwrap();
            } else {
                builder.append_data(&mut header, name, io::empty()).unwrap();
            }
        }
        let mut end = tar::Header::new_gnu();
        end.set_size(0);
        builder.append_data(&mut end, END, io::empty()).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn volume_import_refuses_link_traversal_duplicates_and_forward_hardlinks() {
        use tar::EntryType as T;
        let outside = fixture();
        fs::write(outside.path().join("sentinel"), b"unchanged").unwrap();
        let parent = fixture();
        for entries in [
            vec![
                ("data", T::Directory, None),
                ("data/link", T::Symlink, outside.path().to_str()),
                ("data/link/sentinel", T::Regular, None),
            ],
            vec![
                ("data", T::Directory, None),
                ("data/file", T::Regular, None),
                ("data/file", T::Regular, None),
            ],
            vec![
                ("data", T::Directory, None),
                ("data/file", T::Link, Some("data/absent")),
            ],
            vec![
                ("data", T::Directory, None),
                ("data/file", T::Link, Some("/etc/passwd")),
            ],
            vec![("data/file", T::Regular, None)],
        ] {
            assert!(read_staged(crafted(&entries).as_slice(), parent.path()).is_err());
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
            assert_eq!(
                fs::read(outside.path().join("sentinel")).unwrap(),
                b"unchanged"
            );
        }
        assert!(relative(Path::new("data/../escape")).is_err());
        assert!(relative(Path::new("/data/file")).is_err());
    }
}
