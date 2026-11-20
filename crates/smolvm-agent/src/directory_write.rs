//! Bounded directory uploads staged per connection, then merged in the selected
//! workload filesystem. Dropping an unfinished upload removes its archive.
use crate::{io_target::IoRoot, nsfile::GuestNs};
use smolvm_protocol::{error_codes, AgentResponse, WorkloadTarget, FILE_TRANSFER_MAX_TOTAL};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, RawFd},
        unix::fs::PermissionsExt,
    },
    path::{Component, Path},
};

pub(crate) struct Session {
    archive: tempfile::NamedTempFile,
    root: IoRoot,
    destination: String,
    received: u64,
}

impl Session {
    pub(crate) fn begin(
        destination: &str,
        target: Option<&WorkloadTarget>,
    ) -> Result<Self, AgentResponse> {
        let destination = crate::normalize_guest_path(destination)?;
        let root = IoRoot::resolve(target)?;
        let archive = tempfile::Builder::new()
            .prefix(".smol-directory-upload-")
            .tempfile_in(crate::storage::archive_scratch_dir())
            .map_err(|e| AgentResponse::error(e.to_string(), error_codes::FILE_IO_FAILED))?;
        Ok(Self {
            archive,
            root,
            destination,
            received: 0,
        })
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.received = self
            .received
            .checked_add(data.len() as u64)
            .filter(|size| *size <= FILE_TRANSFER_MAX_TOTAL)
            .ok_or("Folder uploads support up to 4 GiB including archive overhead.")?;
        self.archive.write_all(data).map_err(|e| e.to_string())
    }

    pub(crate) fn finish(mut self, client: Option<RawFd>) -> Result<(), String> {
        self.archive.flush().map_err(|e| e.to_string())?;
        let file = self.archive.reopen().map_err(|e| e.to_string())?;
        let owner = crate::workload_owner(&self.root);
        match self.root.namespace() {
            GuestNs::Container(namespace) => {
                namespace.unpack_directory(file, &self.destination, client, owner)
            }
            GuestNs::Root(_) => {
                let destination = crate::resolve_guest_io_path(
                    &self.destination,
                    crate::FilePathAccess::Write,
                    &self.root,
                )
                .map_err(|response| match response {
                    AgentResponse::Error { message, .. } => message,
                    _ => "Cannot resolve the folder destination.".into(),
                })?;
                unpack_owned(file, &destination, client, owner).map_err(|e| e.to_string())
            }
        }
    }
}

struct CheckedFile {
    file: File,
    client: Option<RawFd>,
}
impl CheckedFile {
    fn check(&self) -> io::Result<()> {
        if self.client.is_some_and(crate::process::is_peer_closed) {
            Err(io::Error::other("Folder upload cancelled."))
        } else {
            Ok(())
        }
    }
}
impl Read for CheckedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.file.read(bytes)
    }
}
impl Seek for CheckedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check()?;
        self.file.seek(position)
    }
}

fn relative(path: &Path) -> bool {
    path.components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
fn unpack(file: File, destination: &Path, client: Option<RawFd>) -> io::Result<()> {
    unpack_owned(file, destination, client, (None, None))
}

fn unpack_owned(
    file: File,
    destination: &Path,
    client: Option<RawFd>,
    owner: (Option<u32>, Option<u32>),
) -> io::Result<()> {
    let length = file.metadata()?.len();
    if !(1024..=FILE_TRANSFER_MAX_TOTAL).contains(&length) || length % 512 != 0 {
        return Err(io::Error::other("Invalid or oversized folder archive."));
    }
    let mut archive = tar::Archive::new(CheckedFile { file, client });
    let mut bytes = 0u64;
    // Inspect headers before touching the destination, including sparse expansion.
    for (index, entry) in archive.entries_with_seek()?.enumerate() {
        let entry = entry?;
        let kind = entry.header().entry_type();
        if index >= 100_000
            || !relative(&entry.path()?)
            || !(kind.is_file()
                || kind.is_dir()
                || kind.is_symlink()
                || kind.is_hard_link()
                || kind.is_gnu_sparse())
            || (kind.is_hard_link() && !entry.link_name()?.is_some_and(|path| relative(&path)))
        {
            return Err(io::Error::other("Unsupported entry in folder archive."));
        }
        bytes = bytes
            .checked_add(entry.size())
            .filter(|size| *size <= FILE_TRANSFER_MAX_TOTAL)
            .ok_or_else(|| io::Error::other("Folder contents exceed 4 GiB."))?;
        let stored = if kind.is_gnu_sparse() {
            entry.header().entry_size()?
        } else {
            entry.size()
        };
        if entry
            .raw_file_position()
            .checked_add(stored)
            .is_none_or(|end| end > length)
        {
            return Err(io::Error::other("Truncated folder archive."));
        }
    }
    let mut reader = archive.into_inner();
    reader.seek(SeekFrom::Start(0))?;
    // Create only the chosen folder, never missing parents or a source-name child.
    match std::fs::create_dir(destination) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && destination.is_dir() => {}
        Err(e) => return Err(e),
    }
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    // Host numeric IDs have no meaning in the guest. Match single-file uploads:
    // non-root workloads own their uploads; other writes use the agent's user.
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    let mut directories = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_dir() {
            directories.push(entry);
        } else {
            unpack_entry(&mut entry, destination, owner, client)?;
        }
    }
    // Apply directory permissions after children, deepest paths first, like
    // tar::Archive::unpack, so read-only source folders can still be copied.
    directories.sort_by(|a, b| b.path_bytes().cmp(&a.path_bytes()));
    for mut entry in directories {
        unpack_entry(&mut entry, destination, owner, client)?;
    }
    Ok(())
}

fn unpack_entry(
    entry: &mut tar::Entry<'_, CheckedFile>,
    destination: &Path,
    owner: (Option<u32>, Option<u32>),
    client: Option<RawFd>,
) -> io::Result<()> {
    if client.is_some_and(crate::process::is_peer_closed) {
        return Err(io::Error::other("Folder upload cancelled."));
    }
    if !entry.unpack_in(destination)? {
        return Err(io::Error::other("Folder entry escaped the destination."));
    }
    if owner != (None, None) {
        let path = destination.join(entry.path()?);
        std::os::unix::fs::lchown(&path, owner.0, owner.1)?;
        if !entry.header().entry_type().is_symlink() {
            // chown can clear set-ID bits; apply the archived mode afterward.
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(entry.header().mode()?),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn helper(destination: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| e.to_string())?;
    unpack_owned(File::from(input), Path::new(destination), None, (uid, gid))
        .map_err(|e| e.to_string())?;
    println!("OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn merge_preserves_tree_and_retry_uses_the_exact_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir_all(source.join("empty")).unwrap();
        let name = "café 雪\nfile";
        std::fs::write(source.join(name), b"contents").unwrap();
        std::fs::set_permissions(source.join(name), std::fs::Permissions::from_mode(0o751))
            .unwrap();
        symlink(name, source.join("link")).unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        {
            let mut tar = tar::Builder::new(&mut archive);
            tar.follow_symlinks(false);
            tar.append_dir_all(".", &source).unwrap();
            tar.finish().unwrap();
        }
        let destination = root.path().join("chosen");
        for _ in 0..2 {
            archive.rewind().unwrap();
            unpack(archive.try_clone().unwrap(), &destination, None).unwrap();
            assert_eq!(std::fs::read(destination.join(name)).unwrap(), b"contents");
            assert_eq!(
                std::fs::read_link(destination.join("link")).unwrap(),
                Path::new(name)
            );
            assert_eq!(
                destination
                    .join(name)
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
            assert!(destination.join("empty").is_dir());
            assert!(!destination.join("source").exists());
        }
        archive.rewind().unwrap();
        assert!(unpack(archive, &root.path().join("missing/parent"), None).is_err());
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn invalid_archive_does_not_create_the_destination() {
        let root = tempfile::tempdir().unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.as_mut_bytes()[..9].copy_from_slice(b"../escape");
        header.set_cksum();
        archive.write_all(header.as_bytes()).unwrap();
        archive.write_all(&[0; 1024]).unwrap();
        archive.rewind().unwrap();
        let destination = root.path().join("chosen");
        assert!(unpack(archive, &destination, None).is_err());
        assert!(!destination.exists());
        assert!(!root.path().join("escape").exists());
    }

    #[test]
    fn oversized_and_truncated_payloads_do_not_touch_the_destination() {
        for size in [FILE_TRANSFER_MAX_TOTAL + 1, 4096] {
            let root = tempfile::tempdir().unwrap();
            let mut archive = tempfile::tempfile().unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_path("file").unwrap();
            header.set_size(size);
            header.set_mode(0o644);
            header.set_cksum();
            archive.write_all(header.as_bytes()).unwrap();
            archive.write_all(&[0; 1024]).unwrap();
            archive.rewind().unwrap();
            let destination = root.path().join("chosen");
            assert!(unpack(archive, &destination, None).is_err());
            assert!(!destination.exists());
        }
    }

    #[test]
    fn upload_uses_guest_ownership_instead_of_host_numeric_ids() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let uid = root.path().metadata().unwrap().uid();
        let gid = root.path().metadata().unwrap().gid();
        for owner in [(None, None), (Some(uid), Some(gid))] {
            let mut archive = tempfile::tempfile().unwrap();
            {
                let mut builder = tar::Builder::new(&mut archive);
                let mut header = tar::Header::new_gnu();
                header.set_size(4);
                header.set_uid(54321);
                header.set_gid(12345);
                header.set_mode(0o700);
                builder
                    .append_data(&mut header, "private", &b"data"[..])
                    .unwrap();
                builder.finish().unwrap();
            }
            archive.rewind().unwrap();
            let destination = root.path().join(format!("chosen-{}", owner.0.is_some()));
            unpack_owned(archive, &destination, None, owner).unwrap();
            let file = destination.join("private");
            let metadata = file.metadata().unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert_eq!(std::fs::read(file).unwrap(), b"data");
        }
    }

    #[test]
    fn existing_symlink_cannot_redirect_writes_outside_the_chosen_folder() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        let destination = root.path().join("chosen");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(outside.join("file"), b"keep").unwrap();
        symlink(&outside, destination.join("link")).unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, "link/file", &b"new!"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        archive.rewind().unwrap();
        assert!(unpack(archive, &destination, None).is_err());
        assert_eq!(std::fs::read(outside.join("file")).unwrap(), b"keep");
    }

    #[test]
    fn dropped_upload_removes_staging_without_touching_destination() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("chosen");
        let mut session =
            Session::begin(destination.to_str().unwrap(), Some(&WorkloadTarget::Vm)).unwrap();
        let staging = session.archive.path().to_path_buf();
        session.write(b"partial archive").unwrap();
        assert!(staging.exists());
        drop(session);
        assert!(!staging.exists());
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disconnected_client_cancels_before_destination_creation() {
        use std::os::{fd::AsRawFd, unix::net::UnixStream};
        let root = tempfile::tempdir().unwrap();
        let (stream, peer) = UnixStream::pair().unwrap();
        let mut archive = tempfile::tempfile().unwrap();
        archive.write_all(&[0; 1024]).unwrap();
        archive.rewind().unwrap();
        drop(peer);
        let destination = root.path().join("chosen");
        let error = unpack(archive, &destination, Some(stream.as_raw_fd())).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(!destination.exists());
    }
}
