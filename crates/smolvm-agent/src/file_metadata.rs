//! Metadata is read in the same namespace as file bytes, including recorded
//! Linux permissions on host shares. The final symlink is described, not read.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use smolvm_protocol::{error_codes, AgentResponse, PathMetadata, WorkloadTarget};

pub(crate) fn read(path: &Path) -> std::io::Result<PathMetadata> {
    let metadata = path.symlink_metadata()?;
    let kind = if metadata.is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "dir"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    };
    let link_target = if metadata.is_symlink() {
        std::fs::read_link(path)?
            .into_os_string()
            .into_string()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "symlink target is not UTF-8",
                )
            })?
    } else {
        String::new()
    };
    Ok(PathMetadata {
        kind: kind.into(),
        size: metadata.len(),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec() as u32,
        resolved_link_target: if metadata.is_symlink() {
            resolve_link(path)?
        } else {
            String::new()
        },
        link_target,
    })
}

/// Resolve links using the helper's actual root. Keep a missing tail so `-L`
/// fails on a dangling link instead of silently copying the next link in a chain.
fn resolve_link(path: &Path) -> std::io::Result<String> {
    use std::collections::VecDeque;
    use std::path::{Component, PathBuf};
    let components = |path: &Path| {
        path.components()
            .map(|p| p.as_os_str().to_owned())
            .collect::<VecDeque<_>>()
    };
    let mut pending = components(path);
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        match Path::new(&part).components().next().unwrap() {
            Component::RootDir => {
                resolved = PathBuf::from("/");
                continue;
            }
            Component::ParentDir => {
                resolved.pop();
                continue;
            }
            Component::CurDir => continue,
            _ => {}
        }
        resolved.push(&part);
        match std::fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.is_symlink() => {
                links += 1;
                if links > 40 {
                    return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = std::fs::read_link(&resolved)?;
                resolved.pop();
                let mut next = components(&target);
                next.append(&mut pending);
                pending = next;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    resolved.into_os_string().into_string().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "resolved symlink target is not UTF-8",
        )
    })
}

pub(crate) fn response(path: &Path) -> AgentResponse {
    match read(path) {
        Ok(metadata) => AgentResponse::ok_with_data(serde_json::json!(metadata)),
        Err(error) => AgentResponse::error(
            format!("stat {}: {error}", path.display()),
            if error.kind() == std::io::ErrorKind::NotFound {
                error_codes::NOT_FOUND
            } else {
                error_codes::FILE_IO_FAILED
            },
        ),
    }
}

pub(crate) fn handle(path: &str, target: Option<&WorkloadTarget>) -> AgentResponse {
    let root = match crate::io_target::IoRoot::resolve(target) {
        Ok(root) => root,
        Err(error) => return error,
    };
    match root.namespace() {
        crate::nsfile::GuestNs::Container(namespace) => namespace.stat(path),
        crate::nsfile::GuestNs::Root(_) => {
            // A trailing slash or dot asks the kernel to resolve the directory.
            let access = if path.ends_with('/') || path.ends_with("/.") {
                crate::FilePathAccess::Read
            } else {
                crate::FilePathAccess::Metadata
            };
            match crate::resolve_guest_io_path(path, access, &root) {
                Ok(resolved) => response(&resolved),
                Err(error) => error,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn metadata_does_not_follow_the_final_link_or_escape_through_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("overlay");
        std::fs::create_dir(&root).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"outside").unwrap();
        symlink(&outside, root.join("link")).unwrap();
        let resolve = |path| {
            crate::resolve_guest_io_path_with_roots(
                path,
                crate::FilePathAccess::Metadata,
                Some(&root),
                &root,
            )
        };
        assert_eq!(read(&resolve("/link").unwrap()).unwrap().kind, "symlink");
        assert!(resolve("/link/secret").is_err());
        assert!(resolve("/missing/file").is_err());
        assert!(!root.join("missing").exists());
        assert!(resolve("/../outside/secret").is_err());
        assert_eq!(read(&resolve("/").unwrap()).unwrap().kind, "dir");
    }

    #[test]
    fn metadata_preserves_permissions_times_and_dangling_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("café 雪\nscript");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
        let time = std::time::UNIX_EPOCH + std::time::Duration::new(1_600_000_000, 123_456_789);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(time))
            .unwrap();
        let actual = read(&path).unwrap();
        assert_eq!(actual.kind, "file");
        assert_eq!(actual.mode, 0o751);
        assert_eq!(actual.modified_secs, 1_600_000_000);
        assert_eq!(actual.modified_nanos, 123_456_789);
        assert_eq!(actual.size, 10);
        assert_eq!(actual.uid, path.metadata().unwrap().uid());
        let link = dir.path().join("link");
        symlink("missing 雪\nfile", &link).unwrap();
        let actual = read(&link).unwrap();
        assert_eq!(actual.kind, "symlink");
        assert_eq!(actual.link_target, "missing 雪\nfile");
        let chain = dir.path().join("chain");
        symlink("link", &chain).unwrap();
        assert_eq!(
            read(&chain).unwrap().resolved_link_target,
            dir.path().join("missing 雪\nfile").to_str().unwrap()
        );
        std::fs::remove_file(&link).unwrap();
        symlink(path.file_name().unwrap(), &link).unwrap();
        assert_eq!(
            read(&chain).unwrap().resolved_link_target,
            path.to_str().unwrap()
        );
        let loop_path = dir.path().join("loop");
        symlink("loop", &loop_path).unwrap();
        assert_eq!(
            read(&loop_path).unwrap_err().raw_os_error(),
            Some(libc::ELOOP)
        );
        assert!(
            matches!(response(&dir.path().join("absent")), AgentResponse::Error { code, .. } if code.as_deref() == Some(error_codes::NOT_FOUND))
        );
    }
}
