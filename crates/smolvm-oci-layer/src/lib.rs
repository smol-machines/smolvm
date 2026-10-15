//! Pure-Rust extraction of a single OCI image layer into an overlayfs lowerdir.
//!
//! This crate owns exactly one slice of image assembly — *extracting one layer* —
//! and nothing about the container runtime. It decompresses a layer blob (gzip,
//! zstd, or plain), untars it into a destination directory, and translates OCI
//! whiteout markers (`.wh.<name>`, `.wh..wh..opq`) into the overlayfs on-disk
//! representation (a `mknod c 0 0` whiteout / a `trusted.overlay.opaque` xattr) —
//! the same conversion containerd / docker-overlay2 / containers-storage perform.
//!
//! What this crate deliberately does **not** do: it never *merges* layers,
//! *mounts* anything, or *executes* a process. Merging is the kernel's overlayfs;
//! mounting and execution are `crun`. Extracting a layer here is byte-level data
//! handling — `gunzip | tar -x` with a marker rename — not runtime.
//!
//! It is the single implementation shared by the host image cache (which fills
//! the cache once, at pull time) and the guest agent (which extracts on its own
//! in-VM pull path). Because a musl guest can't link the C-backed `zstd` crate,
//! decompression stays pure-Rust (gzip via `flate2`/miniz_oxide, zstd via
//! `ruzstd`), so both callers share this one copy.

use std::io::Read;
use std::path::{Path, PathBuf};

use tracing::warn;

/// OCI/AUFS whiteout marker that deletes a single name from lower layers
/// (`.wh.<name>`).
const WHITEOUT_PREFIX: &str = ".wh.";
/// OCI/AUFS opaque-directory marker: the directory replaces, rather than merges
/// with, the same directory in lower layers (`.wh..wh..opq`).
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// What an OCI layer tar entry means once its name is interpreted.
#[derive(Debug, PartialEq, Eq)]
pub enum LayerEntry<'a> {
    /// `.wh..wh..opq`: mark the parent directory opaque.
    OpaqueDir,
    /// `.wh.<name>`: delete `<name>` from lower layers (carries `<name>`).
    Whiteout(&'a str),
    /// An ordinary entry to extract as-is.
    Normal,
}

/// Classify an entry by its file name. The opaque marker must be checked before
/// the generic `.wh.` prefix, since `.wh..wh..opq` also starts with `.wh.`.
pub fn classify_layer_entry(file_name: &str) -> LayerEntry<'_> {
    if file_name == OPAQUE_WHITEOUT {
        return LayerEntry::OpaqueDir;
    }
    match file_name.strip_prefix(WHITEOUT_PREFIX) {
        Some(name) if !name.is_empty() => LayerEntry::Whiteout(name),
        _ => LayerEntry::Normal,
    }
}

/// Join `rel` under `base`, returning `None` if any component would escape the
/// base — lexically (`..`, an absolute path, a Windows-style prefix) **or**
/// through a symlink already on disk.
///
/// The symlink check is the load-bearing half. This path feeds the whiteout
/// branch, which performs *destructive* operations (`remove_file`,
/// `remove_dir_all`, `mknod`, `setxattr`) as root on the host when filling the
/// image cache. A purely lexical guard would let a hostile layer ship
/// `evil -> /` followed by `evil/etc/.wh.passwd` and delete host paths outside
/// the layer dir: `..` never appears, so the lexical check passes, and the
/// destructive call lands wherever the symlink points. Refusing to *traverse*
/// any symlinked component closes that, and matches what `tar::Entry::unpack_in`
/// already enforces for ordinary entries.
///
/// Each component is checked as the path is built, so a symlink planted earlier
/// in the very same layer is caught before anything is written through it.
pub fn jailed_join(base: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                out.push(part);
                // symlink_metadata does NOT follow the final component, so this
                // sees the link itself rather than its target.
                if let Ok(md) = std::fs::symlink_metadata(&out) {
                    if md.file_type().is_symlink() {
                        return None;
                    }
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Create an overlayfs whiteout (a `mknod` character device with device number
/// 0/0) at `path`, replacing any existing entry. This is how the kernel's
/// overlayfs records "this name is deleted from lower layers" — the on-disk
/// representation that OCI's `.wh.<name>` marker must be translated into.
///
/// Linux-only: overlayfs whiteouts are a Linux concept. The non-Linux stub keeps
/// the crate compiling on the macOS/Windows host build (where `mknod`/`makedev`
/// signatures differ); the host cache-fill runs on the Linux node.
#[cfg(target_os = "linux")]
pub fn create_overlay_whiteout(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    // Clear any entry the layer may already have written at this name so mknod
    // doesn't fail with EEXIST.
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(path);
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid NUL-terminated path; mode and dev are scalars.
    let rc = unsafe {
        libc::mknod(
            c_path.as_ptr(),
            libc::S_IFCHR as libc::mode_t,
            libc::makedev(0, 0),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn create_overlay_whiteout(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "overlayfs whiteouts are only created on Linux",
    ))
}

/// Mark `dir` opaque for overlayfs via the `trusted.overlay.opaque` xattr — the
/// representation of OCI's `.wh..wh..opq` marker. Linux-only (see
/// [`create_overlay_whiteout`]).
#[cfg(target_os = "linux")]
pub fn set_overlay_opaque(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let name = std::ffi::CString::new("trusted.overlay.opaque").expect("static xattr name");
    let value = b"y";
    // SAFETY: path/name are NUL-terminated; value/len describe a valid buffer.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_overlay_opaque(_dir: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "overlayfs opaque dirs are only set on Linux",
    ))
}

/// Wrap `inner` in a transparent decompressor selected by peeking the leading
/// magic bytes — gzip (`1f 8b`) or zstd (`28 b5 2f fd`), else pass-through. Magic
/// sniffing is correct regardless of the manifest `mediaType` (which images
/// sometimes mislabel).
pub fn decompress_layer_reader<'a>(
    mut inner: impl Read + 'a,
) -> std::io::Result<Box<dyn Read + 'a>> {
    // Peek the compression magic without consuming it: read up to 4 bytes, then
    // chain them back in front of the rest of the stream.
    let mut magic = [0u8; 4];
    let mut n = 0;
    while n < magic.len() {
        match inner.read(&mut magic[n..])? {
            0 => break,
            k => n += k,
        }
    }
    let stream = std::io::Cursor::new(magic[..n].to_vec()).chain(inner);
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        // MultiGzDecoder, not GzDecoder: gzip streams may carry several members
        // concatenated (pigz and some registry re-compressors emit them), and the
        // single-member decoder stops at the first boundary — silently truncating
        // the layer so tar then fails mid-entry.
        Ok(Box::new(flate2::read::MultiGzDecoder::new(stream)))
    } else if n >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        // Pure-Rust zstd decoder — the C `zstd` crate can't link against musl.
        let dec = ruzstd::decoding::StreamingDecoder::new(stream)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Box::new(dec))
    } else {
        // Uncompressed tar (or unrecognized) — pass through untouched.
        Ok(Box::new(stream))
    }
}

/// The `.smolmachine` sidecar members that identify a smolmachine pack blob
/// masquerading as an OCI layer: `agent-rootfs.tar` is the archive's first entry
/// (so the guard fires before anything large is written) and `storage.ext4` is
/// the multi-GiB disk template that would fill the disk. Only TOP-LEVEL entries
/// match — a real container image nesting a same-named file (e.g.
/// `/var/lib/foo/storage.ext4`) must not trip the guard.
fn pack_sidecar_sentinel(path: &Path) -> Option<&'static str> {
    const SENTINELS: [&str; 2] = ["agent-rootfs.tar", "storage.ext4"];
    let mut components = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir));
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(name)), None) => {
            SENTINELS.into_iter().find(|s| name.to_str() == Some(s))
        }
        _ => None,
    }
}

/// Extract one OCI layer blob into `dest`, applying OCI whiteout semantics so the
/// directory is a correct overlayfs lowerdir.
///
/// Each layer is extracted in isolation into its own directory (later stacked as
/// an overlayfs lowerdir). A plain `tar -x` does not give the kernel's overlayfs
/// what it needs, so this translates at unpack time:
/// - `.wh.<name>` (delete marker) → an overlayfs whiteout (`mknod c 0 0`), so the
///   stacked overlay hides `<name>` from lower layers.
/// - `.wh..wh..opq` (opaque marker) → the `trusted.overlay.opaque` xattr on the
///   parent dir.
///
/// `reader` yields the raw layer blob (gzip/zstd/plain — decompressed here). The
/// whiteout translation only takes effect on Linux; on other hosts the markers
/// would surface as `Unsupported` errors, so this is called on the Linux node.
pub fn extract_oci_layer<R: Read>(reader: R, dest: &Path) -> std::io::Result<()> {
    extract_oci_layer_with_size(reader, dest).map(|_| ())
}

/// Extract one OCI layer and return the logical bytes carried by regular file
/// entries. Computing this while tar headers are already in hand avoids a full
/// post-extraction directory walk, which is especially costly inside a VM for
/// package-heavy images containing hundreds of thousands of files.
pub fn extract_oci_layer_with_size<R: Read>(reader: R, dest: &Path) -> std::io::Result<u64> {
    #[cfg(unix)]
    use std::collections::{HashMap, HashSet};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    // Layers arrive gzip- or zstd-compressed (or, rarely, plain). Decompress
    // transparently so a zstd layer no longer breaks extraction.
    let reader = decompress_layer_reader(reader)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    // Preserve the archive's uid/gid. The caller runs as root (CAP_CHOWN) so this
    // chowns each entry to the image's intended owner; without it every file is
    // owned by root, breaking images that ship non-root-owned paths.
    archive.set_preserve_ownerships(true);
    archive.set_overwrite(true);

    // A layer can declare a read-only directory before its children. Relax each
    // such parent at most once, then restore its declared mode after extraction.
    // The old path chmodded the parent for every tar entry, which turned images
    // with large package trees into hundreds of thousands of redundant metadata
    // writes and also left restrictive directory modes changed to 0755.
    #[cfg(unix)]
    let mut checked_parents = HashSet::<PathBuf>::new();
    #[cfg(unix)]
    let mut relaxed_parents = HashMap::<PathBuf, u32>::new();
    let mut logical_bytes = 0u64;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let entry_type = entry.header().entry_type();

        // A smolmachine PACK blob is not an OCI filesystem layer: it is a
        // .smolmachine sidecar carrying agent-rootfs.tar and a multi-GiB non-sparse
        // storage.ext4 disk template. Unpacking it here fills the disk before
        // failing, so detect its top-level sentinels and abort immediately.
        if let Some(sentinel) = pack_sidecar_sentinel(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "layer is a smolmachine pack (contains '{sentinel}') — pull it on the \
                     host via the smolmachine flow, not as a container image"
                ),
            ));
        }

        // Jail the on-disk path under the layer dir (defends against `..` and
        // absolute paths embedded in the archive).
        let Some(full_path) = jailed_join(dest, &path) else {
            warn!(path = %path.display(), "skipping layer entry that escapes the layer dir");
            continue;
        };

        // Whiteout markers are interpreted by name, before normal extraction.
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            match classify_layer_entry(file_name) {
                LayerEntry::OpaqueDir => {
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent)?;
                        set_overlay_opaque(parent)?;
                    }
                    continue;
                }
                LayerEntry::Whiteout(removed) => {
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent)?;
                        create_overlay_whiteout(&parent.join(removed))?;
                    }
                    continue;
                }
                LayerEntry::Normal => {}
            }
        }

        // A hardlink whose target wasn't extracted into this layer can't be
        // created here; skip it (overlayfs resolves the lower-layer file).
        if entry.header().entry_type() == tar::EntryType::Link {
            let target = entry.link_name()?.and_then(|link| jailed_join(dest, &link));
            if target.is_none_or(|t| !t.exists()) {
                continue;
            }
        }

        // Ensure the parent is writable before extracting children — OCI layers
        // can set restrictive directory modes before their contents. Unix-only:
        // real cache-fills run on the Linux node; the crate just needs to compile
        // on the macOS/Windows host builds of the main engine.
        #[cfg(unix)]
        if let Some(parent) = full_path.parent() {
            let parent = parent.to_path_buf();
            if checked_parents.insert(parent.clone()) {
                if let Ok(metadata) = std::fs::symlink_metadata(&parent) {
                    if metadata.is_dir() {
                        let mode = metadata.permissions().mode();
                        if mode & 0o300 != 0o300 {
                            std::fs::set_permissions(
                                &parent,
                                std::fs::Permissions::from_mode(mode | 0o700),
                            )?;
                            relaxed_parents.insert(parent, mode);
                        }
                    }
                }
            }
        }

        let entry_size = entry.header().size().unwrap_or(0);
        if let Err(e) = entry.unpack_in(dest) {
            // Regular files and directories failing is a real error; non-regular
            // entries (symlinks, device nodes, fifos) can fail benignly — skip.
            match entry.header().entry_type() {
                tar::EntryType::Regular
                | tar::EntryType::GNUSparse
                | tar::EntryType::Continuous
                | tar::EntryType::Directory => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to unpack '{}': {}", path.display(), e),
                    ));
                }
                _ => {
                    warn!(path = %path.display(), error = %e, "skipping non-regular layer entry");
                }
            }
        } else if matches!(
            entry_type,
            tar::EntryType::Regular | tar::EntryType::GNUSparse | tar::EntryType::Continuous
        ) {
            logical_bytes = logical_bytes.saturating_add(entry_size);
        }

        // A repeated directory entry may reset its own mode. Forget any earlier
        // relaxation so later children re-check the newly declared permissions.
        #[cfg(unix)]
        if entry_type == tar::EntryType::Directory {
            checked_parents.remove(&full_path);
            relaxed_parents.remove(&full_path);
        }
    }

    #[cfg(unix)]
    {
        let mut relaxed: Vec<_> = relaxed_parents.into_iter().collect();
        relaxed.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, mode) in relaxed {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(logical_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognizes_markers_and_normals() {
        assert_eq!(classify_layer_entry(".wh..wh..opq"), LayerEntry::OpaqueDir);
        assert_eq!(
            classify_layer_entry(".wh.RPM-GPG-KEY-kojiv2"),
            LayerEntry::Whiteout("RPM-GPG-KEY-kojiv2")
        );
        // A bare ".wh." carries no name → treat as a normal file, not a whiteout.
        assert_eq!(classify_layer_entry(".wh."), LayerEntry::Normal);
        assert_eq!(classify_layer_entry("CERN.repo"), LayerEntry::Normal);
        assert_eq!(classify_layer_entry(".wherever"), LayerEntry::Normal);
    }

    #[test]
    fn jailed_join_blocks_lexical_escapes() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert_eq!(
            jailed_join(base, Path::new("etc/hosts")),
            Some(base.join("etc/hosts"))
        );
        assert_eq!(jailed_join(base, Path::new("../escape")), None);
        assert_eq!(jailed_join(base, Path::new("/abs")), None);
    }

    /// A hostile layer must not be able to reach outside the layer dir through a
    /// symlink it planted itself. This is the guard protecting the whiteout
    /// branch's destructive ops (`remove_dir_all`/`mknod`) when the host fills
    /// the image cache as root — a lexical-only check would pass `evil/etc/passwd`
    /// straight through to the symlink target.
    #[cfg(unix)]
    #[test]
    fn jailed_join_refuses_to_traverse_a_planted_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tmp.path().join("layer");
        let victim = tmp.path().join("victim");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("precious"), b"do not delete").unwrap();

        // The layer ships `evil -> <victim>` (tar-rs creates symlinks with
        // unrestricted targets), then an entry underneath it.
        std::os::unix::fs::symlink(&victim, layer.join("evil")).unwrap();

        assert_eq!(
            jailed_join(&layer, Path::new("evil/precious")),
            None,
            "must refuse to resolve THROUGH a symlinked component"
        );
        assert_eq!(
            jailed_join(&layer, Path::new("evil")),
            None,
            "the symlink itself is not a safe destination either"
        );
        // A sibling that never crosses the symlink still resolves.
        assert_eq!(
            jailed_join(&layer, Path::new("safe/file")),
            Some(layer.join("safe/file"))
        );
        assert!(victim.join("precious").exists(), "victim untouched");
    }

    /// The layer-specific piece is the magic-sniffing decompressor: confirm gzip,
    /// zstd, and plain tar blobs all round-trip to the identical tar stream (so a
    /// mislabeled or differently-compressed layer extracts the same). Runs
    /// portably — no filesystem ownership/whiteout ops, which require root+Linux
    /// and are covered by the guest's existing tests and the arch-box e2e.
    #[test]
    fn decompress_round_trips_gzip_zstd_and_plain() {
        use std::io::Write;
        // A minimal tar holding one file "hello" = "world".
        let tar_bytes = {
            let mut b = tar::Builder::new(Vec::new());
            let data = b"world";
            let mut h = tar::Header::new_gnu();
            h.set_path("hello").unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append(&h, &data[..]).unwrap();
            b.into_inner().unwrap()
        };

        let gzip = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&tar_bytes).unwrap();
            e.finish().unwrap()
        };
        let zstd = zstd::stream::encode_all(&tar_bytes[..], 1).unwrap();

        // Two gzip members concatenated — what pigz/some registries emit. The
        // single-member decoder would stop after the first and truncate the layer.
        let gzip_multi = {
            let mid = tar_bytes.len() / 2;
            let mut out = Vec::new();
            for part in [&tar_bytes[..mid], &tar_bytes[mid..]] {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(part).unwrap();
                out.extend_from_slice(&e.finish().unwrap());
            }
            out
        };

        for (label, blob) in [
            ("plain", tar_bytes.clone()),
            ("gzip", gzip),
            ("gzip-multimember", gzip_multi),
            ("zstd", zstd),
        ] {
            let mut out = Vec::new();
            decompress_layer_reader(&blob[..])
                .unwrap_or_else(|e| panic!("{label} decompress init failed: {e}"))
                .read_to_end(&mut out)
                .unwrap_or_else(|e| panic!("{label} read failed: {e}"));
            assert_eq!(
                out, tar_bytes,
                "{label} did not round-trip to the tar stream"
            );
            // And the round-tripped stream is a valid tar carrying our one entry.
            let mut ar = tar::Archive::new(&out[..]);
            let names: Vec<_> = ar
                .entries()
                .unwrap()
                .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec!["hello".to_string()], "{label} entry list");
        }
    }

    #[cfg(unix)]
    #[test]
    fn extraction_restores_restrictive_directory_modes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(tmp.path()).unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_size(0);
        directory.set_mode(0o555);
        directory.set_uid(owner.uid() as u64);
        directory.set_gid(owner.gid() as u64);
        directory.set_cksum();
        builder
            .append_data(&mut directory, "readonly", std::io::empty())
            .unwrap();

        let payload = b"still extracted";
        let mut file = tar::Header::new_gnu();
        file.set_size(payload.len() as u64);
        file.set_mode(0o644);
        file.set_uid(owner.uid() as u64);
        file.set_gid(owner.gid() as u64);
        file.set_cksum();
        builder
            .append_data(&mut file, "readonly/file", &payload[..])
            .unwrap();

        let layer = builder.into_inner().unwrap();
        let destination = tmp.path().join("layer");
        std::fs::create_dir(&destination).unwrap();
        extract_oci_layer(&layer[..], &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("readonly/file")).unwrap(),
            payload
        );
        assert_eq!(
            std::fs::metadata(destination.join("readonly"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
    }

    #[cfg(unix)]
    #[test]
    fn extraction_reports_regular_file_bytes_without_a_directory_walk() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(tmp.path()).unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for (path, payload) in [("one", &b"123"[..]), ("nested/two", &b"45678"[..])] {
            let mut file = tar::Header::new_gnu();
            file.set_size(payload.len() as u64);
            file.set_mode(0o644);
            file.set_uid(owner.uid() as u64);
            file.set_gid(owner.gid() as u64);
            file.set_cksum();
            builder.append_data(&mut file, path, payload).unwrap();
        }

        let destination = tmp.path().join("layer");
        std::fs::create_dir(&destination).unwrap();
        let bytes =
            extract_oci_layer_with_size(&builder.into_inner().unwrap()[..], &destination).unwrap();

        assert_eq!(bytes, 8);
        assert_eq!(
            std::fs::read(destination.join("nested/two")).unwrap(),
            b"45678"
        );
    }
}
