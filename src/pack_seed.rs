//! Prepare reusable, guest-extracted storage disks for macOS pack imports.

use std::path::Path;

/// Seed a new machine's storage from a container pack, returning its disk size.
pub fn try_seed(
    name: &str,
    sidecar: &Path,
    storage_gib: Option<u64>,
) -> crate::Result<Option<u64>> {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("SMOLVM_PACK_STORAGE_SEEDS").as_deref() == Ok("off") {
            return Ok(None);
        }
        imp::seed(name, sidecar, storage_gib)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (name, sidecar, storage_gib);
        Ok(None)
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, BufReader, Read, Seek, SeekFrom};
    #[cfg(target_os = "macos")]
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, PermissionsExt},
    };
    use std::path::Path;
    #[cfg(target_os = "macos")]
    use std::{path::PathBuf, time::Duration};

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use smolvm_pack::format::PackManifest;
    #[cfg(target_os = "macos")]
    use smolvm_pack::format::PackMode;
    use smolvm_protocol::normalize_image_ref;

    #[cfg(target_os = "macos")]
    use crate::agent::{AgentManager, LaunchFeatures, VmResources};
    use crate::{Error, Result};

    const FORMAT: u32 = 2;
    const GIB: u64 = 1024 * 1024 * 1024;

    #[derive(Serialize, Deserialize)]
    struct Seed {
        format: u32,
        artifact: String,
        storage_gib: u64,
    }

    fn fail(error: impl std::fmt::Display) -> Error {
        Error::agent("prepare packed image storage", error.to_string())
    }

    fn layer_ids(manifest: &PackManifest) -> Result<Vec<String>> {
        let mut seen = BTreeSet::new();
        manifest
            .assets
            .layers
            .iter()
            .map(|layer| {
                let id = layer
                    .path
                    .strip_prefix("layers/")
                    .and_then(|path| path.strip_suffix(".tar"))
                    .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .ok_or_else(|| fail("invalid packed layer path"))?;
                if !seen.insert(id.to_string()) {
                    return Err(fail("duplicate packed layer"));
                }
                Ok(id.to_string())
            })
            .collect()
    }

    fn read_manifest(file: &mut File) -> Result<PackManifest> {
        let footer = smolvm_pack::packer::read_footer_from_file(file).map_err(fail)?;
        file.seek(SeekFrom::Start(footer.manifest_offset))
            .map_err(fail)?;
        let mut bytes = vec![0; footer.manifest_size as usize];
        file.read_exact(&mut bytes).map_err(fail)?;
        PackManifest::from_json(&bytes).map_err(fail)
    }

    #[cfg(target_os = "macos")]
    fn extract_layers(file: &mut File, output: &Path, manifest: &PackManifest) -> Result<()> {
        let footer = smolvm_pack::packer::read_footer_from_file(file).map_err(fail)?;
        file.seek(SeekFrom::Start(0)).map_err(fail)?;
        let compressed = file.take(footer.assets_size);
        let decoder = zstd::stream::Decoder::new(compressed).map_err(fail)?;
        extract_layer_archive(decoder, output, manifest)
    }

    fn extraction_limit(variable: &str, default: u64) -> u64 {
        std::env::var(variable)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    fn extract_layer_archive(
        reader: impl Read,
        output: &Path,
        manifest: &PackManifest,
    ) -> Result<()> {
        let ids = layer_ids(manifest)?;
        let mut pending: BTreeMap<_, _> = manifest
            .assets
            .layers
            .iter()
            .zip(&ids)
            .map(|(layer, id)| (layer.path.clone(), (id, layer.size)))
            .collect();
        let declared: BTreeSet<_> = pending.keys().cloned().collect();
        let mut archive = tar::Archive::new(reader);
        fs::create_dir_all(output).map_err(fail)?;
        let max_bytes = extraction_limit("SMOLVM_PACK_MAX_EXTRACT_BYTES", 128 * GIB);
        let max_entries = extraction_limit("SMOLVM_PACK_MAX_ENTRIES", 2_000_000);
        let mut bytes = 0u64;
        let mut count = 0u64;
        for entry in archive.entries().map_err(fail)? {
            let mut entry = entry.map_err(fail)?;
            count = count.saturating_add(1);
            bytes = bytes
                .checked_add(entry.size())
                .filter(|bytes| *bytes <= max_bytes)
                .ok_or_else(|| fail("pack exceeds extraction byte limit"))?;
            if count > max_entries {
                return Err(fail("pack exceeds extraction entry limit"));
            }
            let path = entry.path().map_err(fail)?.to_string_lossy().into_owned();
            let Some((id, expected)) = pending.remove(&path) else {
                if declared.contains(&path) {
                    return Err(fail("duplicate packed layer archive"));
                }
                continue;
            };
            if !entry.header().entry_type().is_file() || entry.size() != expected {
                return Err(fail(
                    "packed layer type or length differs from its manifest",
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join(format!("{id}.tar")))
                .map_err(fail)?;
            if io::copy(&mut entry, &mut file).map_err(fail)? != expected {
                return Err(fail("truncated packed layer"));
            }
        }
        if !pending.is_empty() {
            return Err(fail("pack is missing a declared layer"));
        }
        fs::write(output.join("layer-order"), ids.join("\n")).map_err(fail)
    }

    struct LayerReader {
        inner: BufReader<File>,
        position: u64,
    }

    impl LayerReader {
        fn open(path: &Path) -> io::Result<Self> {
            Ok(Self {
                inner: BufReader::with_capacity(1024 * 1024, File::open(path)?),
                position: 0,
            })
        }
    }

    impl Read for LayerReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buffer)?;
            self.position += count as u64;
            Ok(count)
        }
    }

    impl Seek for LayerReader {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.position = match from {
                SeekFrom::Current(offset) => {
                    let position = self.position.checked_add_signed(offset).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "layer seek out of bounds")
                    })?;
                    self.inner.seek_relative(offset)?;
                    position
                }
                from => self.inner.seek(from)?,
            };
            Ok(self.position)
        }
    }

    fn storage_budget(layers: &Path) -> Result<Option<(u64, u64)>> {
        let max_entries = extraction_limit("SMOLVM_PACK_MAX_ENTRIES", 2_000_000);
        let max_bytes = extraction_limit("SMOLVM_PACK_MAX_EXTRACT_BYTES", 128 * GIB);
        let mut entries = 0u64;
        let mut blocks = 0u64;
        let mut bytes = 0u64;
        for entry in fs::read_dir(layers).map_err(fail)? {
            let path = entry.map_err(fail)?.path();
            if path.extension().is_none_or(|extension| extension != "tar") {
                continue;
            }
            let mut archive = tar::Archive::new(LayerReader::open(&path).map_err(fail)?);
            for entry in archive.entries_with_seek().map_err(fail)? {
                let entry = entry.map_err(fail)?;
                if entry
                    .path()?
                    .file_name()
                    .is_some_and(|name| name.as_encoded_bytes().starts_with(b".wh."))
                {
                    return Ok(None);
                }
                entries = entries.saturating_add(1);
                bytes = bytes.saturating_add(entry.size());
                if entries > max_entries {
                    return Err(fail("packed layers exceed entry limit"));
                }
                if bytes > max_bytes {
                    return Err(fail("packed layers exceed extraction byte limit"));
                }
                blocks = blocks.saturating_add(entry.size().div_ceil(4096).max(1));
            }
        }
        let data = blocks.saturating_mul(4096).saturating_mul(5).div_ceil(4);
        let inodes = entries.saturating_add(4096).saturating_mul(16384);
        let logical = data
            .max(inodes)
            .saturating_add(GIB / 4)
            .div_ceil(GIB)
            .max(1);
        let physical = data
            .saturating_add(entries.saturating_mul(1024))
            .saturating_add(GIB / 4);
        Ok(Some((logical, physical)))
    }

    fn image_metadata(manifest: &PackManifest, ids: &[String]) -> Result<Vec<(String, Vec<u8>)>> {
        let image = normalize_image_ref(&manifest.image);
        let filename = image.replace(['/', ':', '@'], "_");
        if filename.contains(['\0', '\n', '\r']) || filename.contains('\\') {
            return Err(fail("invalid packed image reference"));
        }
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": manifest.platform.strip_prefix("linux/").unwrap_or("arm64"),
            "os": "linux", "config": {
                "Entrypoint": manifest.entrypoint, "Cmd": manifest.cmd, "Env": manifest.env,
                "WorkingDir": manifest.workdir, "User": manifest.user,
            }
        }))
        .map_err(fail)?;
        let digest = format!("{:x}", Sha256::digest(&config));
        let layers: Vec<_> = ids
            .iter()
            .map(|id| serde_json::json!({"digest": format!("sha256:{id}")}))
            .collect();
        let image_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "config": {"digest": format!("sha256:{digest}")}, "layers": layers,
        }))
        .map_err(fail)?;
        Ok(vec![
            (format!("/storage/configs/{digest}.json"), config),
            (
                format!("/storage/manifests/{filename}.json"),
                image_manifest,
            ),
            (
                format!("/storage/image-metadata/{filename}.size"),
                manifest.image_size.to_string().into_bytes(),
            ),
        ])
    }

    #[cfg(target_os = "macos")]
    struct Builder {
        manager: AgentManager,
        dir: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl Drop for Builder {
        fn drop(&mut self) {
            self.manager.kill_and_wait(Duration::from_secs(5));
            if !self.manager.is_process_alive() {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn prepare(
        layers: &Path,
        destination: &Path,
        manifest: &PackManifest,
        size: u64,
    ) -> Result<()> {
        let name = format!(
            "pack-seed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let manager = AgentManager::for_vm_with_sizes(&name, Some(size), Some(1))?;
        let builder = Builder {
            manager,
            dir: crate::agent::vm_data_dir(&name),
        };
        fs::write(builder.dir.join(".pack-seed-owner"), &name).map_err(fail)?;
        builder.manager.ensure_running_via_subprocess(
            vec![],
            vec![],
            VmResources {
                cpus: 2,
                memory_mib: 1024,
                storage_gib: Some(size),
                overlay_gib: Some(1),
                ..Default::default()
            },
            LaunchFeatures {
                packed_layers_dir: Some(layers.to_path_buf()),
                watch_parent: Some(true),
                ..Default::default()
            },
        )?;
        let mut client = builder.manager.connect()?;
        let ids = layer_ids(manifest)?;
        let mut script = "set -eu; mkdir -p /storage/layers /storage/configs /storage/manifests /storage/image-metadata; ".to_string();
        for id in &ids {
            script.push_str(&format!("mkdir -p /storage/layers/{id}; tar --extract --numeric-owner --xattrs --xattrs-include='*' --blocking-factor=1024 --file=/packed_layers/{id}.tar --directory=/storage/layers/{id}; printf ok > /storage/layers/{id}.ok; "));
        }
        let (code, _, stderr) = client.vm_exec(
            vec!["sh".into(), "-c".into(), script],
            vec![],
            None,
            Some(Duration::from_secs(600)),
            None,
        )?;
        if code != 0 {
            return Err(fail(String::from_utf8_lossy(&stderr)));
        }
        for (path, bytes) in image_metadata(manifest, &ids)? {
            client.write_file(&path, &bytes, Some(0o644))?;
        }
        builder.manager.stop()?;
        fs::rename(builder.manager.storage_path(), destination).map_err(fail)?;
        File::open(destination)
            .and_then(|file| file.sync_all())
            .map_err(fail)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    struct Lock(File);
    #[cfg(target_os = "macos")]
    impl Lock {
        fn new(path: &Path, operation: i32) -> Result<Self> {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(fail)?;
            loop {
                if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                    return Ok(Self(file));
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(fail(error));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    impl Drop for Lock {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    fn valid_seed(dir: &Path, artifact: &str, size: u64) -> bool {
        let metadata = fs::read(dir.join("seed.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Seed>(&bytes).ok());
        if !metadata.is_some_and(|metadata| {
            metadata.format == FORMAT
                && metadata.artifact == artifact
                && metadata.storage_gib == size
        }) {
            return false;
        }
        let path = dir.join("storage.raw");
        if !fs::symlink_metadata(&path).is_ok_and(|metadata| {
            metadata.is_file() && Some(metadata.len()) == size.checked_mul(GIB)
        }) {
            return false;
        }
        File::open(path).is_ok_and(|mut file| {
            let mut magic = [0; 2];
            file.seek(SeekFrom::Start(1080)).is_ok()
                && file.read_exact(&mut magic).is_ok()
                && magic == [0x53, 0xef]
        })
    }

    #[cfg(target_os = "macos")]
    fn identity(metadata: &fs::Metadata) -> [u64; 7] {
        [
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
        ]
    }

    #[cfg(target_os = "macos")]
    fn artifact_digest(file: &mut File, root: &Path) -> Result<String> {
        let before = identity(&file.metadata().map_err(fail)?);
        let key = hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            format!("{before:?}").as_bytes(),
        ));
        let hashes = root.join(".digests");
        fs::create_dir_all(&hashes).map_err(fail)?;
        let path = hashes.join(key);
        if let Ok(mut cached) = File::open(&path) {
            let mut bytes = Vec::new();
            Read::by_ref(&mut cached)
                .take(65)
                .read_to_end(&mut bytes)
                .map_err(fail)?;
            if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
                return String::from_utf8(bytes).map_err(fail);
            }
        }
        file.seek(SeekFrom::Start(0)).map_err(fail)?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(fail)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        if identity(&file.metadata().map_err(fail)?) != before {
            return Err(fail("pack changed while hashing"));
        }
        let digest = hex::encode(hash.finish());
        let mut temporary = tempfile::NamedTempFile::new_in(&hashes).map_err(fail)?;
        use std::io::Write;
        temporary.write_all(digest.as_bytes()).map_err(fail)?;
        temporary.persist(path).map_err(fail)?;
        Ok(digest)
    }

    #[cfg(target_os = "macos")]
    fn require_space(root: &Path, bytes: u64) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(fail)?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        let stats = unsafe { stats.assume_init() };
        let available = u64::from(stats.f_bavail).saturating_mul(stats.f_frsize);
        if available < bytes {
            return Err(fail(format!(
                "not enough free disk space: need at least {bytes} bytes, {available} available"
            )));
        }
        Ok(())
    }

    fn creator_is_gone(name: &str, prefix: &str) -> bool {
        let Some(pid) = name
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.split('-').next())
            .and_then(|pid| pid.parse::<libc::pid_t>().ok())
            .filter(|pid| *pid > 0)
        else {
            return false;
        };
        (unsafe { libc::kill(pid, 0) }) != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(target_os = "macos")]
    fn reap_abandoned(root: &Path) -> Result<()> {
        let Ok(_lock) = Lock::new(&root.join(".cache.lock"), libc::LOCK_EX | libc::LOCK_NB) else {
            return Ok(());
        };
        for entry in fs::read_dir(root).map_err(fail)?.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if creator_is_gone(&name, ".pack-seed-")
                    && fs::read_to_string(entry.path().join(".pack-seed-owner"))
                        .is_ok_and(|marker| marker == name)
                {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        for entry in fs::read_dir(crate::agent::vm_cache_root())
            .map_err(fail)?
            .flatten()
        {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let dir = entry.path();
            let Ok(name) = fs::read_to_string(dir.join(".pack-seed-owner")) else {
                continue;
            };
            if !creator_is_gone(&name, "pack-seed-")
                || crate::agent::vm_data_dir(&name) != dir
                || fs::read_to_string(dir.join("name")).ok().as_deref() != Some(name.as_str())
            {
                continue;
            }
            let Ok(_lock) = Lock::new(&dir.join("vm.lock"), libc::LOCK_EX | libc::LOCK_NB) else {
                continue;
            };
            if !AgentManager::for_vm(&name)?.is_process_alive() {
                let _ = fs::remove_dir_all(dir);
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn prune(root: &Path, keep: &Path) -> Result<()> {
        let Ok(_lock) = Lock::new(&root.join(".cache.lock"), libc::LOCK_EX | libc::LOCK_NB) else {
            return Ok(());
        };
        let cap = extraction_limit("SMOLVM_PACK_CACHE_MAX_BYTES", 20 * GIB);
        let mut entries = Vec::new();
        let mut total = 0u64;
        for entry in fs::read_dir(root).map_err(fail)? {
            let entry = entry.map_err(fail)?;
            if !entry.file_type().map_err(fail)?.is_dir() {
                continue;
            }
            let path = entry.path();
            if !entry.file_name().to_str().is_some_and(|name| {
                name.strip_prefix('v')
                    .and_then(|name| name.split_once('-'))
                    .is_some_and(|(version, _)| version.parse::<u32>().is_ok())
            }) {
                continue;
            }
            let size = fs::metadata(path.join("storage.raw"))
                .map(|metadata| metadata.blocks().saturating_mul(512))
                .unwrap_or(0);
            total = total.saturating_add(size);
            entries.push((
                entry
                    .metadata()
                    .map_err(fail)?
                    .modified()
                    .unwrap_or(std::time::UNIX_EPOCH),
                path,
                size,
            ));
        }
        entries.sort_by_key(|(time, _, _)| *time);
        for (_, path, size) in entries {
            if total <= cap {
                break;
            }
            if path != keep {
                fs::remove_dir_all(path).map_err(fail)?;
                total = total.saturating_sub(size);
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn install_seed(seed: &Path, directory: &File, size: u64) -> Result<()> {
        fn open(directory: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }

        struct Temporary<'a> {
            directory: &'a File,
            name: std::ffi::CString,
        }
        impl Drop for Temporary<'_> {
            fn drop(&mut self) {
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }

        let bytes = size
            .checked_mul(GIB)
            .ok_or_else(|| fail("storage size overflow"))?;
        let seed = File::open(seed).map_err(fail)?;
        let name = std::ffi::CString::new(format!(
            ".pack-storage-{}-{}.raw",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
        .map_err(fail)?;
        if unsafe { libc::fclonefileat(seed.as_raw_fd(), directory.as_raw_fd(), name.as_ptr(), 0) }
            != 0
        {
            return Err(fail(io::Error::last_os_error()));
        }
        let temporary = Temporary { directory, name };
        open(directory, &temporary.name, libc::O_RDONLY)
            .map_err(fail)?
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
        let storage = open(directory, &temporary.name, libc::O_RDWR).map_err(fail)?;
        storage
            .set_len(bytes)
            .and_then(|()| storage.sync_all())
            .map_err(fail)?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.name.as_ptr(),
                directory.as_raw_fd(),
                c"storage.raw".as_ptr(),
            )
        } != 0
        {
            return Err(fail(io::Error::last_os_error()));
        }
        if unsafe { libc::unlinkat(directory.as_raw_fd(), c"storage.qcow2".as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(fail(error));
            }
        }
        let mut formatted = open(
            directory,
            c"storage.formatted",
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        )
        .map_err(fail)?;
        use std::io::Write;
        formatted
            .write_all(b"1")
            .and_then(|()| formatted.sync_all())
            .and_then(|()| directory.sync_all())
            .map_err(fail)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn seed(name: &str, sidecar: &Path, requested: Option<u64>) -> Result<Option<u64>> {
        let mut file = File::open(sidecar).map_err(fail)?;
        let source_identity = identity(&file.metadata().map_err(fail)?);
        let manifest = read_manifest(&mut file)?;
        if manifest.mode != PackMode::Container
            || manifest.checkpoint.is_some()
            || manifest.assets.layers.len() != 1
            || manifest.assets.workspace_seed.is_some()
        {
            return Ok(None);
        }
        if layer_ids(&manifest).is_err() {
            return Ok(None);
        }
        let dir = crate::agent::vm_data_dir(name);
        if fs::symlink_metadata(dir.join("pack")).is_ok() {
            return Ok(None);
        }
        let target = File::open(&dir).map_err(fail)?;
        if AgentManager::for_vm(name)?.is_process_alive() {
            return Err(fail("cannot replace the storage of a running machine"));
        }
        let root = crate::agent::vm_cache_root().join("_pack-storage-seeds");
        fs::create_dir_all(&root).map_err(fail)?;
        if let Err(error) = reap_abandoned(&root) {
            tracing::warn!(%error, "could not reclaim abandoned packed storage seeds");
        }
        let cache_lock = Lock::new(&root.join(".cache.lock"), libc::LOCK_SH)?;
        let artifact = artifact_digest(&mut file, &root)?;
        let request_key = requested
            .filter(|size| *size < crate::storage::DEFAULT_STORAGE_SIZE_GIB)
            .map(|size| size.to_string())
            .unwrap_or_else(|| "auto".into());
        let key = root.join(format!("v{FORMAT}-{artifact}-{request_key}"));
        let _key_lock = Lock::new(&key.with_extension("lock"), libc::LOCK_EX)?;
        let metadata = fs::read(key.join("seed.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Seed>(&bytes).ok());
        let size = if let Some(metadata) =
            metadata.filter(|metadata| valid_seed(&key, &artifact, metadata.storage_gib))
        {
            metadata.storage_gib
        } else {
            let staging = tempfile::Builder::new()
                .prefix(&format!(".pack-seed-{}-", std::process::id()))
                .tempdir_in(&root)
                .map_err(fail)?;
            fs::write(
                staging.path().join(".pack-seed-owner"),
                staging.path().file_name().unwrap().as_encoded_bytes(),
            )
            .map_err(fail)?;
            let layers = staging.path().join("layers");
            let tar_bytes = manifest
                .assets
                .layers
                .iter()
                .try_fold(0u64, |sum, layer| sum.checked_add(layer.size))
                .filter(|bytes| {
                    *bytes <= extraction_limit("SMOLVM_PACK_MAX_EXTRACT_BYTES", 128 * GIB)
                })
                .ok_or_else(|| fail("packed layers exceed extraction limits"))?;
            require_space(&root, tar_bytes.saturating_add(GIB / 4))?;
            extract_layers(&mut file, &layers, &manifest)?;
            let Some((minimum, physical)) = storage_budget(&layers)? else {
                return Ok(None);
            };
            let size = match requested {
                Some(size) if size < minimum => return Ok(None),
                Some(size) => size.min(crate::storage::DEFAULT_STORAGE_SIZE_GIB.max(minimum)),
                None => crate::storage::DEFAULT_STORAGE_SIZE_GIB.max(minimum),
            };
            require_space(&root, physical)?;
            prepare(
                &layers,
                &staging.path().join("storage.raw"),
                &manifest,
                size,
            )?;
            if identity(&file.metadata().map_err(fail)?) != source_identity
                || identity(&fs::metadata(sidecar).map_err(fail)?) != source_identity
            {
                return Err(fail("pack changed while preparing its storage"));
            }
            fs::remove_dir_all(layers).map_err(fail)?;
            fs::set_permissions(
                staging.path().join("storage.raw"),
                fs::Permissions::from_mode(0o444),
            )
            .map_err(fail)?;
            fs::write(
                staging.path().join("seed.json"),
                serde_json::to_vec(&Seed {
                    format: FORMAT,
                    artifact: artifact.clone(),
                    storage_gib: size,
                })
                .map_err(fail)?,
            )
            .map_err(fail)?;
            File::open(staging.path().join("seed.json"))
                .and_then(|file| file.sync_all())
                .map_err(fail)?;
            if key.exists() {
                fs::remove_dir_all(&key).map_err(fail)?;
            }
            fs::rename(staging.path(), &key).map_err(fail)?;
            File::open(&root)
                .and_then(|file| file.sync_all())
                .map_err(fail)?;
            size
        };
        if identity(&file.metadata().map_err(fail)?) != source_identity
            || identity(&fs::metadata(sidecar).map_err(fail)?) != source_identity
        {
            return Err(fail("pack changed while preparing its storage"));
        }
        if requested.is_some_and(|requested| requested < size) {
            return Ok(None);
        }
        let size = requested.unwrap_or(size);
        install_seed(&key.join("storage.raw"), &target, size)?;
        File::open(&key)
            .and_then(|file| file.set_modified(std::time::SystemTime::now()))
            .map_err(fail)?;
        drop(cache_lock);
        if let Err(error) = prune(&root, &key) {
            tracing::warn!(%error, "could not prune packed storage seeds");
        }
        Ok(Some(size))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use smolvm_pack::format::LayerEntry;
        use std::io::Write;

        fn manifest() -> PackManifest {
            let mut manifest = PackManifest::new(
                "alpine:latest".into(),
                "sha256:source".into(),
                "linux/arm64".into(),
                "darwin/arm64".into(),
            );
            manifest.assets.layers.push(LayerEntry {
                digest: format!("sha256:{}", "a".repeat(64)),
                path: format!("layers/{}.tar", "a".repeat(64)),
                size: 4,
            });
            manifest
        }

        fn archive(paths: &[&str]) -> Vec<u8> {
            let mut builder = tar::Builder::new(Vec::new());
            for path in paths {
                let mut header = tar::Header::new_gnu();
                header.set_size(4);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, &b"data"[..])
                    .unwrap();
            }
            builder.into_inner().unwrap()
        }

        #[test]
        fn source_manifest_follows_the_open_file_not_a_replaced_path() {
            use smolvm_pack::format::PackFooter;
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("pack.smolmachine");
            let manifest = manifest();
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let footer = PackFooter {
                stub_size: 0,
                assets_offset: 0,
                assets_size: 0,
                manifest_offset: 0,
                manifest_size: bytes.len() as u64,
                checksum: 0,
            };
            let mut contents = bytes;
            contents.extend_from_slice(&footer.to_bytes());
            fs::write(&path, contents).unwrap();
            let mut file = File::open(&path).unwrap();
            fs::rename(&path, root.path().join("original")).unwrap();
            fs::write(path, b"replacement").unwrap();
            assert_eq!(read_manifest(&mut file).unwrap().image, manifest.image);
        }

        #[test]
        fn extracts_only_declared_layers_and_retains_order() {
            let manifest = manifest();
            let output = tempfile::tempdir().unwrap();
            let bytes = archive(&["unrelated", &manifest.assets.layers[0].path]);
            extract_layer_archive(&bytes[..], output.path(), &manifest).unwrap();
            assert_eq!(
                fs::read(output.path().join(format!("{}.tar", "a".repeat(64)))).unwrap(),
                b"data"
            );
            assert!(!output.path().join("unrelated").exists());
            assert_eq!(
                fs::read_to_string(output.path().join("layer-order")).unwrap(),
                "a".repeat(64)
            );
        }

        #[test]
        fn rejects_duplicate_missing_and_mismatched_layers() {
            let mut manifest = manifest();
            let output = tempfile::tempdir().unwrap();
            let path = manifest.assets.layers[0].path.clone();
            let bytes = archive(&[&path, &path]);
            assert!(extract_layer_archive(&bytes[..], output.path(), &manifest)
                .unwrap_err()
                .to_string()
                .contains("duplicate"));
            let output = tempfile::tempdir().unwrap();
            let bytes = archive(&["not-a-layer"]);
            assert!(extract_layer_archive(&bytes[..], output.path(), &manifest)
                .unwrap_err()
                .to_string()
                .contains("missing"));
            let bytes = archive(&[&path]);
            manifest.assets.layers[0].size = 5;
            assert!(extract_layer_archive(&bytes[..], output.path(), &manifest)
                .unwrap_err()
                .to_string()
                .contains("length"));
        }

        #[test]
        fn refuses_layer_path_traversal_and_duplicate_ids() {
            let mut manifest = manifest();
            manifest.assets.layers[0].path = "layers/../escape.tar".into();
            assert!(layer_ids(&manifest).is_err());
            let mut manifest = super::tests::manifest();
            manifest
                .assets
                .layers
                .push(manifest.assets.layers[0].clone());
            assert!(layer_ids(&manifest).is_err());
        }

        #[test]
        fn refuses_symlink_layers() {
            let mut manifest = manifest();
            manifest.assets.layers[0].size = 0;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            let mut archive = tar::Builder::new(Vec::new());
            archive
                .append_link(&mut header, &manifest.assets.layers[0].path, "/etc/passwd")
                .unwrap();
            let bytes = archive.into_inner().unwrap();
            let output = tempfile::tempdir().unwrap();
            assert!(extract_layer_archive(&bytes[..], output.path(), &manifest).is_err());
        }

        #[test]
        fn storage_budget_counts_inodes_instead_of_only_file_bytes() {
            let output = tempfile::tempdir().unwrap();
            let mut archive =
                tar::Builder::new(File::create(output.path().join("layer.tar")).unwrap());
            for index in 0..65536 {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(&mut header, format!("file-{index}"), io::empty())
                    .unwrap();
            }
            archive.finish().unwrap();
            drop(archive);
            let (size, physical) = storage_budget(output.path()).unwrap().unwrap();
            assert_eq!(size, 2);
            assert!(physical > GIB / 4);
            assert!(physical < 2 * GIB);
        }

        #[test]
        fn layer_reader_tracks_reads_and_seeks_inside_and_outside_its_buffer() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("bytes");
            let bytes: Vec<_> = (0..3_000_000).map(|index| (index % 251) as u8).collect();
            fs::write(&path, &bytes).unwrap();
            let mut reader = LayerReader::open(&path).unwrap();
            let mut buffer = [0; 64];
            for target in [0u64, 900_000, 15, 2_900_000, 2_900_040, 5] {
                let offset = target as i64 - reader.position as i64;
                assert_eq!(reader.seek(SeekFrom::Current(offset)).unwrap(), target);
                reader.read_exact(&mut buffer).unwrap();
                assert_eq!(buffer, bytes[target as usize..target as usize + 64]);
                assert_eq!(reader.stream_position().unwrap(), target + 64);
            }
            assert_eq!(reader.seek(SeekFrom::End(-64)).unwrap(), 2_999_936);
            reader.read_exact(&mut buffer).unwrap();
            assert_eq!(buffer, bytes[2_999_936..]);
            assert_eq!(reader.read(&mut buffer).unwrap(), 0);
            assert!(reader.seek(SeekFrom::Current(-3_000_001)).is_err());
            assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn installation_stays_with_the_pinned_directory_after_a_same_name_retry() {
            let root = tempfile::tempdir().unwrap();
            let seed = root.path().join("seed");
            fs::write(&seed, b"seed contents").unwrap();
            fs::set_permissions(&seed, fs::Permissions::from_mode(0o444)).unwrap();
            let path = root.path().join("machine");
            fs::create_dir(&path).unwrap();
            let target = File::open(&path).unwrap();
            let abandoned = root.path().join("abandoned");
            fs::rename(&path, &abandoned).unwrap();
            fs::write(abandoned.join("storage.qcow2"), "old top").unwrap();
            fs::create_dir(&path).unwrap();
            fs::write(path.join("storage.raw"), "new machine").unwrap();
            fs::write(path.join("storage.formatted"), "new marker").unwrap();

            install_seed(&seed, &target, 1).unwrap();

            assert_eq!(fs::read(path.join("storage.raw")).unwrap(), b"new machine");
            assert_eq!(
                fs::read(path.join("storage.formatted")).unwrap(),
                b"new marker"
            );
            let raw = File::open(abandoned.join("storage.raw")).unwrap();
            assert_eq!(raw.metadata().unwrap().len(), GIB);
            assert_eq!(raw.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            let mut prefix = [0; 13];
            (&raw).read_exact(&mut prefix).unwrap();
            assert_eq!(&prefix, b"seed contents");
            assert!(!abandoned.join("storage.qcow2").exists());
            assert_eq!(fs::read(abandoned.join("storage.formatted")).unwrap(), b"1");
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn a_deleted_target_cannot_redirect_installation_to_a_new_machine() {
            let root = tempfile::tempdir().unwrap();
            let seed = root.path().join("seed");
            fs::write(&seed, b"seed contents").unwrap();
            let path = root.path().join("machine");
            fs::create_dir(&path).unwrap();
            let target = File::open(&path).unwrap();
            fs::remove_dir(&path).unwrap();
            fs::create_dir(&path).unwrap();
            fs::write(path.join("storage.raw"), "new machine").unwrap();

            assert!(install_seed(&seed, &target, 1).is_err());
            assert_eq!(fs::read(path.join("storage.raw")).unwrap(), b"new machine");
            assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        }

        #[test]
        fn storage_seed_defers_whiteouts_to_the_layer_extractor() {
            let output = tempfile::tempdir().unwrap();
            let mut archive =
                tar::Builder::new(File::create(output.path().join("layer.tar")).unwrap());
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "etc/.wh.removed", io::empty())
                .unwrap();
            archive.finish().unwrap();
            drop(archive);
            assert!(storage_budget(output.path()).unwrap().is_none());
        }

        #[test]
        fn scratch_cleanup_keeps_live_and_ambiguous_creators() {
            assert!(!creator_is_gone(
                &format!("pack-seed-{}-unique", std::process::id()),
                "pack-seed-"
            ));
            for name in [
                "pack-seed--1-unique",
                "pack-seed-0-unique",
                "other-42-unique",
            ] {
                assert!(!creator_is_gone(name, "pack-seed-"));
            }
        }

        #[test]
        fn cache_metadata_preserves_image_defaults_and_exact_layer_order() {
            let mut manifest = manifest();
            manifest.env = vec!["PATH=/usr/bin".into()];
            manifest.user = Some("42:43".into());
            manifest.workdir = Some("/srv".into());
            manifest.cmd = vec!["serve".into()];
            let ids = vec!["b".repeat(64), "a".repeat(64)];
            let files = image_metadata(&manifest, &ids).unwrap();
            let config: serde_json::Value = serde_json::from_slice(&files[0].1).unwrap();
            assert_eq!(config["config"]["User"], "42:43");
            assert_eq!(config["config"]["WorkingDir"], "/srv");
            assert_eq!(config["config"]["Cmd"][0], "serve");
            assert!(files[1].0.ends_with("docker.io_library_alpine_latest.json"));
            let image: serde_json::Value = serde_json::from_slice(&files[1].1).unwrap();
            assert_eq!(image["layers"][0]["digest"], format!("sha256:{}", ids[0]));
            assert_eq!(
                image["config"]["digest"],
                format!("sha256:{:x}", Sha256::digest(&files[0].1))
            );
        }

        #[test]
        fn published_seed_requires_metadata_size_and_filesystem_magic() {
            let output = tempfile::tempdir().unwrap();
            fs::write(
                output.path().join("seed.json"),
                serde_json::to_vec(&Seed {
                    format: FORMAT,
                    artifact: "digest".into(),
                    storage_gib: 1,
                })
                .unwrap(),
            )
            .unwrap();
            let mut file = File::create(output.path().join("storage.raw")).unwrap();
            file.set_len(GIB).unwrap();
            assert!(!valid_seed(output.path(), "digest", 1));
            file.seek(SeekFrom::Start(1080)).unwrap();
            file.write_all(&[0x53, 0xef]).unwrap();
            assert!(valid_seed(output.path(), "digest", 1));
            assert!(!valid_seed(output.path(), "other", 1));
            assert!(!valid_seed(output.path(), "digest", 2));
            fs::remove_file(output.path().join("storage.raw")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", output.path().join("storage.raw")).unwrap();
            assert!(!valid_seed(output.path(), "digest", 1));
        }
    }
}
