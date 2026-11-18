//! Private, atomically published identities; no credential helper or Keychain.
use anyhow::{ensure, Context, Result};
use russh::keys::{ssh_key::LineEnding, Algorithm, PrivateKey, PublicKey};
use serde::Serialize;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(windows)]
#[path = "windows_private.rs"]
mod windows_private;

/// Standard client connection details; private key bytes are never returned.
#[derive(Debug, Serialize)]
pub struct Connection {
    /// Stable host alias, scoped by this environment's public host identity.
    pub host: String,
    /// OpenSSH config file, suitable for `ssh -F` and editor configuration.
    pub config: PathBuf,
}

fn protect(path: &Path) -> Result<()> {
    let before = path.symlink_metadata()?;
    ensure!(
        before.is_file() || before.is_dir(),
        "SSH storage must not use links or special files"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let after = file.metadata()?;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "SSH storage changed while opening it"
        );
        ensure!(
            after.uid() == unsafe { libc::geteuid() } && (!after.is_file() || after.nlink() == 1),
            "SSH storage must belong only to this user"
        );
        file.set_permissions(fs::Permissions::from_mode(if after.is_dir() {
            0o700
        } else {
            0o600
        }))?;
    }
    #[cfg(windows)]
    windows_private::make_private(path).map_err(anyhow::Error::msg)?;
    Ok(())
}
fn directory(machine: &str, create: bool) -> Result<PathBuf> {
    ensure!(
        crate::db::SmolvmDb::open()?.get_vm(machine)?.is_some(),
        "selected machine does not exist"
    );
    let root = crate::agent::vm_data_dir(machine).join("ssh");
    if create {
        fs::create_dir_all(root.parent().context("missing machine directory")?)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&root) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    protect(&root).context("cannot access private machine SSH identity; run ssh-config first")?;
    root.canonicalize().map_err(Into::into)
}
// Serialize concurrent SSH cold starts through cleanup, rather than letting
// a second connection mistake the first connection's boot for an orphan.
#[cfg(not(unix))]
pub(super) fn startup_lock(machine: &str) -> Result<fs::File> {
    let path = directory(machine, false)?.join("startup.lock");
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "SSH startup lock is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.nlink() == 1,
            "SSH startup lock must belong only to this user"
        );
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    windows_private::make_private(&path).map_err(anyhow::Error::msg)?;
    Ok(file)
}

fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    protect(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "SSH identity is not a regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "SSH identity is too large");
    Ok(bytes)
}
fn publish(root: &Path, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
    let path = root.join(name);
    if fs::symlink_metadata(&path).is_ok() {
        protect(&path)?;
    }
    let mut stage = tempfile::NamedTempFile::new_in(root)?;
    protect(stage.path())?;
    stage.write_all(bytes)?;
    stage.as_file().sync_all()?;
    if replace {
        stage.persist(&path).map_err(|e| e.error)?;
    } else {
        match stage.persist_noclobber(&path) {
            Ok(_) => (),
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.error.into()),
        }
    }
    Ok(())
}
fn key(root: &Path, name: &str) -> Result<PrivateKey> {
    let path = root.join(name);
    if matches!(path.symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound) {
        let generated = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let encoded = generated.to_openssh(LineEnding::LF)?;
        publish(root, name, encoded.as_bytes(), false)?;
    }
    Ok(PrivateKey::from_openssh(read(&path)?.as_slice())?)
}
fn quote_config(path: &Path) -> Result<String> {
    let value = path.to_str().context("SSH paths must be valid UTF-8")?;
    ensure!(
        !value.contains(['\n', '\r', '\0']),
        "invalid SSH configuration path"
    );
    // Config directives expand % tokens; only our literal path belongs here.
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn quote_command(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("SSH executable path must be valid UTF-8")?;
    ensure!(
        !value.contains(['\n', '\r', '\0', '%']),
        "unsupported SSH proxy executable path"
    );
    #[cfg(unix)]
    {
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    }
    #[cfg(windows)]
    {
        // OpenSSH's Windows proxy command is launched through its command-line
        // parser; % expansion was rejected above and quotes cannot name a file.
        ensure!(
            !value.contains(['"', '&', '|', '<', '>', '^']),
            "unsupported SSH proxy executable path"
        );
        Ok(format!("\"{value}\""))
    }
}
fn host_alias(machine: &str, host_key: &PublicKey) -> Result<String> {
    use sha2::{Digest, Sha256};
    // A user can include several installations' configs in one SSH config.
    // Names alone collide across data roots; the persisted host key identifies
    // the actual environment and survives repeated configuration and restarts.
    let digest = Sha256::digest(host_key.to_bytes()?);
    let hash = hex::encode(&digest[..8]);
    let label: String = machine
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(32)
        .collect();
    Ok(format!(
        "{}-{}.smol",
        if label.is_empty() { "machine" } else { &label },
        hash
    ))
}

pub(super) fn configure(machine: &str) -> Result<Connection> {
    let root = directory(machine, true)?;
    let host_key = key(&root, "host_ed25519")?;
    key(&root, "id_ed25519")?;
    let host = host_alias(machine, host_key.public_key())?;
    let known = format!("{host} {}\n", host_key.public_key().to_openssh()?);
    publish(&root, "known_hosts", known.as_bytes(), true)?;
    let executable = quote_command(&std::env::current_exe()?)?;
    let config=format!("Host {host}\n  HostName {host}\n  User smol\n  IdentityFile {}\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile none\n  StrictHostKeyChecking yes\n  ProxyCommand {executable} machine ssh-proxy --context-hex {}\n",
        quote_config(&root.join("id_ed25519"))?,quote_config(&root.join("known_hosts"))?,super::context::Context::capture(machine, host_key.public_key())?);
    publish(&root, "config", config.as_bytes(), true)?;
    Ok(Connection {
        host,
        config: root.join("config"),
    })
}
pub(super) fn load(machine: &str) -> Result<(PrivateKey, PublicKey)> {
    let root = directory(machine, false)?;
    let host = PrivateKey::from_openssh(read(&root.join("host_ed25519"))?.as_slice())?;
    let client = PrivateKey::from_openssh(read(&root.join("id_ed25519"))?.as_slice())?;
    Ok((host, client.public_key().clone()))
}

pub(super) fn verify(machine: &str, expected: &PublicKey) -> Result<()> {
    let root = directory(machine, false)?;
    let current = PrivateKey::from_openssh(read(&root.join("host_ed25519"))?.as_slice())?;
    ensure!(
        current.public_key().key_data() == expected.key_data(),
        "machine SSH identity changed; reconnect using its current configuration"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_names_in_different_installations_get_distinct_stable_aliases() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_key = key(first.path(), "host").unwrap();
        let second_key = key(second.path(), "host").unwrap();
        let alias = host_alias("development", first_key.public_key()).unwrap();
        assert_ne!(
            alias,
            host_alias("development", second_key.public_key()).unwrap()
        );
        assert_eq!(
            alias,
            host_alias(
                "development",
                key(first.path(), "host").unwrap().public_key()
            )
            .unwrap()
        );
        assert!(alias.starts_with("development-") && alias.ends_with(".smol"));
    }

    #[test]
    fn concurrent_creators_reuse_one_key_and_never_rotate_invalid_storage() {
        let root = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(8);
        let keys = std::thread::scope(|scope| {
            (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        key(root.path(), "key").unwrap().public_key().clone()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(keys.iter().all(|key| key == &keys[0]));
        fs::write(root.path().join("key"), b"damaged identity").unwrap();
        assert!(key(root.path(), "key").is_err());
        assert_eq!(
            fs::read(root.path().join("key")).unwrap(),
            b"damaged identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_links_and_special_files_without_changing_their_targets() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::write(&target, b"keep").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let linked = root.path().join("linked");
        symlink(&target, &linked).unwrap();
        assert!(read(&linked).is_err());
        assert!(publish(root.path(), "linked", b"replace", true).is_err());
        fs::remove_file(&linked).unwrap();
        fs::hard_link(&target, &linked).unwrap();
        assert!(read(&linked).is_err());
        assert!(publish(root.path(), "linked", b"replace", true).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        let fifo = root.path().join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a live, NUL-terminated path in our temporary directory.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(read(&fifo).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn identities_and_published_config_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        protect(root.path()).unwrap();
        key(root.path(), "key").unwrap();
        publish(root.path(), "config", b"Host test\n", true).unwrap();
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["key", "config"] {
            assert_eq!(
                fs::metadata(root.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
