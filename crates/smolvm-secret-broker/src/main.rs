use anyhow::{Context, Result};
use smolvm_secret_broker::{Broker, Config};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .context("usage: smolvm-secret-broker HOST_CONFIG.json")?;
    anyhow::ensure!(
        args.next().is_none(),
        "expected one host configuration file"
    );
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let broker = Broker::new(config)?;
    #[cfg(unix)]
    let unix_binding = broker
        .unix_socket_path()
        .map(bind_private_socket)
        .transpose()?;
    let listener = tokio::net::TcpListener::bind(broker.listen_address()).await?;
    println!("credential broker listening on {}", listener.local_addr()?);
    let unix_broker = broker.clone();
    let unix_server = async move {
        #[cfg(unix)]
        if let Some((listener, guard)) = unix_binding {
            let _guard = guard;
            return unix_broker.serve_unix(listener).await;
        }
        let _ = unix_broker;
        std::future::pending::<Result<()>>().await
    };
    tokio::select! {
        result = broker.serve(listener) => result,
        result = unix_server => result,
        result = shutdown_signal() => { result?; Ok(()) }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(unix)]
struct SocketGuard {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn bind_private_socket(path: &std::path::Path) -> Result<(tokio::net::UnixListener, SocketGuard)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    anyhow::ensure!(path.is_absolute(), "broker socket path must be absolute");
    let parent = path
        .parent()
        .context("broker socket requires a parent directory")?;
    let meta = std::fs::metadata(parent)?;
    anyhow::ensure!(
        meta.is_dir() && meta.mode() & 0o077 == 0,
        "broker socket parent must be private (0700)"
    );
    // Never unlink a pre-existing entry, including an active socket or symlink.
    let listener = tokio::net::UnixListener::bind(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        device: meta.dev(),
        inode: meta.ino(),
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, guard))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn socket_is_private_and_cleaned_up() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("broker.sock");
        let (listener, guard) = bind_private_socket(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(bind_private_socket(&path).is_err());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn never_deletes_a_replacement_or_an_existing_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("broker.sock");
        let (_listener, guard) = bind_private_socket(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        drop(guard);
        assert!(bind_private_socket(&path).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "replacement");
    }

    #[tokio::test]
    async fn refuses_public_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(bind_private_socket(&root.path().join("broker.sock")).is_err());
    }
}
